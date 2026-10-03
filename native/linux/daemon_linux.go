//go:build linux

// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func secureRootDirectory(path string, mode os.FileMode, group int) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("daemon paths must be canonical absolute paths")
	}
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 {
		return errors.New("daemon directory must be a non-writable root-owned directory, not a symlink")
	}
	if err := os.Chown(path, 0, group); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func secureRootFile(path string, optional bool) error {
	info, err := os.Lstat(path)
	if optional && os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != 0 || info.Mode().Perm()&0077 != 0 {
		return errors.New("native policy must be a private root-owned regular file")
	}
	return nil
}

func peerUID(connection *net.UnixConn) (uint32, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return 0, err
	}
	var credential *unix.Ucred
	var socketError error
	err = raw.Control(func(fd uintptr) {
		credential, socketError = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if err != nil {
		return 0, err
	}
	if socketError != nil || credential == nil {
		return 0, errors.New("cannot authenticate Unix peer")
	}
	return credential.Uid, nil
}

func serveConnection(ctx context.Context, connection *net.UnixConn, ownerUID uint32, nft string, state *adapterState) {
	defer connection.Close()
	connection.SetDeadline(time.Now().Add(5 * time.Second))
	uid, err := peerUID(connection)
	if err != nil || (uid != 0 && uid != ownerUID) {
		json.NewEncoder(connection).Encode(Response{SchemaVersion: 1, OK: false, Platform: "linux", Reason: "Unix peer is not authorized", Error: "Unix peer is not authorized", Authenticated: false})
		return
	}
	var request Request
	data, err := bufio.NewReader(io.LimitReader(connection, maxJSON+2)).ReadBytes('\n')
	if err != nil && err != io.EOF {
		return
	}
	if err := decodeJSON(bytes.NewReader(data), &request); err != nil {
		json.NewEncoder(connection).Encode(Response{SchemaVersion: 1, OK: false, Platform: "linux", Reason: err.Error(), Error: err.Error(), Authenticated: true})
		return
	}
	if request.Command == "status" || request.Command == "apply-bans" {
		refreshTable(ctx, nft, state)
	}
	json.NewEncoder(connection).Encode(state.handle(request))
}

func refreshTable(ctx context.Context, nft string, state *adapterState) {
	check, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	command := exec.CommandContext(check, nft, "-j", "list", "table", "inet", "networkcontrol")
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	pipe, err := command.StdoutPipe()
	if err == nil {
		err = command.Start()
	}
	var data []byte
	if err == nil {
		data, err = io.ReadAll(io.LimitReader(pipe, maxJSON+1))
		if len(data) > maxJSON {
			cancel()
			err = errors.New("nftables readiness response exceeds 1 MiB")
		}
		waitErr := command.Wait()
		if err == nil {
			err = waitErr
		}
	}
	if err == nil {
		err = verifyTableJSON(data)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	state.tableChecked = time.Now()
	state.tableInstalled = err == nil
	if err != nil {
		state.reason = "Dedicated bidirectional nftables table is not verified; no native ban readiness claim"
	} else {
		state.reason = ""
	}
}

func runDaemon(options Options) error {
	if os.Geteuid() != 0 {
		return errors.New("explicit privileged daemon installation is required")
	}
	if options.SocketPath != "/run/networkcontrol/adapter.sock" || options.PolicyPath != "/var/lib/networkcontrol/bans.json" {
		return errors.New("daemon uses fixed isolated socket and policy locations")
	}
	if err := secureRootDirectory(filepath.Dir(options.SocketPath), 0750, int(options.OwnerGID)); err != nil {
		return err
	}
	if err := secureRootDirectory(filepath.Dir(options.PolicyPath), 0700, 0); err != nil {
		return err
	}
	if err := secureRootFile(options.PolicyPath, true); err != nil {
		return err
	}
	if !filepath.IsAbs(options.NFTPath) || filepath.Clean(options.NFTPath) != options.NFTPath {
		return errors.New("nft executable must use a canonical absolute path")
	}
	nftInfo, err := os.Stat(options.NFTPath)
	if err != nil {
		return err
	}
	nftStat, ok := nftInfo.Sys().(*syscall.Stat_t)
	if !ok || !nftInfo.Mode().IsRegular() || nftStat.Uid != 0 || nftInfo.Mode().Perm()&0022 != 0 {
		return errors.New("nft executable must be a non-writable root-owned regular file")
	}
	state, err := newState(options.PolicyPath)
	if err != nil {
		return err
	}
	lock, err := os.OpenFile("/run/networkcontrol/daemon.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return errors.New("another NetworkControl Linux daemon is running")
	}
	if info, err := os.Lstat(options.SocketPath); err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || info.Mode()&os.ModeSocket == 0 || stat.Uid != 0 {
			return errors.New("refusing to replace unowned native socket")
		}
		if err := os.Remove(options.SocketPath); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	output, err := openQueue(outputQueue, "outbound")
	if err != nil {
		return err
	}
	defer output.conn.Close()
	input, err := openQueue(inputQueue, "inbound")
	if err != nil {
		return err
	}
	defer input.conn.Close()
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: options.SocketPath, Net: "unix"})
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := os.Chown(options.SocketPath, 0, int(options.OwnerGID)); err != nil {
		return err
	}
	if err := os.Chmod(options.SocketPath, 0660); err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	state.queueHealthy = true
	failure := make(chan error, 2)
	var workers sync.WaitGroup
	for _, queue := range []*nativeQueue{output, input} {
		workers.Add(1)
		go func(queue *nativeQueue) {
			defer workers.Done()
			if err := queue.run(ctx, state); err != nil && ctx.Err() == nil {
				state.mu.Lock()
				state.queueHealthy, state.reason = false, "Native queue failed; dedicated table remains fail-closed"
				state.queueErrors++
				state.mu.Unlock()
				failure <- err
				cancel()
			}
		}(queue)
	}
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			refreshTable(ctx, options.NFTPath, state)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	go func() {
		<-ctx.Done()
		listener.Close()
	}()
	semaphore := make(chan struct{}, 16)
	for ctx.Err() == nil {
		connection, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() == nil {
				cancel()
				workers.Wait()
				return err
			}
			break
		}
		select {
		case semaphore <- struct{}{}:
			go func() {
				defer func() { <-semaphore }()
				serveConnection(ctx, connection, uint32(options.OwnerUID), options.NFTPath, state)
			}()
		default:
			connection.Close()
		}
	}
	workers.Wait()
	select {
	case err := <-failure:
		return fmt.Errorf("queue stopped; queued traffic remains blocked: %w", err)
	default:
		return nil
	}
}
