// SPDX-License-Identifier: GPL-3.0-only
// Adapted 2026-10-02 from OpenSnitch a1353848ba1b660320e90cefea782c3fba272c00:
// daemon/netstat/parse.go, find.go and daemon/procmon/find.go. See NOTICE.md.
package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Identity struct {
	PID         int    `json:"pid,omitempty"`
	UID         uint32 `json:"uid"`
	ProcessPath string `json:"processPath,omitempty"`
	StartTicks  string `json:"processStartTicks,omitempty"`
}

type socketEntry struct {
	local, remote         netip.Addr
	localPort, remotePort uint16
	uid                   uint32
	inode                 string
	state                 string
}

func procAddress(value string) (netip.Addr, uint16, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return netip.Addr{}, 0, errors.New("invalid proc socket address")
	}
	bytes, err := hex.DecodeString(parts[0])
	if err != nil || (len(bytes) != 4 && len(bytes) != 16) {
		return netip.Addr{}, 0, errors.New("invalid proc socket IP")
	}
	for offset := 0; offset < len(bytes); offset += 4 {
		value := binary.LittleEndian.Uint32(bytes[offset : offset+4])
		binary.BigEndian.PutUint32(bytes[offset:offset+4], value)
	}
	ip, _ := netip.AddrFromSlice(bytes)
	port, err := strconv.ParseUint(parts[1], 16, 16)
	return ip.Unmap(), uint16(port), err
}

func parseSocketLine(line string) (socketEntry, error) {
	var entry socketEntry
	fields := strings.Fields(line)
	if len(fields) < 10 {
		return entry, errors.New("truncated proc socket row")
	}
	var err error
	entry.local, entry.localPort, err = procAddress(fields[1])
	if err != nil {
		return entry, err
	}
	entry.remote, entry.remotePort, err = procAddress(fields[2])
	if err != nil {
		return entry, err
	}
	uid, err := strconv.ParseUint(fields[7], 10, 32)
	if err != nil {
		return entry, err
	}
	if _, err := strconv.ParseUint(fields[9], 10, 64); err != nil || fields[9] == "0" {
		return entry, errors.New("invalid proc socket inode")
	}
	entry.uid, entry.inode, entry.state = uint32(uid), fields[9], fields[3]
	return entry, nil
}

func matchingInodes(root string, tuple Tuple, deadline time.Time) (map[string]uint32, error) {
	inodes := make(map[string]uint32)
	for _, suffix := range []string{"", "6"} {
		file, err := os.Open(filepath.Join(root, "net", tuple.Network+suffix))
		if err != nil {
			return nil, err
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			if time.Now().After(deadline) {
				file.Close()
				return nil, errors.New("process lookup deadline exceeded")
			}
			entry, err := parseSocketLine(scanner.Text())
			if err != nil || entry.localPort != tuple.SourcePort {
				continue
			}
			listener := tuple.Network == "tcp" && entry.state == "0A"
			local := entry.local == tuple.Source.Unmap() || ((tuple.Network == "udp" || listener) && entry.local.IsUnspecified())
			remote := entry.remote == tuple.Destination.Unmap() && entry.remotePort == tuple.DestPort
			if (tuple.Network == "udp" || listener) && entry.remote.IsUnspecified() && entry.remotePort == 0 {
				remote = true
			}
			if local && remote {
				inodes[entry.inode] = entry.uid
			}
		}
		err = scanner.Err()
		file.Close()
		if err != nil {
			return nil, err
		}
	}
	return inodes, nil
}

func startTicks(root string, pid int) (string, error) {
	data, err := os.ReadFile(filepath.Join(root, strconv.Itoa(pid), "stat"))
	if err != nil {
		return "", err
	}
	closing := strings.LastIndexByte(string(data), ')')
	if closing < 0 {
		return "", errors.New("invalid proc process stat")
	}
	fields := strings.Fields(string(data)[closing+1:])
	if len(fields) < 20 {
		return "", errors.New("truncated proc process stat")
	}
	if _, err := strconv.ParseUint(fields[19], 10, 64); err != nil {
		return "", err
	}
	return fields[19], nil
}

func resolveProcess(root string, tuple Tuple, deadline time.Time) (Identity, error) {
	var found Identity
	inodes, err := matchingInodes(root, tuple, deadline)
	if err != nil {
		return found, err
	}
	if len(inodes) == 0 {
		return found, errors.New("no matching native socket inode")
	}
	namespace, err := os.Readlink(filepath.Join(root, "self", "ns", "net"))
	if err != nil {
		return found, err
	}
	pids, err := os.ReadDir(root)
	if err != nil {
		return found, err
	}
	for _, item := range pids {
		if time.Now().After(deadline) {
			return Identity{}, errors.New("process lookup deadline exceeded")
		}
		pid, err := strconv.Atoi(item.Name())
		if err != nil || pid <= 0 || !item.IsDir() {
			continue
		}
		base := filepath.Join(root, item.Name())
		currentNS, err := os.Readlink(filepath.Join(base, "ns", "net"))
		if err != nil || currentNS != namespace {
			continue
		}
		before, err := startTicks(root, pid)
		if err != nil {
			continue
		}
		fds, err := os.ReadDir(filepath.Join(base, "fd"))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			if time.Now().After(deadline) {
				return Identity{}, errors.New("process lookup deadline exceeded")
			}
			link, err := os.Readlink(filepath.Join(base, "fd", fd.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") || !strings.HasSuffix(link, "]") {
				continue
			}
			uid, matched := inodes[strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")]
			if !matched {
				continue
			}
			path, err := os.Readlink(filepath.Join(base, "exe"))
			if err != nil || validatePaths([]string{path}) != nil {
				return Identity{}, errors.New("process executable identity unavailable")
			}
			after, err := startTicks(root, pid)
			if err != nil || before != after {
				return Identity{}, errors.New("process identity changed during lookup")
			}
			confirmedPath, err := os.Readlink(filepath.Join(base, "exe"))
			confirmedFD, fdErr := os.Readlink(filepath.Join(base, "fd", fd.Name()))
			if err != nil || fdErr != nil || confirmedPath != path || confirmedFD != link {
				return Identity{}, errors.New("socket or executable identity changed during lookup")
			}
			if found.PID != 0 && found.PID != pid {
				return Identity{}, errors.New("socket is shared by multiple processes; attribution ambiguous")
			}
			found = Identity{PID: pid, UID: uid, ProcessPath: path, StartTicks: before}
		}
	}
	if found.PID == 0 {
		return found, fmt.Errorf("socket inode has no accessible process owner")
	}
	return found, nil
}
