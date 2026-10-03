// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"flag"
	"fmt"
	"os"
)

type Options struct {
	SocketPath string
	PolicyPath string
	NFTPath    string
	OwnerUID   uint
	OwnerGID   uint
}

func main() {
	flags := flag.NewFlagSet("networkcontrol-linux", flag.ExitOnError)
	options := Options{}
	serve := flags.Bool("serve", false, "explicitly start the privileged NFQUEUE daemon")
	license := flags.Bool("license", false, "show license provenance")
	flags.StringVar(&options.SocketPath, "socket", "/run/networkcontrol/adapter.sock", "root-owned local IPC socket")
	flags.StringVar(&options.PolicyPath, "policy", "/var/lib/networkcontrol/bans.json", "private root-owned native ban policy")
	flags.StringVar(&options.NFTPath, "nft", "/usr/sbin/nft", "absolute root-owned nft executable for read-only readiness verification")
	flags.UintVar(&options.OwnerUID, "owner-uid", ^uint(0), "the one desktop UID allowed to control bans")
	flags.UintVar(&options.OwnerGID, "owner-gid", ^uint(0), "a private desktop group used for socket access")
	flags.Parse(os.Args[1:])
	if *license {
		fmt.Println("NetworkControl Linux adapter: GPL-3.0-only; no warranty. OpenSnitch donor a1353848ba1b660320e90cefea782c3fba272c00. See LICENSE and NOTICE.md; netlink dependency uses MIT.")
		return
	}
	if !*serve || flags.NArg() != 0 || options.OwnerUID == ^uint(0) || options.OwnerGID == ^uint(0) || options.OwnerUID > 0xffffffff || options.OwnerGID > 0xffffffff {
		fmt.Fprintln(os.Stderr, "Explicit --serve --owner-uid UID --owner-gid PRIVATE_GID is required. This program never installs firewall rules.")
		os.Exit(2)
	}
	if err := runDaemon(options); err != nil {
		fmt.Fprintln(os.Stderr, "NetworkControl Linux adapter failed:", err)
		os.Exit(1)
	}
}
