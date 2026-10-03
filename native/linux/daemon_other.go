//go:build !linux

// SPDX-License-Identifier: GPL-3.0-only
package main

import "errors"

func runDaemon(Options) error {
	return errors.New("the NFQUEUE adapter is only supported on Linux; no host changes were made")
}
