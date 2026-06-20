//go:build !linux

package main

import (
	"fmt"
	"os"
	"time"
)

func isRoot() bool {
	return false
}

func synScanPorts(targetIP string, ports []int, concurrency int, timeout time.Duration) []int {
	fmt.Fprintln(os.Stderr, "syn scan: not supported on this OS, use TCP connect scan instead")
	return nil
}
