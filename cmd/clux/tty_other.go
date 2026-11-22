//go:build !darwin && !linux && !windows

package main

import "os"

// isTerminal: unknown platforms never prompt.
func isTerminal(*os.File) bool { return false }
