//go:build !darwin

package main

import "os"

// isTerminal is only needed for the macOS native-mode offer.
func isTerminal(*os.File) bool { return false }
