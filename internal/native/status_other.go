//go:build !darwin

package native

import "os"

// readRootFile: the native runtime is macOS-only; elsewhere nothing writes
// the file.
func readRootFile(path string) ([]byte, error) { return os.ReadFile(path) }
