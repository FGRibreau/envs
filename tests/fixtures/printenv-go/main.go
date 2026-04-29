// Test fixture: a tiny Go program that prints specific env vars on stdout.
//
// Usage:
//   go build -o printenv-go main.go
//   ENVS_TEST_KEY=foo ./printenv-go ENVS_TEST_KEY
//   → prints "ENVS_TEST_KEY=foo"
//
// Why Go specifically?
//   The spec emphasizes that envs's wrapper architecture (set environ before
//   execve) works for any language including Go, which bypasses libc::getenv
//   and reads from runtime.envs at startup. This fixture proves that env vars
//   injected by `envs run` reach a Go binary's `os.Getenv()` correctly.
//
// Compiled lazily by `tests/it_go_compat.rs` if `go` is on PATH; otherwise the
// test is skipped.

package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: printenv-go KEY [KEY ...]")
		os.Exit(2)
	}
	for _, key := range os.Args[1:] {
		val := os.Getenv(key)
		fmt.Printf("%s=%s\n", key, val)
	}
}
