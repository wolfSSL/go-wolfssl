//go:build linux || darwin
// +build linux darwin

package wolfSSL

import "syscall"

func mapInaccessible(n int) ([]byte, func(), error) {
	b, err := syscall.Mmap(-1, 0, n, syscall.PROT_NONE, syscall.MAP_PRIVATE|syscall.MAP_ANON)
	if err != nil {
		return nil, nil, err
	}
	return b, func() { syscall.Munmap(b) }, nil
}
