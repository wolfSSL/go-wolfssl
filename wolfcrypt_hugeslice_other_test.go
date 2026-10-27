//go:build !linux && !darwin
// +build !linux,!darwin

package wolfSSL

import "errors"

func mapInaccessible(n int) ([]byte, func(), error) {
	return nil, nil, errors.New("inaccessible mappings not supported on this platform")
}
