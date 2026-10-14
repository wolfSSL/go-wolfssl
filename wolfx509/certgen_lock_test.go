/* certgen_lock_test.go
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

package wolfx509

import (
	"sync"
	"testing"
	"time"
)

func TestCreateCertificateRequestHoldsKeyLock(t *testing.T) {
	k, err := GenerateP256Key()
	if err != nil {
		t.Fatalf("GenerateP256Key: %v", err)
	}
	defer k.Free()
	tmpl := &CertificateRequest{Subject: Name{CommonName: "lock.example"}}

	k.Lock()
	done := make(chan error, 1)
	go func() {
		_, err := CreateCertificateRequest(tmpl, k)
		done <- err
	}()
	select {
	case err := <-done:
		k.Unlock()
		t.Fatalf("CreateCertificateRequest ran while the key was locked (err=%v)", err)
	case <-time.After(50 * time.Millisecond):
	}
	k.Unlock()
	if err := <-done; err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
}

func TestCreateCertificateRequestConcurrentWithKeyFree(t *testing.T) {
	k, err := GenerateP256Key()
	if err != nil {
		t.Fatalf("GenerateP256Key: %v", err)
	}
	tmpl := &CertificateRequest{Subject: Name{CommonName: "race.example"}}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 10; j++ {
				der, err := CreateCertificateRequest(tmpl, k)
				if err == nil && len(der) == 0 {
					t.Error("CreateCertificateRequest returned empty DER")
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		k.Free()
	}()
	close(start)
	wg.Wait()
	if _, err := CreateCertificateRequest(tmpl, k); err == nil {
		t.Fatal("CreateCertificateRequest succeeded with a freed key")
	}
}
