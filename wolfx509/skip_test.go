/* skip_test.go — shared skip helper for builds without --enable-certgen.
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 */

package wolfx509

import (
	"errors"
	"testing"
)

// skipIfCertGenMissing skips when err is the sentinel returned by
// CreateCertificate / CreateCertificateRequest on builds without
// WOLFSSL_CERT_GEN.
func skipIfCertGenMissing(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, ErrNotCompiledIn) {
		t.Skip("WOLFSSL_CERT_GEN not compiled in")
	}
}
