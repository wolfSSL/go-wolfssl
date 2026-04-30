/* testing_helpers_test.go — small shared helpers for tests.
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

package wolfSSL

import "testing"

// notCompiledIn aliases the package-level NOT_COMPILED_IN for in-package tests.
const notCompiledIn = NOT_COMPILED_IN

// skipIfNotCompiledIn skips the test when ret signals a missing wolfSSL feature.
func skipIfNotCompiledIn(t *testing.T, ret int, feature string) {
	t.Helper()
	if ret == notCompiledIn {
		t.Skipf("%s not compiled in", feature)
	}
}
