// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024 QUIP Contributors

package probe

import "testing"

func TestValidCheckNameAcceptsEveryPublishedName(t *testing.T) {
	for _, name := range CheckNames() {
		if !ValidCheckName(name) {
			t.Errorf("ValidCheckName(%q) = false, want true", name)
		}
	}
}

func TestValidCheckNameNormalizesLikeRun(t *testing.T) {
	// Run lowercases and trims before matching, so validation must accept
	// anything Run would go on to recognize.
	for _, name := range []string{"P2P", " p2p ", "\tAPI_Port\n"} {
		if !ValidCheckName(name) {
			t.Errorf("ValidCheckName(%q) = false, want true", name)
		}
	}
}

func TestValidCheckNameRejectsUnknown(t *testing.T) {
	for _, name := range []string{"bogus", "", "p2p ports", "tls;rpc"} {
		if ValidCheckName(name) {
			t.Errorf("ValidCheckName(%q) = true, want false", name)
		}
	}
}

// CheckNames hands out a copy so a caller cannot corrupt the set of checks Run
// matches against.
func TestCheckNamesReturnsACopy(t *testing.T) {
	names := CheckNames()
	if len(names) == 0 {
		t.Fatal("CheckNames returned nothing")
	}
	original := names[0]
	names[0] = "clobbered"

	if got := CheckNames()[0]; got != original {
		t.Errorf("after mutating the result, CheckNames()[0] = %q, want %q", got, original)
	}
	if !ValidCheckName(original) {
		t.Errorf("mutating the result broke ValidCheckName(%q)", original)
	}
}
