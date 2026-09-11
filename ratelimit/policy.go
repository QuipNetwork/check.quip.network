// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024 QUIP Contributors

package ratelimit

import "time"

// This file holds the ban policy: how long a client is blocked after draining
// its bucket, and how long a violation record stands. The mechanics in
// ratelimit.go are policy-free — they only ask banDuration how long to ban and
// compare against violationDecay to decide whether the record has gone stale.

// maxBanDuration is the ceiling on any ban, no matter how many violations a
// client has accumulated. Tests assert no ban ever exceeds it.
const maxBanDuration = 5 * time.Minute

// violationDecay is how long a violation record stands before the ladder
// resets to level 1.
//
// It must stay longer than maxBanDuration. If a client could outlast the decay
// window by serving its ban, every violation would be a first violation and
// the ladder would never escalate. The margin here is threefold, so a client
// that trips, waits out a full ban, and trips again still climbs.
const violationDecay = 15 * time.Minute

// banDurations is the ban ladder, indexed by violation count. The first entry
// applies to the first violation; counts past the end get the last entry.
//
// The first ban is short on purpose. Draining a bucket that holds 10 requests
// and refills at 2 per second usually means a retry loop with no backoff, not
// an attack, and 30 seconds is long enough to break that loop while a human
// iterating on a firewall barely notices. A client that keeps hammering
// through the short ban reaches the ceiling on its third violation.
var banDurations = []time.Duration{
	30 * time.Second,
	2 * time.Minute,
	maxBanDuration,
}

// banDuration returns how long a client with the given violation count is
// banned. Counts past the end of the ladder get its last, longest entry.
func banDuration(violations int) time.Duration {
	idx := violations - 1
	if idx >= len(banDurations) {
		idx = len(banDurations) - 1
	}
	if idx < 0 {
		idx = 0
	}
	return banDurations[idx]
}
