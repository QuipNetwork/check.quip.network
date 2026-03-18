// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024 QUIP Contributors

package quip

import "encoding/binary"

const (
	// ALPN protocol identifier for QUIP v1.
	ALPN = "quip-v1"

	// DefaultPort is the default QUIP listening port.
	DefaultPort = 20049

	// ProtocolVersion is the current wire protocol version.
	ProtocolVersion byte = 1

	// Message types.
	MsgStatusRequest  byte = 0x06
	MsgStatusResponse byte = 0x86

	// HeaderSize is the wire header length in bytes:
	// [1B msg_type][1B version][4B request_id][4B payload_len]
	HeaderSize = 10

	// MaxDatagramFrameSize is the maximum QUIC datagram payload.
	MaxDatagramFrameSize = 65535
)

// BuildStatusRequest returns a wire-encoded STATUS_REQUEST datagram
// with the given request ID and an empty payload.
func BuildStatusRequest(requestID uint32) []byte {
	buf := make([]byte, HeaderSize)
	buf[0] = MsgStatusRequest
	buf[1] = ProtocolVersion
	binary.BigEndian.PutUint32(buf[2:6], requestID)
	binary.BigEndian.PutUint32(buf[6:10], 0) // payload_len = 0
	return buf
}

// IsStatusResponse checks whether the given datagram starts with
// a STATUS_RESPONSE message type byte.
func IsStatusResponse(data []byte) bool {
	return len(data) >= 1 && data[0] == MsgStatusResponse
}
