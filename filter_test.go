package main

import (
	"encoding/hex"
	"testing"
	"time"
)

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestFilter(t *testing.T) {
	// Mock the timeNow function for testing.
	oldTimeNow := timeNow
	defer func() { timeNow = oldTimeNow }()
	now := uint64(time.Now().Unix())
	timeNow = func() uint64 { return now }

	// Sequence of packets to pass through the filter.
	// Since the filter is stateful, the order of these tests matter.
	dh := mustDecodeHex
	tests := []struct {
		addTime   uint64    // Amount of time to add before test
		direction direction // The direction of the packet
		packet    []byte    // The packet data
		dropped   bool      // Should the packet be dropped?
	}{
		// Drop invalid packets.
		{1, inbound, dh("000000"), true},

		// Always allow sending ICMP packets.
		{1, outbound, dh("450000549e734000400188330a0000020a000001080068b5104b000106c9f65800000000b5090e0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637"), false},
		// Always allow receiving ICMP packets.
		{1, inbound, dh("4500005411c70000400154e00a0000010a000002000070b5104b000106c9f65800000000b5090e0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637"), false},

		// Drop outbound packet to non-specified port (src:6000, dst:37156).
		{1, outbound, dh("450000355f7e40004006c7420a0000020a00000117709124f1c002bc98efee28801800c336d800000101080a098a72a0098a77380a"), true},
		// Allow inbound packet to specified port (dst:37156, src:6000).
		{1, inbound, dh("451000369b89400040068b260a0000010a0000029124177098efee28f1c002bc801800c532d300000101080a098a8b66098a5f6a0d0a"), false},
		// Now allow outbound packet to non-specified port since we received traffic from it before (src:6000, dst:37156).
		{1, outbound, dh("450000345f7f40004006c7420a0000020a00000117709124f1c002bd98efee2a801000c32bb800000101080a098a7398098a8b66"), false},

		// Drop outbound packet to non-specified port (src:41614, dst:6001).
		{2000, outbound, dh("4510003c52af40004006d3fa0a0000020a000001a28e1771a857d99f00000000a002627001a40000020404ec0402080a098a8b300000000001030307"), true},

		// Drop inbound packet to non-specified port (src:6000, dst:41164).
		{1, inbound, dh("45100028ae1b4000400678a20a0000010a0000021770a0cc00000000948245b65014000009590000"), true},
		// Allow outbound packet to specified port (src:41164, dst:6000).
		{1, outbound, dh("4510003ccb64400040065b450a0000020a000001a0cc1770948245b500000000a0026270a7850000020404ec0402080a098a8ed10000000001030307"), false},
		// Now allow inbound packet to non-specified port since we transmitted traffic from it before (src:6000, dst:41164).
		{1, inbound, dh("45100028ae1b4000400678a20a0000010a0000021770a0cc00000000948245b65014000009590000"), false},

		// Drop inbound packet to non-specified port and from non-specified port (src:50564, dst:7000).
		{1, inbound, dh("4510003cd8ad400040064dfc0a0000010a000002c5841b586d7303d100000000a00262709b280000020404ec0402080a098fdb7c0000000001030307"), true},

		// Add significant amount of time and see formerly allowed packets to be rejected.
		{1, outbound, dh("450000345f7f40004006c7420a0000020a00000117709124f1c002bd98efee2a801000c32bb800000101080a098a7398098a8b66"), false},
		{1, inbound, dh("45100028ae1b4000400678a20a0000010a0000021770a0cc00000000948245b65014000009590000"), false},
		{3000, inbound, nil, true},
		{1, outbound, dh("450000345f7f40004006c7420a0000020a00000117709124f1c002bd98efee2a801000c32bb800000101080a098a7398098a8b66"), true},
		{1, inbound, dh("45100028ae1b4000400678a20a0000010a0000021770a0cc00000000948245b65014000009590000"), false},
		{3000, inbound, nil, true},
		{1, outbound, dh("450000345f7f40004006c7420a0000020a00000117709124f1c002bd98efee2a801000c32bb800000101080a098a7398098a8b66"), true},
		{1, inbound, dh("45100028ae1b4000400678a20a0000010a0000021770a0cc00000000948245b65014000009590000"), true},
	}

	pf := newPortFilter([]uint16{6000})
	for i, tt := range tests {
		now += tt.addTime
		dropped := pf.Filter(tt.packet, tt.direction)
		if dropped != tt.dropped {
			t.Errorf("test %d, Filter() = %t, want %t", i, dropped, tt.dropped)
		}
	}
}
