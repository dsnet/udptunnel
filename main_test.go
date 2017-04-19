// Copyright 2017, The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE.md file.

package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
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

type testLogger struct {
	*testing.T // Already has Fatalf method
}

func (t testLogger) Printf(f string, x ...interface{}) { t.Logf(f, x...) }

func TestTunnel(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("need root privileges")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sockSpecified, addrSpecified := openSocket(t) // Local UDP socket for specifically allowed traffic
	defer sockSpecified.Close()
	sockEphemeral, addrEphemeral := openSocket(t) // Local UDP socket with ephemeral port
	defer sockEphemeral.Close()
	sockRemote, _ := openSocket(t) // Remote socket for tunnel
	defer sockRemote.Close()
	sockLocal, addrLocal := openSocket(t) // Local socket for tunnel
	sockLocal.Close()                     // Close immediately so we can use the port

	chanSpecified := make(chan []byte, 1)
	go readSocket(t, ctx, sockSpecified, chanSpecified)
	chanEphemeral := make(chan []byte, 1)
	go readSocket(t, ctx, sockEphemeral, chanEphemeral)
	chanRemote := make(chan []byte, 1)
	go readSocket(t, ctx, sockRemote, chanRemote)

	chanDrop := make(chan []byte, 1)
	chanReady := make(chan struct{})
	go func() {
		defer close(chanDrop)
		config := TunnelConfig{
			TunnelDevice:   "test0",
			TunnelAddress:  "10.0.10.1",
			NetworkAddress: fmt.Sprintf(":%d", addrLocal.Port),
			AllowedPorts:   []uint16{uint16(addrSpecified.Port)},
		}
		run(ctx, config, testLogger{t}, chanReady, chanDrop)
	}()

	defer func() {
		cancel()
		sockSpecified.Close()
		sockEphemeral.Close()
		sockRemote.Close()
		for range chanSpecified {
		}
		for range chanEphemeral {
		}
		for range chanRemote {
		}
		for range chanDrop {
		}
	}()

	// Wait until the VPN tunnel is ready.
	<-chanReady

	magic := md5.Sum(nil)
	badMagic := md5.Sum([]byte("badMagic"))
	hello := []byte("hello")
	addrRemoteSpecified, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("10.0.10.2:%d", addrSpecified.Port))
	addrRemoteEphemeral, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("10.0.10.2:%d", addrEphemeral.Port))
	// Ping packet from 10.0.0.2 to 10.0.0.1.
	pingPacket := mustDecodeHex("450000542ded40004001e4b90a000a020a000a0108007ff17e6b000117c7f758000000002baf000000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637")
	// UDP packet from 10.0.0.2:0 to 10.0.0.1:0 with "hello" body.
	udpPacket := mustDecodeHex("450000218dac40004011851d0a000a020a000a0100000000000d000068656c6c6f")

	tests := []struct {
		action func() error
		result string
		check  func([]byte) error
	}{
		{
			// Outbound packet dropped because remote host is unknown.
			action: writeSocket(sockSpecified, []byte("hello"), addrRemoteSpecified),
			result: "dropped",
		}, {
			// Unable to authenticate remote host due to bad magic prefix.
			action: writeSocket(sockRemote, append(badMagic[:], pingPacket...), addrLocal),
			result: "dropped",
		}, {
			// Still unable to ping remote host since the host is unknown
			action: exec.Command("ping", "-c", "1", "-w", "1", "10.0.10.2").Start,
			result: "dropped",
		}, {
			// Remote host now sends ICMP packet with valid magic prefix.
			action: writeSocket(sockRemote, append(magic[:], pingPacket...), addrLocal),
			result: "outboundRemote",
			check:  wantICMP,
		}, {
			// Able to succesfully ping the remote host now.
			action: exec.Command("ping", "-c", "1", "-w", "1", "10.0.10.2").Start,
			result: "outboundRemote",
			check:  wantICMP,
		},

		// The next four tests are always dropped because they are all
		// UDP packets destined for an ephemeral port that we have not yet
		// seen any transmitted packet from that port.
		{
			action: writeSocket(sockSpecified, hello, addrRemoteEphemeral),
			result: "dropped",
		}, {
			action: writeSocket(sockEphemeral, hello, addrRemoteEphemeral),
			result: "dropped",
		}, {
			action: writeSocket(sockRemote, append(magic[:], setPorts(udpPacket, addrSpecified.Port, addrEphemeral.Port)...), addrLocal),
			result: "dropped",
		}, {
			action: writeSocket(sockRemote, append(magic[:], setPorts(udpPacket, addrEphemeral.Port, addrEphemeral.Port)...), addrLocal),
			result: "dropped",
		},

		// The next four tests are always allowed because they are all
		// UDP packets to a specifically allowed port.
		{
			action: writeSocket(sockSpecified, hello, addrRemoteSpecified),
			result: "outboundRemote",
			check:  wantUDP,
		}, {
			action: writeSocket(sockEphemeral, hello, addrRemoteSpecified),
			result: "outboundRemote",
			check:  wantUDP,
		}, {
			action: writeSocket(sockRemote, append(magic[:], setPorts(udpPacket, addrSpecified.Port, addrSpecified.Port)...), addrLocal),
			result: "inboundSpecified",
			check:  wantHello,
		}, {
			action: writeSocket(sockRemote, append(magic[:], setPorts(udpPacket, addrEphemeral.Port, addrSpecified.Port)...), addrLocal),
			result: "inboundSpecified",
			check:  wantHello,
		},

		// Two of the next four tests are allowed now even though they are
		// destined for an ephemeral port because we have now seen a packet
		// transmitted from that port.
		// Packets where both the source and destination are ephemeral are
		// still always dropped.
		{
			action: writeSocket(sockSpecified, hello, addrRemoteEphemeral),
			result: "outboundRemote",
			check:  wantUDP,
		}, {
			action: writeSocket(sockEphemeral, hello, addrRemoteEphemeral),
			result: "dropped",
		}, {
			action: writeSocket(sockRemote, append(magic[:], setPorts(udpPacket, addrSpecified.Port, addrEphemeral.Port)...), addrLocal),
			result: "inboundEphemeral",
			check:  wantHello,
		}, {
			action: writeSocket(sockRemote, append(magic[:], setPorts(udpPacket, addrEphemeral.Port, addrEphemeral.Port)...), addrLocal),
			result: "dropped",
		},
	}

	for i, tt := range tests {
		if err := tt.action(); err != nil {
			t.Fatalf("test %d, action failed: %v", i, err)
		}
		var result string
		var b []byte
		select {
		case b = <-chanSpecified:
			result = "inboundSpecified"
		case b = <-chanEphemeral:
			result = "inboundEphemeral"
		case b = <-chanRemote:
			result = "outboundRemote"
		case b = <-chanDrop:
			result = "dropped"
		case <-time.After(1 * time.Second):
			t.Fatalf("timed out waiting for response")
		}
		if result != tt.result {
			t.Fatalf("test %d, mismatching result: got %s, want %s", i, result, tt.result)
		}
		if tt.check == nil {
			continue
		}
		if err := tt.check(b); err != nil {
			t.Fatalf("test %d, check failed: %v", i, err)
		}
	}
}

func openSocket(t *testing.T) (sock *net.UDPConn, addr *net.UDPAddr) {
	sock, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		t.Fatalf("error listening on socket: %v", err)
	}
	addr, err = net.ResolveUDPAddr("udp", sock.LocalAddr().String())
	if err != nil {
		t.Fatalf("error resolving address: %v", err)
	}
	return sock, addr
}

func readSocket(t *testing.T, ctx context.Context, sock *net.UDPConn, c chan<- []byte) {
	defer close(c)
	buf := make([]byte, 1<<16)
	for {
		n, _, err := sock.ReadFromUDP(buf)
		if err != nil {
			if !isDone(ctx) {
				t.Errorf("sock read error: %v", err)
			}
			return
		}
		c <- append([]byte(nil), buf[:n]...)
	}
}

func writeSocket(sock *net.UDPConn, b []byte, addr *net.UDPAddr) func() error {
	return func() error {
		_, err := sock.WriteToUDP(b, addr)
		return err
	}
}

func setPorts(p []byte, src, dst int) []byte {
	p = append([]byte(nil), p...)
	b := ipPacket(p).Body()
	binary.BigEndian.PutUint16(b[:2], uint16(src))
	binary.BigEndian.PutUint16(b[2:], uint16(dst))
	return p
}

func wantICMP(b []byte) error {
	if len(b) > md5.Size {
		b = b[md5.Size:] // Strip magic
	}
	if proto := ipPacket(b).Protocol(); proto != icmp {
		return fmt.Errorf("got protocol %d, want ICMP", proto)
	}
	return nil
}

func wantUDP(b []byte) error {
	if len(b) > md5.Size {
		b = b[md5.Size:] // Strip magic
	}
	if proto := ipPacket(b).Protocol(); proto != udp {
		return fmt.Errorf("got protocol %d, want UDP", proto)
	}
	return wantHello(ipPacket(b).Body()[8:])
}

func wantHello(b []byte) error {
	if !bytes.Equal(b, []byte("hello")) {
		return fmt.Errorf("got %q, want %q", b, "hello")
	}
	return nil
}
