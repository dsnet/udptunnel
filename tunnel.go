// Copyright 2017, The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE.md file.

package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"net"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/songgao/water"
)

type direction byte

const (
	outbound direction = 'T' // Transmit
	inbound  direction = 'R' // Receive
)

type logger interface {
	Fatalf(string, ...interface{})
	Printf(string, ...interface{})
}

type tunnel struct {
	server  bool
	tunDev  string
	tunAddr string
	netAddr string
	ports   []uint16
	magic   string

	log logger

	// remoteAddr is the address of the remote endpoint and may be
	// arbitrarily updated.
	remoteAddr atomic.Value

	// testReady and testDrop are used by tests to detect specific events.
	testReady chan<- struct{} // Closed when tunnel is ready
	testDrop  chan<- []byte   // Copy of every dropped packet
}

// run starts the VPN tunnel over UDP using the provided config and logger.
// When the context is canceled, the function is guaranteed to block until
// it is fully shutdown.
//
// The channels testReady and testDrop are only used for testing and may be nil.
func (t tunnel) run(ctx context.Context) {
	// Determine the daemon mode from the network address.
	var wg sync.WaitGroup
	defer wg.Wait()

	// Create a new tunnel device (requires root privileges).
	iface, err := water.NewTUN(t.tunDev)
	if err != nil {
		t.log.Fatalf("error creating tun device: %v", err)
	}
	defer pingIface(&wg, t.tunAddr)
	defer iface.Close()
	if err := exec.Command("/sbin/ip", "link", "set", "dev", t.tunDev, "mtu", "1300").Run(); err != nil {
		t.log.Fatalf("ip link error: %v", err)
	}
	if err := exec.Command("/sbin/ip", "addr", "add", t.tunAddr+"/24", "dev", t.tunDev).Run(); err != nil {
		t.log.Fatalf("ip addr error: %v", err)
	}
	if err := exec.Command("/sbin/ip", "link", "set", "dev", t.tunDev, "up").Run(); err != nil {
		t.log.Fatalf("ip link error: %v", err)
	}

	// Create a new UDP socket.
	_, port, _ := net.SplitHostPort(t.netAddr)
	laddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort("", port))
	if err != nil {
		t.log.Fatalf("error resolving address: %v", err)
	}
	sock, err := net.ListenUDP("udp", laddr)
	if err != nil {
		t.log.Fatalf("error listening on socket: %v", err)
	}
	defer sock.Close()

	// TODO(dsnet): We should drop root privileges at this point since the
	// TUN device and UDP socket have been set up. However, there is no good
	// support for doing so currently: https://golang.org/issue/1435

	// Since the remote address could change due to updates to DNS,
	// start goroutine to periodically check DNS for a new address.
	if !t.server {
		raddr, err := net.ResolveUDPAddr("udp", t.netAddr)
		if err != nil {
			t.log.Fatalf("error resolving address: %v", err)
		}
		t.updateRemoteAddr(raddr)
		go func() {
			ticker := time.NewTicker(time.Minute)
			defer ticker.Stop()
			for range ticker.C {
				raddr, _ := net.ResolveUDPAddr("udp", t.netAddr)
				if isDone(ctx) {
					return
				}
				t.updateRemoteAddr(raddr)
			}
		}()
	}

	if t.testReady != nil {
		close(t.testReady)
	}
	magic := md5.Sum([]byte(t.magic))
	pf := newPortFilter(t.ports)
	pl := newPacketLogger(ctx, &wg, t.log)

	// Handle outbound traffic.
	wg.Add(1)
	go func() {
		defer wg.Done()
		b := make([]byte, 1<<16)
		for {
			n, err := iface.Read(b[len(magic):])
			if err != nil {
				if isDone(ctx) {
					return
				}
				t.log.Fatalf("tun read error: %v", err)
			}
			n += copy(b, magic[:])
			p := b[len(magic):n]

			raddr := t.loadRemoteAddr()
			if pf.Filter(p, outbound) || raddr == nil {
				if t.testDrop != nil {
					t.testDrop <- append([]byte(nil), p...)
				}
				pl.Log(p, outbound, true)
				continue
			}

			if _, err := sock.WriteToUDP(b[:n], raddr); err != nil {
				if isDone(ctx) {
					return
				}
				t.log.Fatalf("net write error: %v", err)
			}
			pl.Log(p, outbound, false)
		}
	}()

	// Handle inbound traffic.
	wg.Add(1)
	go func() {
		defer wg.Done()
		b := make([]byte, 1<<16)
		for {
			n, raddr, err := sock.ReadFromUDP(b)
			if err != nil {
				if isDone(ctx) {
					return
				}
				t.log.Fatalf("net read error: %v", err)
			}
			if !bytes.HasPrefix(b[:n], magic[:]) {
				if t.testDrop != nil {
					t.testDrop <- append([]byte(nil), b[:n]...)
				}
				t.log.Printf("invalid packet from remote address: %v", raddr)
				continue
			}
			p := b[len(magic):n]

			if pf.Filter(p, inbound) {
				if t.testDrop != nil {
					t.testDrop <- append([]byte(nil), p...)
				}
				pl.Log(p, inbound, true)
				continue
			}

			// We assume a matching magic prefix is sufficient to validate
			// that the new IP is really the remote endpoint.
			// We assume that any adversary capable of performing a replay
			// attack already has the power to disrupt communication.
			if t.server {
				t.updateRemoteAddr(raddr)
			}

			if _, err := iface.Write(p); err != nil {
				if isDone(ctx) {
					return
				}
				t.log.Fatalf("tun write error: %v", err)
			}
			pl.Log(p, inbound, false)
		}
	}()

	<-ctx.Done()
}

func (t *tunnel) loadRemoteAddr() *net.UDPAddr {
	addr, _ := t.remoteAddr.Load().(*net.UDPAddr)
	return addr
}
func (t *tunnel) updateRemoteAddr(addr *net.UDPAddr) {
	oldAddr := t.loadRemoteAddr()
	if addr != nil && (oldAddr == nil || !addr.IP.Equal(oldAddr.IP) || addr.Port != oldAddr.Port || addr.Zone != oldAddr.Zone) {
		t.remoteAddr.Store(addr)
		t.log.Printf("switching remote address: %v", addr)
	}
}

// pingIface sends a broadcast ping to the IP range of the TUN device
// until the TUN device has shutdown.
func pingIface(wg *sync.WaitGroup, addr string) {
	// HACK(dsnet): For reasons I do not understand, closing the TUN device
	// does not cause a pending Read operation to become unblocked and return
	// with some EOF error. As a workaround, we broadcast on the IP range
	// of the TUN device, forcing the Read to unblock with at least one packet.
	// The subsequent call to Read will properly report that it is closed.
	//
	// See https://github.com/songgao/water/issues/22
	addr = strings.TrimRight(addr, "0123456798") + "255"
	cmd := exec.Command("/bin/ping", "-c", "1", "-b", addr)
	cmd.Start()
	wg.Wait()
	cmd.Process.Kill()
}

func isDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}
