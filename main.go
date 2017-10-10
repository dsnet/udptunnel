// Copyright 2017, The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE.md file.

// udptunnel is a daemon that sets up a point-to-point virtual private network
// between two hosts:
//	* A client host that may be behind an obtrusive NAT that frequently drops
//	TCP connections, but happens to pass UDP traffic reliably.
//	* A server host that is internet-accessible.
//
// This only supports Linux.
//
// Example Setup
//
// The udptunnel is setup by running it on two different hosts, one in a server
// configuration, and the other in client configuration. The difference between
// a server or client is determined by the NetworkAddress field in the
// configuration. If the address has an empty host portion, then the daemon
// operates in server mode. Otherwise, the daemon operates in client mode and
// will use the host to dial the server.
//
// Example server config:
//	{"TunnelAddress": "10.0.0.1", "NetworkAddress": ":8000", "AllowedPorts": [22]}
// Example client config:
//	{"TunnelAddress": "10.0.0.2", "NetworkAddress": "example.com:8000", "AllowedPorts": [22]}
//
// See the TunnelConfig struct for more details.
//
// Security Considerations
//
// TUN traffic is sent ad-verbatim between the two endpoints via unencrypted
// UDP traffic. The intended use case is to run a secure protocol (like SSH;
// see github.com/dsnet/sshtunnel) on top of this simple VPN. In order to
// prevent attackers from connecting to other locally binded sockets on the
// endpoints, a simple port filter is built-in to restrict IP traffic to only
// the specified ports. Users of udptunnel should also setup iptable rules as
// a secondary measure to restrict malicious traffic.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"path"
	"syscall"

	"github.com/dsnet/golib/jsonfmt"
)

// Version of the udptunnel binary. May be set by linker when building.
var version string

type TunnelConfig struct {
	// LogFile is where the tunnel daemon will direct its output log.
	// If the path is empty, then the server will output to os.Stderr.
	LogFile string `json:",omitempty"`

	// TunnelDevice is the name of the TUN device (default: "tunnel").
	TunnelDevice string

	// TunnelAddress is the private IPv4 address for the tunnel.
	// The client and server should have different IP addresses both in the
	// 255.255.255.0 subnet mask.
	// The default value is 10.0.0.1 for the server and 10.0.0.2 for the client.
	TunnelAddress string

	// NetworkAddress is the public host and port for UDP traffic.
	// If the host portion is empty, then the daemon is operting operating in
	// server mode and will bind on the specified port (e.g., ":8000").
	// Otherwise, the daemon is operating in client mode and will use the
	// specified host to communicate with the server (e.g., "example.com:8000").
	NetworkAddress string

	// AllowedPorts is a list of allowed UDP and TCP ports.
	// Since udptunnel sends traffic as unencrypted messages,
	// only protocols that provide application-layer security (like SSH)
	// should be used.
	//
	// The set of allowed ports must match on both the client and server.
	AllowedPorts []uint16

	// PacketMagic is used to generate a sequence of bytes that is prepended to
	// every TUN packet sent over UDP. Only inbound messages carrying the
	// magic sequence will be accepted. This mechanism is used as a trivial way
	// to protect against denial-of-service attacks by ensuring the server only
	// responds to remote IP addresses that are validated.
	//
	// This validation mechanism is only intended to protect against adversaries
	// with the ability to create arbitrary spoof UDP packets. It does not
	// protect against man-in-the-middle (MITM) attacks since any attacker with
	// the ability to intercept traffic already has the capability to block
	// communication between the client and server.
	//
	// This value must match on both the client and server.
	PacketMagic string `json:",omitempty"`
}

func loadConfig(conf string) (tunn tunnel, logger *log.Logger, closer func() error) {
	var logBuf bytes.Buffer
	logger = log.New(io.MultiWriter(os.Stderr, &logBuf), "", log.Ldate|log.Ltime|log.Lshortfile)

	var hash string
	if b, _ := ioutil.ReadFile(os.Args[0]); len(b) > 0 {
		hash = fmt.Sprintf("%x", sha256.Sum256(b))
	}

	// Load configuration file.
	var config TunnelConfig
	c, err := ioutil.ReadFile(conf)
	if err != nil {
		logger.Fatalf("unable to read config: %v", err)
	}
	if c, err = jsonfmt.Format(c, jsonfmt.Standardize()); err != nil {
		logger.Fatalf("unable to parse config: %v", err)
	}
	if err := json.Unmarshal(c, &config); err != nil {
		logger.Fatalf("unable to decode config: %v", err)
	}
	if config.TunnelDevice == "" {
		config.TunnelDevice = "tunnel"
	}
	host, _, _ := net.SplitHostPort(config.NetworkAddress)
	serverMode := host == ""
	if config.TunnelAddress == "" {
		if serverMode {
			config.TunnelAddress = "10.0.0.1"
		} else {
			config.TunnelAddress = "10.0.0.2"
		}
	}

	// Print the configuration.
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "\t")
	enc.Encode(struct {
		TunnelConfig
		BinaryVersion string `json:",omitempty"`
		BinarySHA256  string `json:",omitempty"`
	}{config, version, hash})
	logger.Printf("loaded config:\n%s", b.String())

	// Setup the log output.
	if config.LogFile == "" {
		logger.SetOutput(os.Stderr)
		closer = func() error { return nil }
	} else {
		f, err := os.OpenFile(config.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0664)
		if err != nil {
			logger.Fatalf("error opening log file: %v", err)
		}
		f.Write(logBuf.Bytes()) // Write log output prior to this point
		logger.Printf("suppress stderr logging (redirected to %s)", f.Name())
		logger.SetOutput(f)
		closer = f.Close
	}

	if _, _, err := net.SplitHostPort(config.NetworkAddress); err != nil {
		logger.Fatalf("invalid network address: %v", err)
	}
	if net.ParseIP(config.TunnelAddress).To4() == nil {
		logger.Fatalf("private tunnel address must be valid IPv4 address")
	}
	if len(config.AllowedPorts) == 0 {
		logger.Fatalf("no allowed ports specified")
	}
	tunn = tunnel{
		server:  serverMode,
		tunDev:  config.TunnelDevice,
		tunAddr: config.TunnelAddress,
		netAddr: config.NetworkAddress,
		ports:   config.AllowedPorts,
		magic:   config.PacketMagic,
		log:     logger,
	}
	return tunn, logger, closer
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "\t%s CONFIG_PATH\n", os.Args[0])
		os.Exit(1)
	}
	tunn, logger, closer := loadConfig(os.Args[1])
	defer closer()

	// Setup signal handler to initiate shutdown.
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		sigc := make(chan os.Signal, 1)
		signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
		logger.Printf("received %v - initiating shutdown", <-sigc)
		cancel()
	}()

	// Start the VPN tunnel.
	if tunn.server {
		logger.Printf("%s starting in server mode", path.Base(os.Args[0]))
	} else {
		logger.Printf("%s starting in client mode", path.Base(os.Args[0]))
	}
	defer logger.Printf("%s shutdown", path.Base(os.Args[0]))
	tunn.run(ctx)
}
