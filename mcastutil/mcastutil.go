//   Copyright 2017 Anatole Denis
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//Package mcastutil implements some multicast-related helper functions
package mcastutil

import (
	"net"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var maxMTU = 1500

func init() {
	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}
	for _, ifi := range ifaces {
		if ifi.MTU > maxMTU {
			maxMTU = ifi.MTU
		}
	}
}

func joinGroup(conn *net.UDPConn, ip *net.IPAddr) (err error) {
	pc6 := ipv6.NewPacketConn(conn)
	if err = pc6.JoinGroup(nil, ip); err == nil || ip.IP.To4() == nil {
		return
	}
	// If it doesn't work as IPv6 (apparently v4-mapped addresses are outright rejected)
	pc4 := ipv4.NewPacketConn(conn)
	err = pc4.JoinGroup(nil, ip)
	return
}
func leaveGroup(conn *net.UDPConn, ip *net.IPAddr) (err error) {
	pc6 := ipv6.NewPacketConn(conn)
	if err = pc6.LeaveGroup(nil, ip); err == nil || ip.IP.To4() == nil {
		return
	}
	// If it doesn't work as IPv6 (apparently v4-mapped addresses are outright rejected)
	pc4 := ipv4.NewPacketConn(conn)
	err = pc4.LeaveGroup(nil, ip)
	return
}

//ListenMulticastUDP reimplements net.ListenMulticastUDP with multiple groups simultaneously
func ListenMulticastUDP(gaddrs []net.IP, port int) (conn *net.UDPConn, err error) {
	// see net/sock_posix.go:184 we need to use a multicast address as laddr for proper SO_REUSEADDR setting
	conn, err = net.ListenUDP("udp6", &net.UDPAddr{IP: gaddrs[0], Port: port})
	if err != nil {
		return
	}

	for _, gaddr := range gaddrs {
		if err = joinGroup(conn, &net.IPAddr{IP: gaddr}); err != nil {
			return
		}
	}
	return
}
