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

// Package sap provides a parser for SAP packages
package sap

import (
	"net"
	"sync"
	"time"

	"github.com/pixelbender/go-sdp/sdp"
)

const (
	// SAPPort is the well-known port for SAP announces
	SAPPort    = 9875
	initialMTU = 1500
)

var (
	// GroupAddr4 is the standard multicast group address for SAP announcements on ipv4
	GroupAddr4 = net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 224, 2, 127, 254}
	// GroupAddr6 is the standard multicast group address for SAP announcements on ipv6
	GroupAddr6 = net.IP{0xff, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x7f, 0xfe}
)

//V6GroupByZone returns the multicast group address associated with a given zone
func V6GroupByZone(zone uint8) net.IP {
	gaddr := make(net.IP, net.IPv6len)
	copy(gaddr, GroupAddr6)
	gaddr[1] = zone
	return gaddr
}

// DefaultSAPGroups is an helper variable with the default groups to listen to for SAP announcements
var DefaultSAPGroups = []net.IP{
	V6GroupByZone(2),
	V6GroupByZone(5),
	V6GroupByZone(8),
	V6GroupByZone(0xe),
	GroupAddr4,
}

// Conn implements ReadCloser for SAP packets
type Conn net.UDPConn

func (c *Conn) Read() (p *Packet, err error) {
	b := make([]byte, initialMTU)

	len, err := (*net.UDPConn)(c).Read(b)
	if err != nil {
		return
	}
	p = new(Packet)

	if p.Header, err = ParseHeader(b[:len]); err == nil {
		p.Payload = b[p.Header.len:len]
	}
	return
}

// SDPConn implements ReadCloser for SDP/SAP packets
type SDPConn net.UDPConn

func (c *SDPConn) Read() (*SDPPacket, error) {
	header, err := (*Conn)(c).Read()
	if err != nil {
		return nil, err
	}
	return header.ParseSDP()
}

// AdvLifetime is a sdp.Description annotated with timing information
type AdvLifetime struct {
	sdp.Description
	Hash     uint16
	Last     time.Time
	Interval time.Duration
	Count    int
}

type origHash struct {
	IDHash  uint16
	OrigSrc [16]byte
}

type channelMap struct {
	sync.RWMutex
	conn          *SDPConn
	lifetimes     map[origHash]AdvLifetime
	notifications chan bool
}

// StreamsAccumulator receives and counts SAP announcements and provides a list of them in a channel when needed
type StreamsAccumulator interface {
	// Iterator makes it possible to use for := range loops on this interface
	Iterator(ChannelFilter) <-chan AdvLifetime
	// WaitChange provides notification when an item is modified
	WaitChange() bool
	// Close cleans up resources after use
	Close()
}

func (m *channelMap) Iterator(filter ChannelFilter) <-chan AdvLifetime {
	m.RLock()
	ch := make(chan AdvLifetime, len(m.lifetimes))
	go func() {
		for _, v := range m.lifetimes {
			if filter(&v) {
				ch <- v
			}
		}
		m.RUnlock()
		close(ch)
	}()
	return ch
}

func (m *channelMap) WaitChange() bool {
	_, ok := <-m.notifications
	return ok
}

func (m *channelMap) Close() {
	m.conn.Close()
}

// CountStreams starts a routine that keeps count of available streams
func (c *SDPConn) CountStreams() StreamsAccumulator {
	channels := channelMap{
		conn:          c,
		lifetimes:     make(map[origHash]AdvLifetime),
		notifications: make(chan bool),
	}
	go countStreams(&channels)
	return &channels
}

func countStreams(channels *channelMap) {
	for {
		p, err := channels.conn.Read()
		if err != nil {
			break
		}

		hash := origHash{IDHash: p.IDHash}
		copy(hash.OrigSrc[:], p.OrigSrc.To16())
		channels.Lock()
		if channel, ok := channels.lifetimes[hash]; ok {
			channel.Interval = time.Now().Sub(channel.Last)
			channel.Last = time.Now()
			channel.Count++
			channels.lifetimes[hash] = channel
		} else {
			channels.lifetimes[hash] = AdvLifetime{Description: p.Payload, Hash: p.IDHash, Last: time.Now(), Count: 1}
		}
		channels.Unlock()
		channels.notifications <- true
	}

	close(channels.notifications)
}
