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
	"log"
	"net"
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

// FindChannels finds the given channels in the SAP announcements
func (c *SDPConn) FindChannels(channels []string) map[string]*net.UDPAddr {

	matches := make(map[string]*net.UDPAddr)
	for {
		announce, err := c.Read()
		if err != nil {
			continue
		}
		for i := range channels {
			if announce.Payload.Session == channels[i] {
				matches[announce.Payload.Session] = &net.UDPAddr{
					IP:   net.ParseIP(announce.Payload.Origin.Address),
					Port: announce.Payload.Media[0].Port, //XXX: Eh
				}
			}
		}
		if len(matches) == len(channels) {
			break
		}
	}
	return matches
}

// CountStreams starts a routine that keeps count of available streams
func (c *SDPConn) CountStreams() StreamChan {
	sch := newStreamChan()
	go c.countStreams(sch)
	return sch
}

// StreamChan is an opaque structure to control the countStreams function
type StreamChan struct {
	datachan    chan []AdvLifetime
	controlchan chan bool
}

func newStreamChan() StreamChan {
	return StreamChan{
		datachan:    make(chan []AdvLifetime),
		controlchan: make(chan bool),
	}
}

// Close implements the Closer interface
func (c StreamChan) Close() {
	c.controlchan <- false
	close(c.controlchan)
}
func (c StreamChan) Read() []AdvLifetime {
	c.controlchan <- true
	return <-c.datachan
}

// AdvLifetime is a sdp.Description annotated with timing information
type AdvLifetime struct {
	sdp.Description
	Last     time.Time
	Interval time.Duration
	Count    int
}

func (c *SDPConn) countStreams(cch StreamChan) {
	var channels []AdvLifetime
	dch := make(chan *sdp.Description)
	go func() {
		for {
			p, err := c.Read()
			if err == nil {
				dch <- &p.Payload
			} else {
				return
			}
		}
	}()
	for {
		select {
		case msg := <-cch.controlchan:
			if !msg {
				close(cch.datachan)
				return
			}
			var snapshot []AdvLifetime
			for _, c := range channels {
				//sdp.Description doesn't provide a deep-copy. Parse(String()) is good enough
				copyc, err := sdp.Parse(c.Description.String())
				if err != nil {
					log.Printf("sdp could not parse own string: %v", c.Description.String())
					continue
				}
				snapshot = append(snapshot, AdvLifetime{
					Description: *copyc,
					Last:        c.Last,
					Interval:    c.Interval,
					Count:       c.Count,
				})
			}
			cch.datachan <- snapshot
		case p := <-dch:
			found := false
			for i, c := range channels {
				if c.Session == p.Session {
					found = true
					channels[i].Interval = time.Now().Sub(c.Last)
					channels[i].Last = time.Now()
					channels[i].Count++
					break
				}
			}
			if !found {
				channels = append(channels, AdvLifetime{
					Description: *p,
					Last:        time.Now(),
					Count:       1,
				})
			}
		}
	}
}
