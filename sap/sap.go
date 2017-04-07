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
	"bytes"
	"errors"
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

// Header is the header structure frop RFC2974
type Header struct {
	Version     uint8
	AddressType bool
	Reserved    bool
	Type        bool
	Compressed  bool
	Encrypted   bool
	AuthLen     uint8
	IDHash      uint16
	AuthData    []byte
	OrigSrc     net.IP
	PayloadType string
	Payload     []byte
	// Additional "metadata" fields
	Len int
}

// Packet represents an SAP packet after parsing
type Packet struct {
	Header      Header
	Description sdp.Description
	Error       error
	Len         int
}

const (
	// SAPTAnnounce is the value of the Type field for announcements
	SAPTAnnounce = false
	// SAPTDelete is the value of the Type field for deletions
	SAPTDelete = true
	// SAPAddrTypeV4 is the value of the AddressType field for IPv4
	SAPAddrTypeV4 = false
	// SAPAddrTypeV6 is the value of the AddressType field for IPv6
	SAPAddrTypeV6 = true

	// SDPPayloadType is the default and only documented SAP payload type
	SDPPayloadType = "application/sdp"
)

// Params holds parameters for the SAP receiver.
type Params struct {
	ChanLen int
	Addr    net.IP
	Port    int
}

// DefaultParamsv6 is a helper params to listen on the default ipv6 address
var DefaultParamsv6 = Params{
	ChanLen: 30,
	Addr:    net.ParseIP("ff05::2:7ffe"),
	Port:    SAPPort,
}

// DefaultParams is a set of default SAP receiver parameters
var DefaultParams = DefaultParamsv6

// DefaultParamsv4 is a helper params to listen on the default ipv4 address
var DefaultParamsv4 = Params{
	ChanLen: 30,
	Addr:    net.IPv4(224, 2, 127, 254),
	Port:    SAPPort,
}

// ListenSAP returns a channel feeding received sdp Announces
func (p *Params) ListenSAP() (<-chan *Packet, chan<- bool, error) {
	sapAddr := net.UDPAddr{
		IP:   p.Addr,
		Port: p.Port,
	}
	conn, err := net.ListenMulticastUDP("udp", nil, &sapAddr)
	if err != nil {
		return nil, nil, err
	}
	ch := make(chan *Packet, p.ChanLen)
	controlChan := make(chan bool)
	go streamDecode(conn, ch, controlChan)
	return ch, controlChan, nil
}

func streamDecode(conn net.PacketConn, announces chan<- *Packet, control <-chan bool) {
	b := make([]byte, initialMTU)
	defer conn.Close()
	defer close(announces)
	for {
		var p Packet
		var desc *sdp.Description
		select {
		case _, ok := <-control:
			if !ok {
				return
			}
		default:
		}

		p.Len, _, p.Error = conn.ReadFrom(b)
		if p.Error != nil {
			goto next
		}
		p.Header, p.Error = Parse(b[:p.Len])
		if p.Error != nil {
			goto next
		}

		if p.Header.PayloadType != SDPPayloadType {
			p.Error = errors.New("Packet payload is not SDP")
			goto next
		}

		desc, p.Error = sdp.Parse(string(p.Header.Payload))
		p.Description = *desc
	next:
		select {
		case announces <- &p:
		default:
			log.Print("Full Buffer! Increase buffer size")
		}
	}
}

// Parse parses the given buffer for an SAP header
func Parse(b []byte) (Header, error) {
	if len(b) < 4 {
		err := errors.New("Invalid header length")
		return Header{}, err
	}
	header := Header{
		Version:     (b[0] & 0xe0) >> 5,
		AddressType: (b[0] & 0x10) != 0,
		Reserved:    (b[0] & 0x80) != 0,
		Type:        (b[0] & 0x40) != 0,
		Compressed:  (b[0] & 0x20) != 0,
		Encrypted:   (b[0] & 0x10) != 0,
		AuthLen:     b[1],
		IDHash:      uint16(b[3]) | uint16(b[2])<<8,
		Len:         4,
	}
	// Sanity checks
	if header.Version > 1 {
		err := errors.New("Invalid SAP version")
		return header, err
	}
	if header.AddressType == SAPAddrTypeV4 {
		if len(b) < header.Len+4 {
			return header, errors.New("Invalid header length")
		}
		header.OrigSrc = b[4:8]
		header.Len += 4
	} else {
		if len(b) < header.Len+6 {
			return header, errors.New("Invalid header length")
		}
		header.OrigSrc = b[4:20]
		header.Len += 16
	}

	if header.AuthLen > 0 {
		if len(b) < header.Len+int(header.AuthLen)*4 {
			return header, errors.New("Invalid header length")
		}
		header.AuthData = b[header.Len : header.Len+(int)(header.AuthLen)*4]
		header.Len += (int)(header.AuthLen) * 4
	}

	if header.Version != 0 {
		var pltypelen int
		// Special case for no payload field, implicit "application/sdp"
		if len(b) >= header.Len+3 && bytes.Equal(b[header.Len:header.Len+3], []byte{'v', '=', '0'}) {
			header.PayloadType = SDPPayloadType
			pltypelen = 0
		} else {
			pltypelen = bytes.Index(b[header.Len:], []byte{0})
			if pltypelen < 0 {
				return header, errors.New("Malformed payload type")
			} else if header.Len+pltypelen+1 > len(b) {
				return header, errors.New("Invalid header length")
			}
			header.PayloadType = string(b[header.Len : header.Len+pltypelen])
		}
		header.Len += pltypelen + 1 // nullbyte at the end of payloadtype
	} else {
		header.PayloadType = SDPPayloadType
	}

	header.Payload = b[header.Len:]
	return header, nil
}

// FindChannels finds the given channels in the SAP announcements
func (p *Params) FindChannels(channels []string) map[string]*net.UDPAddr {
	ch, controlch, err := p.ListenSAP()
	defer close(controlch)
	if err != nil {
		return nil
	}
	matches := make(map[string]*net.UDPAddr)
	for announce := range ch {
		for i := range channels {
			if announce.Description.Session == channels[i] {
				matches[announce.Description.Session] = &net.UDPAddr{
					IP:   net.ParseIP(announce.Description.Origin.Address),
					Port: announce.Description.Media[0].Port, //XXX: Eh
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
func CountStreams(sapch <-chan *Packet) StreamChan {
	sch := newStreamChan()
	go countStreams(sapch, sch)
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

func countStreams(dch <-chan *Packet, cch StreamChan) {
	var channels []AdvLifetime
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
			if p.Error != nil {
				continue
			}

			found := false
			for i, c := range channels {
				if c.Session == p.Description.Session {
					found = true
					channels[i].Interval = time.Now().Sub(c.Last)
					channels[i].Last = time.Now()
					channels[i].Count++
					break
				}
			}
			if !found {
				channels = append(channels, AdvLifetime{
					Description: p.Description,
					Last:        time.Now(),
					Count:       1,
				})
			}
		}
	}
}
