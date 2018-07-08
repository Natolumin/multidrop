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
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/pixelbender/go-sdp/sdp"
)

// Header is the header structure from RFC2974
type Header struct {
	Version     uint8
	AddressType bool
	Reserved    bool
	Type        bool
	Compressed  bool
	Encrypted   bool
	AuthLen     uint8
	IDHash      uint16
	AuthData    *AuthData
	OrigSrc     net.IP
	PayloadType string
	// Additional "metadata" fields
	len int
}

// AuthData is the subheader containing authentication data
type AuthData struct {
	Version    uint8
	Padding    bool
	AuthMethod uint8
	PaddingLen uint8
	Data       []byte
}

const (
	// AuthMethodPGP is the code to use in the AuthHeader for PGP authentication
	AuthMethodPGP = 0
	// AuthMethodCMS is the code to use in the AuthHeader for CMS(Cryptographic Message Syntax) authentication
	AuthMethodCMS = 1
)

// Packet represents an SAP packet after parsing
type Packet struct {
	Header
	Payload []byte
}

// SDPPacket is an SAP packet with decoded SDP payload
type SDPPacket struct {
	Header
	Payload sdp.Session
}

const (
	// TypeAnnounce is the value of the Type field for announcements
	TypeAnnounce = false
	// TypeDelete is the value of the Type field for deletions
	TypeDelete = true
	// AddrTypeV4 is the value of the AddressType field for IPv4
	AddrTypeV4 = false
	// AddrTypeV6 is the value of the AddressType field for IPv6
	AddrTypeV6 = true

	// SDPPayloadType is the default and only documented SAP payload type
	SDPPayloadType = "application/sdp"
)

// ParseHeader parses the given buffer for an SAP header
func ParseHeader(b []byte) (Header, error) {
	if len(b) < 4 {
		err := errors.New("invalid header length")
		return Header{}, err
	}
	header := Header{
		Version:     (b[0] & 0xe0) >> 5,
		AddressType: (b[0] & 0x10) != 0,
		Reserved:    (b[0] & 0x08) != 0,
		Type:        (b[0] & 0x04) != 0,
		Compressed:  (b[0] & 0x02) != 0,
		Encrypted:   (b[0] & 0x01) != 0,
		AuthLen:     b[1],
		IDHash:      uint16(b[3]) | uint16(b[2])<<8,
		len:         4,
	}
	// Sanity checks
	if header.Version > 1 {
		err := errors.New("invalid SAP version")
		return header, err
	}
	if header.AddressType == AddrTypeV4 {
		if len(b) < header.len+net.IPv4len {
			return header, errors.New("invalid header length")
		}
		header.OrigSrc = b[4:8]
		header.len += 4
	} else {
		if len(b) < header.len+net.IPv6len {
			return header, errors.New("invalid header length")
		}
		header.OrigSrc = b[4:20]
		header.len += 16
	}

	if header.AuthLen > 0 {
		if len(b) < header.len+int(header.AuthLen)*4 {
			return header, errors.New("invalid header length")
		}
		ahData, err := parseAuthData(b[header.len : header.len+(int)(header.AuthLen)*4])
		if err != nil {
			return header, err
		}
		header.len += (int)(header.AuthLen) * 4
		header.AuthData = &ahData
	}

	if header.Version != 0 {
		// Special case for no payload field, implicit "application/sdp"
		if len(b) >= header.len+3 && bytes.Equal(b[header.len:header.len+3], []byte{'v', '=', '0'}) {
			header.PayloadType = SDPPayloadType
		} else {
			pltypelen := bytes.Index(b[header.len:], []byte{0})
			if pltypelen < 0 {
				return header, errors.New("malformed payload type")
			}
			header.PayloadType = string(b[header.len : header.len+pltypelen])
			header.len += pltypelen + 1 // nullbyte at the end of payloadtype
		}
	} else {
		header.PayloadType = SDPPayloadType
	}

	return header, nil
}

func parseAuthData(b []byte) (AuthData, error) {
	d := AuthData{
		Version:    (b[0] & 0xe0) >> 5,
		Padding:    (b[0] & 0x10) != 0,
		AuthMethod: b[0] & 0x0f,
	}
	if d.Version != 1 {
		return d, fmt.Errorf("version %d is not supported", d.Version)
	}
	if d.Padding {
		d.PaddingLen = b[len(b)-1]
		if int(d.PaddingLen) > len(b)-1 {
			return d, errors.New("invalid padding length")
		}
	}

	d.Data = b[1 : len(b)-int(d.PaddingLen)]
	return d, nil
}

func booluint8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

//WriteBinary writes a packet in binary format
func (p *Packet) WriteBinary(b []byte) (int, error) {
	p.recomputeLen()

	if len(b) < p.len+len([]byte(p.Payload)) {
		return 0, errors.New("buffer too small")
	}

	b[0] = p.Version<<5 + booluint8(p.AddressType)<<4 + booluint8(p.Reserved)<<3 + booluint8(p.Type)<<2 + booluint8(p.Encrypted)<<1 + booluint8(p.Compressed)
	b[1] = p.AuthLen
	binary.BigEndian.PutUint16(b[2:4], p.IDHash)
	var curlen int
	if p.AddressType == AddrTypeV4 {
		copy(b[4:8], p.OrigSrc.To4())
		curlen = 8
	} else {
		copy(b[4:20], p.OrigSrc)
		curlen = 20
	}
	if p.AuthLen != 0 {
		if err := p.AuthData.writeBinary(b[curlen : curlen+int(p.AuthLen)*4]); err != nil {
			return curlen, err
		}
		curlen += int(p.AuthLen) * 4
	}
	if p.Version == 1 {
		copy(b[curlen:curlen+len([]byte(p.PayloadType))], []byte(p.PayloadType))
		curlen += len([]byte(p.PayloadType))
		b[curlen] = 0
		curlen++
	}
	copy(b[curlen:], p.Payload)
	curlen += len(p.Payload)
	return curlen, nil
}

//WriteBinary writes out a packet in binary format
func (p *SDPPacket) WriteBinary(b []byte) (int, error) {
	packet := Packet{Header: p.Header, Payload: []byte(p.Payload.String())}
	return packet.WriteBinary(b)
}

func (a *AuthData) writeBinary(b []byte) error {
	b[0] = a.Version<<5 + booluint8(a.Padding)<<4 + (a.AuthMethod & 0xff)
	copy(b[1:], a.Data)
	if a.Padding {
		copy(b[1+len(a.Data):], make([]byte, a.PaddingLen))
		b[len(a.Data)+int(a.PaddingLen)] = a.PaddingLen
	}
	return nil
}

func (p *Packet) Length() int {
	p.recomputeLen()
	return p.len + len(p.Payload)
}
func (p *SDPPacket) Length() int {
	p.recomputeLen()
	return p.len + len([]byte(p.Payload.String()))
}

func (h *Header) recomputeLen() {
	if h.AuthData != nil {
		h.AuthLen = h.AuthData.reflowPadding()
	}
	h.len = 4 + int(h.AuthLen)*4
	h.AddressType = (h.OrigSrc.To4() == nil)
	if h.AddressType == AddrTypeV4 {
		h.len += net.IPv4len
	} else {
		h.len += net.IPv6len
	}

	if h.Version != 0 {
		h.len += len([]byte(h.PayloadType)) + 1
	}
}

func (a *AuthData) reflowPadding() uint8 {
	// FIXME: error when data is too large
	authlen := uint8(len(a.Data) + 1)
	if a.Padding {
		authlen += a.PaddingLen
	}
	if authlen%4 != 0 {
		authlen -= a.PaddingLen
		a.PaddingLen = uint8(4 - ((len(a.Data) + 1) % 4))
		a.Padding = true
		return authlen/4 + 1
	}
	return authlen / 4
}

// ParseSDP converts an sap.Packet into an sap.SDPPacket by parsing the payload as SDP
func (p *Packet) ParseSDP() (sdppacket *SDPPacket, err error) {
	if p.PayloadType != SDPPayloadType {
		err = errors.New("invalid payload type: " + p.PayloadType)
		return
	}

	desc, err := sdp.Parse(p.Payload)
	if err != nil {
		return
	}
	sdppacket = &SDPPacket{
		Header:  p.Header,
		Payload: *desc,
	}
	return
}
