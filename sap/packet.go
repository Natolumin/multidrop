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
	Len int
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
	Len     int
}

// SDPPacket is an SAP packet with decoded SDP payload
type SDPPacket struct {
	Header
	Payload sdp.Description
	Len     int
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
		Len:         4,
	}
	// Sanity checks
	if header.Version > 1 {
		err := errors.New("invalid SAP version")
		return header, err
	}
	if header.AddressType == AddrTypeV4 {
		if len(b) < header.Len+net.IPv4len {
			return header, errors.New("invalid header length")
		}
		header.OrigSrc = b[4:8]
		header.Len += 4
	} else {
		if len(b) < header.Len+net.IPv6len {
			return header, errors.New("invalid header length")
		}
		header.OrigSrc = b[4:20]
		header.Len += 16
	}

	if header.AuthLen > 0 {
		if len(b) < header.Len+int(header.AuthLen)*4 {
			return header, errors.New("invalid header length")
		}
		ahData, err := parseAuthData(b[header.Len : header.Len+(int)(header.AuthLen)*4])
		if err != nil {
			return header, err
		}
		header.Len += (int)(header.AuthLen) * 4
		header.AuthData = &ahData
	}

	if header.Version != 0 {
		// Special case for no payload field, implicit "application/sdp"
		if len(b) >= header.Len+3 && bytes.Equal(b[header.Len:header.Len+3], []byte{'v', '=', '0'}) {
			header.PayloadType = SDPPayloadType
		} else {
			pltypelen := bytes.Index(b[header.Len:], []byte{0})
			if pltypelen < 0 {
				return header, errors.New("malformed payload type")
			}
			header.PayloadType = string(b[header.Len : header.Len+pltypelen])
			header.Len += pltypelen + 1 // nullbyte at the end of payloadtype
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

// ParseSDP converts an sap.Packet into an sap.SDPPacket by parsing the payload as SDP
func (p *Packet) ParseSDP() (sdppacket *SDPPacket, err error) {
	if p.PayloadType != SDPPayloadType {
		err = errors.New("invalid payload type: " + p.PayloadType)
		return
	}

	desc, err := sdp.Parse(string(p.Payload))
	if err != nil {
		return
	}
	sdppacket = &SDPPacket{
		Header:  p.Header,
		Len:     p.Len,
		Payload: *desc,
	}
	return
}
