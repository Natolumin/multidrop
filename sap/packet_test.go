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
	"encoding/hex"
	"net"
	"reflect"
	"testing"

	"github.com/pixelbender/go-sdp/sdp"
)

var testPackets = []struct {
	hexStream   string
	validSAP    bool
	validSDP    bool
	expected    Header
	rawPayload  []byte
	expectedsdp sdp.Description
}{
	{ // 1: Normal validSAP packet with explicit PayloadType and empty payload
		hexStream: "3000f8300000000000000000c0f13198207f00006170706c69636174696f6e2f73647000",
		validSAP:  true,
		validSDP:  true,
		expected: Header{Version: 1,
			AddressType: AddrTypeV6,
			Reserved:    false,
			Type:        TypeAnnounce,
			Encrypted:   false,
			Compressed:  false,
			AuthLen:     0,
			IDHash:      0xf830,
			OrigSrc:     net.ParseIP("::c0f1:3198:207f:0"),
			PayloadType: SDPPayloadType,
			Len:         36,
		},
	},
	{ // 2: Normal validSAP IPv4 packet
		hexStream: "2000f830207f00006170706c69636174696f6e2f73647000",
		validSAP:  true,
		validSDP:  true,
		expected: Header{Version: 1,
			AddressType: AddrTypeV4,
			Reserved:    false,
			Type:        TypeAnnounce,
			Encrypted:   false,
			Compressed:  false,
			AuthLen:     0,
			IDHash:      0xf830,
			OrigSrc:     net.IP{0x20, 0x7f, 0, 0},
			PayloadType: SDPPayloadType,
			Len:         24,
		},
	},
	{ // 3: Normal validSAP packet with implicit PayloadType
		hexStream: "3000f8300000000000000000c0f13198207f0000" + "763d300d0a",
		validSAP:  true,
		validSDP:  true,
		expected: Header{Version: 1,
			AddressType: AddrTypeV6,
			Reserved:    false,
			Type:        TypeAnnounce,
			Encrypted:   false,
			Compressed:  false,
			AuthLen:     0,
			IDHash:      0xf830,
			OrigSrc:     net.ParseIP("::c0f1:3198:207f:0"),
			PayloadType: SDPPayloadType,
			Len:         20,
		},
		rawPayload:  []byte("v=0\r\n"),
		expectedsdp: sdp.Description{Version: 0},
	},
	{ // 4: v0 Normal validSAP packet with implicit PayloadType
		hexStream: "1000f8300000000000000000c0f13198207f0000",
		validSAP:  true,
		validSDP:  true,
		expected: Header{Version: 0,
			AddressType: AddrTypeV6,
			Reserved:    false,
			Type:        TypeAnnounce,
			Encrypted:   false,
			Compressed:  false,
			AuthLen:     0,
			IDHash:      0xf830,
			OrigSrc:     net.ParseIP("::c0f1:3198:207f:0"),
			PayloadType: SDPPayloadType,
			Len:         20,
		},
	},
	{ // 5: v1 validSAP !validSDP
		hexStream: "3000f8300000000000000000c0f13198207f00006170706c69636174696f6e2f73647000" + "773d300d0a",
		validSAP:  true,
		validSDP:  false,
		expected: Header{Version: 1,
			AddressType: AddrTypeV6,
			Reserved:    false,
			Type:        TypeAnnounce,
			Encrypted:   false,
			Compressed:  false,
			AuthLen:     0,
			IDHash:      0xf830,
			OrigSrc:     net.ParseIP("::c0f1:3198:207f:0"),
			PayloadType: SDPPayloadType,
			Len:         36,
		},
		rawPayload: []byte("w=0\r\n"),
	},
	{ // 6: Implicit PayloadType and invalidSAP payload
		hexStream: "3000f8300000000000000000c0f13198207f0000" +
			"6f3d4d754d7544564220333536343433203120494e2049503620666631353a343234323a3a303a313a303430313a30",
	},
	{ // 7: Incorrect version
		hexStream: "5000f8300000000000000000c0f13198207f00006170706c69636174696f6e2f73647000",
	},
	{ // 8: Truncated packet (initial header)
		hexStream: "30",
	},
	{ // 9: Truncated packet (IPv6 address)
		hexStream: "3000f8300000000000000000c0f131",
	},
	{ // 10: Truncated packet (IPv4 address)
		hexStream: "2000f835a128",
	},
	{ // 11: Invalid PayloadType
		hexStream: "3000f8300000000000000000c0f13198207f00006270706c69636174696f6e2f73647000" + "763d300d0a",
		validSAP:  true,
		validSDP:  false,
		expected: Header{Version: 1,
			AddressType: AddrTypeV6,
			Reserved:    false,
			Type:        TypeAnnounce,
			Encrypted:   false,
			Compressed:  false,
			AuthLen:     0,
			IDHash:      0xf830,
			OrigSrc:     net.ParseIP("::c0f1:3198:207f:0"),
			PayloadType: "bpplication/sdp",
			Len:         36,
		},
		rawPayload: []byte("v=0\r\n"),
	},
	{ // 12: Truncated packet (incorrect authlen)
		hexStream: "30f0f8300000000000000000c0f13198207f00006170706c69636174696f6e2f73647000" + "773d300d0a",
	},
	{ // 13: validSAP packet with authdata
		hexStream: "3001f8300000000000000000c0f13198207f0000300000036170706c69636174696f6e2f73647000",
		validSAP:  true,
		validSDP:  true,
		expected: Header{Version: 1,
			AddressType: AddrTypeV6,
			Reserved:    false,
			Type:        TypeAnnounce,
			Encrypted:   false,
			Compressed:  false,
			AuthLen:     1,
			IDHash:      0xf830,
			OrigSrc:     net.ParseIP("::c0f1:3198:207f:0"),
			AuthData: &AuthData{
				Version:    1,
				Padding:    true,
				AuthMethod: AuthMethodPGP,
				PaddingLen: 3,
				Data:       []byte{},
			},
			PayloadType: SDPPayloadType,
			Len:         40,
		},
	},
	{ // 14: Invalid AuthData padding
		hexStream: "3001f8300000000000000000c0f13198207f0000300000136170706c69636174696f6e2f73647000",
	},
	{ // 15: Invalid AuthData Version
		hexStream: "3001f8300000000000000000c0f13198207f0000700000036170706c69636174696f6e2f73647000",
	},
}

func TestParse(t *testing.T) {
	for i, hexpacket := range testPackets {
		packet, err := hex.DecodeString(hexpacket.hexStream)
		if err != nil {
			t.Fatalf("Test packet %d malformed", i+1)
		}
		decoded, err := ParseHeader(packet)
		if !hexpacket.validSAP {
			if err == nil {
				t.Errorf("%d: InvalidSAP packet correctly decoded", i+1)
			}
			continue
		}
		if err != nil {
			t.Errorf("%d: Expected validSAP packet, got error %v", i+1, err)
			continue
		}
		if !reflect.DeepEqual(decoded, hexpacket.expected) {
			if !reflect.DeepEqual(decoded.AuthData, hexpacket.expected.AuthData) {
				t.Logf("%d: Auth data doesn't match: expected %v got %v", i+1, *hexpacket.expected.AuthData, *decoded.AuthData)
			}
			t.Errorf("%d: Incorrect decoding: expected %v got %v", i+1, hexpacket.expected, decoded)
			continue
		}
		if !bytes.Equal(packet[decoded.Len:], hexpacket.rawPayload) {
			t.Errorf("%d: Wrong payload offset, differing payloads: %x and %x", i+1, packet[decoded.Len:], hexpacket.rawPayload)
			continue
		}
	}
}

func TestParseSDP(t *testing.T) {
	for i, hexpacket := range testPackets {
		if !hexpacket.validSAP {
			continue
		}
		packet := Packet{
			Header:  hexpacket.expected,
			Payload: hexpacket.rawPayload,
			Len:     hexpacket.expected.Len + len(hexpacket.rawPayload),
		}
		if sdppacket, err := packet.ParseSDP(); (err == nil) != hexpacket.validSDP {
			if hexpacket.validSDP {
				t.Errorf("%d: Could not decode SDP payload: %x", i+1, hexpacket.rawPayload)
			} else {
				t.Errorf("%d: Could decode invalid SDP packet: %s", i+1, sdppacket.Payload.String())
			}
		} else if err == nil && sdppacket.Payload.String() != hexpacket.expectedsdp.String() {
			t.Errorf("%d: InvalidSAP SDP decode: expected: \n%s---got:\n%s", i+1, hexpacket.expectedsdp.String(), sdppacket.Payload.String())
		}
	}
}
