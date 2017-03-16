package sap

import (
	"bytes"
	"errors"
	"log"
	"net"

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
func (p Params) ListenSAP() (<-chan *Packet, error) {
	sapAddr := net.UDPAddr{
		IP:   p.Addr,
		Port: p.Port,
	}
	conn, err := net.ListenMulticastUDP("udp", nil, &sapAddr)
	if err != nil {
		return nil, err
	}
	ch := make(chan *Packet, p.ChanLen)
	go streamDecode(conn, ch)
	return ch, nil
}

func streamDecode(conn net.PacketConn, announces chan<- *Packet) {
	b := make([]byte, initialMTU)
	for {
		var p Packet
		var desc *sdp.Description

		p.Len, _, p.Error = conn.ReadFrom(b)
		if p.Error != nil {
			goto next
		}
		p.Header, p.Error = Parse(b, p.Len)
		if p.Error != nil {
			goto next
		}

		if p.Header.PayloadType != SDPPayloadType {
			p.Error = errors.New("Packet payload is not SDP")
			goto next
		}

		desc, p.Error = sdp.Parse(string(p.Header.Payload))
		p.Description = *desc
		if p.Error != nil {
			continue
		}
	next:
		select {
		case announces <- &p:
		default:
			log.Print("Full Buffer! Increase buffer size")
		}
	}
}

// Parse parses the given buffer for an SAP header
func Parse(b []byte, totalLength int) (Header, error) {
	header := Header{
		Version:     (b[0] & 0xe0) >> 5,
		AddressType: (b[0] & 0x10) != 0,
		Reserved:    (b[0] & 0x80) != 0,
		Type:        (b[0] & 0x40) != 0,
		Compressed:  (b[0] & 0x20) != 0,
		Encrypted:   (b[0] & 0x10) != 0,
		AuthLen:     b[1],
		IDHash:      ((uint16)(b[2]))<<8 + (uint16)(b[3]),
		Len:         4,
	}
	// Sanity checks
	if header.Version > 1 {
		err := errors.New("Invalid SAP version")
		return header, err
	}
	if totalLength < header.Len {
		err := errors.New("Invalid Length")
		return header, err
	}
	if header.AddressType == SAPAddrTypeV4 {
		header.OrigSrc = b[4:8]
		header.Len += 4
	} else {
		header.OrigSrc = b[4:20]
		header.Len += 16
	}
	if totalLength < header.Len {
		err := errors.New("Invalid Length")
		return header, err
	}

	if header.AuthLen > 0 {
		header.AuthData = b[header.Len : header.Len+(int)(header.AuthLen)*4]
		header.Len += (int)(header.AuthLen) * 4
	}
	if totalLength < header.Len {
		err := errors.New("Invalid Length")
		return header, err
	}

	if header.Version != 0 {
		var pltypelen int
		// Special case for no payload field, implicit "application/sdp"
		if bytes.Equal(b[header.Len:header.Len+3], []byte{'v', '=', '0'}) {
			header.PayloadType = SDPPayloadType
			pltypelen = 0
		} else {
			pltypelen = bytes.Index(b[header.Len:], []byte{0})
			if pltypelen < 0 {
				err := errors.New("Malformed payload type")
				return header, err
			}
			header.PayloadType = string(b[header.Len : header.Len+pltypelen])
		}
		header.Len += pltypelen + 1 // nullbyte at the end of payloadtype
	} else {
		header.PayloadType = SDPPayloadType
	}
	if totalLength < header.Len {
		err := errors.New("Invalid Length")
		return header, err
	}

	header.Payload = b[header.Len:totalLength]
	return header, nil
}
