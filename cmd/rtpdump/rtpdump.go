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

//rtpdump is a tool to identify packet loss in multicast RTP diffusion
package main

import (
	"flag"
	"log"
	"net"
	"time"

	"github.com/Natolumin/multidrop/sap"

	"github.com/opennota/rtp/rtp"
)

var debug bool

func init() {
	flag.BoolVar(&debug, "v", false, "Be more verbose")
}

func main() {
	group := flag.String("group", "", "Group on which to listen for the stream")
	port := flag.Int("port", -1, "The port on which to listen for the stream")
	channel := flag.String("channel", "", "Channel to find in the SAP announcement then listen to. Defaults to all channels")
	flag.Parse()

	if *channel != "" && *group != "" {
		log.Print("Incompatible options: channel and group")
		flag.PrintDefaults()
	}
	if *channel != "" && *port != -1 {
		log.Print("Incompatible options: channel and port")
		flag.PrintDefaults()
	}
	if *channel == "" && (*port < 0 || *group == "") {
		log.Print("Port and group are required if channel is not given")
		flag.PrintDefaults()
	}

	// Auto-reconnect on channel loss
	var gaddr *net.UDPAddr
	if *channel == "" {
		gaddr = &net.UDPAddr{
			IP:   net.ParseIP(*group),
			Port: *port,
		}
	}
	for {
		if *channel != "" {
			groups := sap.DefaultParams.FindChannels([]string{*channel})
			gaddr = groups[*channel]
			if debug {
				log.Println("Found channel " + *channel)
			}
		}
		conn, err := net.ListenMulticastUDP("udp", nil, gaddr)
		if err != nil {
			if debug {
				log.Printf("Couldn't listen on %v", gaddr)
			}
			break
		}
		parseRTP(conn)
	}
}

func parseRTP(conn *net.UDPConn) {
	b := make([]byte, 1500)
	var seqnum uint16
	var started bool
	for {
		conn.SetReadDeadline(time.Now().Add(time.Minute * 2))
		len, _, err := conn.ReadFromUDP(b)
		if err, ok := err.(net.Error); ok && err.Timeout() {
			log.Println("Timeout exceeded: No packet received")
			return
		} else if err != nil {
			if debug {
				log.Printf("Could not read from connection: %v", err)
			}
			return
		}
		decoded, err := rtp.ParsePacket(b[:len])
		if err != nil {
			if debug {
				log.Printf("Malformed packet (err: %v) %v", err, b)
			}
			return
		}
		if !started {
			log.Printf("Stream start at sequence %d", decoded.SequenceNumber)
			seqnum = decoded.SequenceNumber - 1
		}
		if seqnum+1 != decoded.SequenceNumber {
			if decoded.SequenceNumber == 0 && seqnum <= 65500 {
				log.Println("Stream reset to sequence number 0. Emitter restart ?")
			} else if seqnum+1 == decoded.SequenceNumber-1 {
				log.Printf("Lost packet %d", seqnum+1)
			} else {
				log.Printf("Lost packets %d to %d", seqnum+1, decoded.SequenceNumber-1)
			}
		}
		seqnum = decoded.SequenceNumber
		started = true
	}
}
