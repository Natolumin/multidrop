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
	"strconv"
	"strings"
	"time"

	"github.com/Natolumin/multidrop/mcastutil"
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
		log.Println("Incompatible options: channel and group")
		flag.PrintDefaults()
	}
	if *channel != "" && *port != -1 {
		log.Println("Incompatible options: channel and port")
		flag.PrintDefaults()
	}

	// Auto-reconnect on channel loss
	var gaddr *net.UDPAddr
	if *group != "" {
		gaddr = &net.UDPAddr{
			IP:   net.ParseIP(*group),
			Port: *port,
		}
		rtpconn, err := mcastutil.ListenMulticastUDP([]net.IP{gaddr.IP}, gaddr.Port, nil)
		if err != nil {
			log.Fatalf("Could not listen on rtp address: %v", err)
		}
		parseRTP("["+*group+"]:"+strconv.Itoa(*port), rtpconn, gaddr)
	} else {
		tc, err := mcastutil.ListenMulticastUDP(sap.DefaultSAPGroups, sap.SAPPort, nil)
		if err != nil {
			log.Fatalf("Could not connect to all multicast groups: %v", err)
		}
		conn := (*sap.SDPConn)(tc)
		groups := conn.CountStreams()

		var filter sap.ChannelFilter
		if *channel != "" {
			channels := strings.Split(*channel, ",")
			filter = sap.FilterAnd(sap.FilterNotExpired, sap.ChannelList(channels))
		} else {
			filter = sap.FilterNotExpired
		}

		knownChannels := map[string]*net.UDPConn{}
		for groups.WaitChange() {
			for grp := range groups.Iterator(filter) {
				gaddr = &net.UDPAddr{
					IP:   net.ParseIP(grp.Session.Connection.Address),
					Port: grp.Session.Media[0].Port,
				}
				if knownChannels[grp.Session.Name] != nil {
					//TODO: lock + map and cleanup when quitting parseRTP
					continue
				}
				log.Printf("Found channel %s on group %v ", grp.Session.Name, gaddr)
				var err error = nil
				knownChannels[grp.Session.Name], err =
					mcastutil.ListenMulticastUDP([]net.IP{gaddr.IP}, gaddr.Port, nil)
				if err != nil {
					log.Printf("Could not listen on rtp address: %v", err)
					continue
				}
				go parseRTP(grp.Session.Name, knownChannels[grp.Session.Name], gaddr)
			}
		}
	}
}

func parseRTP(identifier string, conn *net.UDPConn, filterIP *net.UDPAddr) {
	b := make([]byte, 1500)
	var seqnum uint16
	var started bool
	for {
		_ = conn.SetReadDeadline(time.Now().Add(time.Minute * 2))
		len, daddr, err := conn.ReadFromUDP(b)

		if daddr != filterIP {
			// On linux, with IPv4 without IP_MULTICAST_ALL or with IPv6, *all* the multicast streams that
			// *any socket on the machine* is subscribed to are distributed in *all* the sockets that match.
			// That means that if any other process on the machine is subscribed to an rtp stream on the
			// same port, even from a completely different address, we will get it here.
			// So yes, we have to do daddr filtering in userspace. Yes it is stupid.
			continue
		}

		if err, ok := err.(net.Error); ok && err.Timeout() {
			log.Printf("%s: Timeout exceeded: No packet received", identifier)
			return
		} else if err != nil {
			log.Printf("%s: Could not read from connection: %v", identifier, err)
			return
		}
		decoded, err := rtp.ParsePacket(b[:len])
		if err != nil {
			if debug {
				log.Printf("%s: Malformed packet (err: %v) %v", identifier, err, b)
			}
			return
		}
		if !started {
			log.Printf("%s: Stream start at sequence %d", identifier, decoded.SequenceNumber)
			seqnum = decoded.SequenceNumber - 1
		}
		if seqnum+1 != decoded.SequenceNumber {
			if decoded.SequenceNumber == 0 && seqnum <= 65500 {
				log.Printf("%s: Stream reset to sequence number 0. Emitter restart ?", identifier)
			} else if seqnum+1 == decoded.SequenceNumber-1 {
				log.Printf("%s: Lost packet %d", identifier, seqnum+1)
			} else {
				log.Printf("%s: Lost packets %d to %d", identifier, seqnum+1, decoded.SequenceNumber-1)
			}
		}
		seqnum = decoded.SequenceNumber
		started = true
	}
}
