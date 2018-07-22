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

//sapdump is a tool to display information on received sap announcements
package main

import (
	"flag"
	"log"
	"net"
	"os"
	"path"
	"strings"
	"text/template"

	"github.com/Natolumin/multidrop/mcastutil"
	"github.com/Natolumin/multidrop/sap"
)

const defFormat = "{{.Payload}}\n"

var runTermui func(*sap.SDPConn) = nil

func main() {

	var format *string
	var curses bool

	if runTermui != nil {
		if path.Base(os.Args[0]) == "saptop" {
			curses = true
		} else {
			flag.BoolVar(&curses, "curses", false, "Display continuous stats instead of dumping incoming announcements (aka \"saptop\")")
		}
	}
	format = flag.String("format", defFormat, "Format string following text/template for dumping SAP announcements")

	//common options
	group := flag.String("group", "", "Comma-separated Group(s) on which to listen for SAP announcements.")
	v6only := flag.Bool("6", false, "Only listen on ipv6 groups (overriden by -group)")
	v4only := flag.Bool("4", false, "Only listen on ipv4 groups (overriden by -group)")

	ifname := flag.String("i", "", "Force binding to a specific interface for multicast group. "+
		"Without this, the OS default is used, which may often not be what you want")

	flag.Parse()

	if *v6only && *v4only {
		log.Fatal("Incompatible flags -4 and -6")
	}

	var iface *net.Interface
	if *ifname != "" {
		var err error
		if iface, err = net.InterfaceByName(*ifname); err != nil {
			log.Fatalf("Could not find interface %s: %v\n", *ifname, err)
		}
	}

	// Socket setup
	var gaddrs []net.IP
	if *group == "" {
		if *v4only {
			gaddrs = []net.IP{sap.GroupAddr4}
		} else if *v6only {
			gaddrs = []net.IP{sap.V6GroupByZone(2), sap.V6GroupByZone(5), sap.V6GroupByZone(8), sap.V6GroupByZone(0xe)}
		} else {
			gaddrs = []net.IP{sap.V6GroupByZone(2), sap.V6GroupByZone(5), sap.V6GroupByZone(8), sap.V6GroupByZone(0xe), sap.GroupAddr4}
		}
	} else {
		groups := strings.Split(*group, ",")
		gaddrs = make([]net.IP, len(groups))
		for i, g := range groups {
			gaddrs[i] = net.ParseIP(g)
		}
	}
	tc, err := mcastutil.ListenMulticastUDP(gaddrs, sap.SAPPort, iface)
	if err != nil {
		log.Fatalf("Could not join all multicast groups: %v", err)
	}
	conn := (*sap.SDPConn)(tc)

	// now loop-dump everything
	if !curses {
		tmpl, err := template.New("format").Parse(*format)
		if err != nil {
			log.Fatalf("Invalid template: %s", err)
		}
		for {
			packet, err := conn.Read()
			if err == nil {
				if err = tmpl.Execute(os.Stdout, packet); err != nil {
					log.Fatal(err)
				}
			} else {
				log.Print(err)
			}
		}
	} else {
		if runTermui != nil {
			runTermui(conn)
		} else {
			panic("Trying to run in curses mode when curses mode is not built")
		}
	}
}
