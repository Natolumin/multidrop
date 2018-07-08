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
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/Natolumin/multidrop/mcastutil"
	"github.com/Natolumin/multidrop/sap"

	"github.com/LINBIT/termui"
	"github.com/emirpasic/gods/sets/treeset"
	godsutils "github.com/emirpasic/gods/utils"
	"github.com/pixelbender/go-sdp/sdp"
)

const defFormat = "{{.Payload}}\n"

const timeResolution = time.Second

var filter = func(lf *sap.AdvLifetime) bool {
	return lf.Last.Add(lf.Interval*10).After(time.Now()) || (lf.Count == 1 && lf.Last.Add(time.Minute*2).After(time.Now()))
}

func main() {

	var format *string
	var curses bool
	//Binary-specific options
	if path.Base(os.Args[0]) == "saptop" {
		curses = true
	} else {
		format = flag.String("format", defFormat, "Format string following text/template for dumping SAP announcements")
		flag.BoolVar(&curses, "curses", false, "Display continuous stats instead of dumping incoming announcements (aka \"saptop\")")
	}

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
		streams := conn.CountStreams()
		defer streams.Close()

		err := termui.Init()
		if err != nil {
			log.Panic(err)
		}
		defer termui.Close()

		go func() {
			evchan := termui.NewSysEvtCh()
			termui.Merge("user events", evchan)
			for streams.WaitChange() {
				evchan <- termui.Event{
					Path: "/net/recv",
					Time: time.Now().Unix(),
					Data: nil,
				}
			}
		}()

		tbl := termui.NewTable()
		tbl.Separator = false
		tbl.Border = false
		tbl.Width = termui.TermWidth()
		tbl.Height = termui.TermHeight()

		termui.Handle("/net/recv", func(termui.Event) {
			updateDisplay(tbl, streams)
		})
		termui.Handle("/timers/1s", func(termui.Event) {
			updateDisplay(tbl, streams)
		})
		termui.Handle("/sys/kbd/q", func(termui.Event) {
			termui.StopLoop()
		})
		termui.Handle("/sys/kbd/C-c", func(termui.Event) {
			termui.StopLoop()
		})
		termui.Handle("/sys/wnd/resize", func(termui.Event) {
			tbl.Width = termui.TermWidth()
			tbl.Height = termui.TermHeight()
		})
		termui.Loop()
	}
}

func updateDisplay(tbl *termui.Table, streams sap.StreamsAccumulator) {
	treeset := treeset.NewWith(func(a, b interface{}) int {
		return godsutils.StringComparator(
			a.(sap.AdvLifetime).Name+strconv.Itoa(int(a.(sap.AdvLifetime).Hash)),
			b.(sap.AdvLifetime).Name+strconv.Itoa(int(b.(sap.AdvLifetime).Hash)),
		)
	})
	displayed := [][]string{[]string{"Session", "Last Adv.", "Nb.", "Interval", "Group Address"}}

	for channel := range streams.Iterator(filter) {
		treeset.Add(channel)
	}
	it := treeset.Iterator()
	for it.Next() {
		channel := it.Value().(sap.AdvLifetime)
		displayed = append(displayed, []string{
			channel.Name,
			channel.Last.Format("15:04:05.000"),
			strconv.Itoa(channel.Count),
			(channel.Interval / timeResolution * timeResolution).String(),
			groupAddr(channel.Session),
		})
	}
	tbl.SetRows(displayed)
	termui.Render(tbl)
}

func groupAddr(d sdp.Session) string {
	addr := d.Origin.Address
	if net.ParseIP(addr).To4() == nil {
		addr = "[" + addr + "]"
	}
	var ports []string
	for _, m := range d.Media {
		ports = append(ports, strconv.Itoa(m.Port))
	}
	return addr + ":" + strings.Join(ports, ",")
}
