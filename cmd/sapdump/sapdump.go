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

	"github.com/Natolumin/multidrop/sap"
	"github.com/pixelbender/go-sdp/sdp"

	"github.com/LINBIT/termui"
)

const defFormat = `{{.Description}}
`

const timeResolution = time.Second

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

	flag.Parse()

	if *v6only && *v4only {
		log.Fatal("Incompatible flags -4 and -6")
	}

	allchan := make(chan *sap.Packet)
	if *group == "" {
		if !*v4only {
			ann6, _, err := sap.DefaultParamsv6.ListenSAP()
			if err != nil {
				log.Fatal(err)
			}
			go func() {
				for p := range ann6 {
					allchan <- p
				}
			}()

		}
		if !*v6only {
			ann4, _, err := sap.DefaultParamsv4.ListenSAP()
			if err != nil {
				log.Fatal(err)
			}
			go func() {
				for p := range ann4 {
					allchan <- p
				}
			}()
		}

	} else {
		groups := strings.Split(*group, ",")
		for _, g := range groups {
			param := sap.DefaultParams
			param.Addr = net.ParseIP(g)
			ann, _, err := param.ListenSAP()
			if err != nil {
				log.Fatal(err)
			}
			go func() {
				for p := range ann {
					allchan <- p
				}
			}()
		}
	}
	// now loop-dump everything
	if !curses {
		tmpl, err := template.New("format").Parse(*format)
		if err != nil {
			log.Fatalf("Invalid template: %s", err)
		}
		for packet := range allchan {
			if packet.Error == nil {
				if err := tmpl.Execute(os.Stdout, packet); err != nil {
					log.Fatal(err)
				}
			}
		}
	} else {
		err := termui.Init()
		if err != nil {
			log.Panic(err)
		}
		defer termui.Close()

		streams := sap.CountStreams(allchan)
		defer streams.Close()

		// TODO: sort channels by number/name

		tbl := termui.NewTable()
		tbl.Separator = false
		tbl.Border = false
		tbl.Width = termui.TermWidth()
		tbl.Height = termui.TermHeight()
		termui.Handle("/timer/1s", func(termui.Event) {
			channels := streams.Read()
			displayed := [][]string{[]string{"Session", "Last Adv.", "Nb.", "Interval", "Group Address"}}
			for _, channel := range channels {
				if channel.Last.Add(channel.Interval*10).After(time.Now()) ||
					(channel.Count == 1 && channel.Last.Add(time.Minute*5).After(time.Now())) {
					displayed = append(displayed, []string{
						channel.Session,
						channel.Last.Format("15:04:05.000"),
						strconv.Itoa(channel.Count),
						(channel.Interval / timeResolution * timeResolution).String(),
						groupAddr(channel.Description),
					})
				}
			}
			tbl.SetRows(displayed)
			termui.Render(tbl)
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

func groupAddr(d sdp.Description) string {
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
