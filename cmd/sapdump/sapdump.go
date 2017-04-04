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

package main

import (
	"flag"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/Natolumin/multidrop/sap"

	"github.com/LINBIT/termui"
)

const defFormat = `{{.Description}}
`

func main() {

	group := flag.String("group", "", "Comma-separated Group(s) on which to listen for SAP announcements.")
	v6only := flag.Bool("6", false, "Only listen on ipv6 groups (overriden by -group)")
	v4only := flag.Bool("4", false, "Only listen on ipv4 groups (overriden by -group)")
	format := flag.String("format", defFormat, "Format string following text/template for dumping SAP announcements")
	curses := flag.Bool("curses", false, "Display continuous stats instead of dumping incoming announcements")

	flag.Parse()

	if *v6only && *v4only {
		log.Fatal("Incompatible flags -4 and -6")
	}
	tmpl, err := template.New("format").Parse(*format)
	if err != nil {
		log.Fatalf("Invalid template: %s", err)
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
	if !*curses {
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

		tbl := termui.NewTable()
		tbl.Width = termui.TermWidth()
		tbl.Height = termui.TermHeight()
		termui.Handle("/timer/1s", func(termui.Event) {
			channels := streams.Read()
			displayed := [][]string{[]string{"Session name", "Last Advertisement", "Nb. Adv.", "Adv Interval"}}
			for _, channel := range channels {
				if channel.Last.Add(channel.Interval*10).After(time.Now()) ||
					(channel.Count == 1 && channel.Last.Add(time.Minute*5).After(time.Now())) {
					displayed = append(displayed, []string{channel.Session, channel.Last.String(), strconv.Itoa(channel.Count), channel.Interval.String()})
				}
			}
			tbl.SetRows(displayed)
			termui.Render(tbl)
		})
		termui.Handle("/sys/kbd/q", func(termui.Event) {
			termui.StopLoop()
		})
		termui.Handle("/sys/wnd/resize", func(termui.Event) {
			tbl.Width = termui.TermWidth()
			tbl.Height = termui.TermHeight()
		})
		termui.Loop()
	}
}
