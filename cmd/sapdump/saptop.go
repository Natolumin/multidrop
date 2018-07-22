// +build curses

package main

import (
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/Natolumin/multidrop/sap"

	"github.com/LINBIT/termui"
	"github.com/emirpasic/gods/sets/treeset"
	godsutils "github.com/emirpasic/gods/utils"
	"github.com/pixelbender/go-sdp/sdp"
)

const timeResolution = time.Second

var filter = func(lf *sap.AdvLifetime) bool {
	return lf.Last.Add(lf.Interval*10).After(time.Now()) || (lf.Count == 1 && lf.Last.Add(time.Minute*2).After(time.Now()))
}

func init() {
	runTermui = runTermuiImpl
}

func runTermuiImpl(conn *sap.SDPConn) {
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
