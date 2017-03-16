package main

import (
	"flag"
	"log"
	"net"
	"os"
	"strings"
	"text/template"

	"github.com/Natolumin/multidrop/sap"
)

const defFormat = `{{.Description}}
`

func main() {

	group := flag.String("group", "", "Comma-separated Group(s) on which to listen for SAP announcements.")
	v6only := flag.Bool("6", false, "Only listen on ipv6 groups (overriden by -group)")
	v4only := flag.Bool("4", false, "Only listen on ipv4 groups (overriden by -group)")
	format := flag.String("format", defFormat, "Format string following text/template for dumping SAP announcements")

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
			ann6, err := sap.DefaultParamsv6.ListenSAP()
			if err != nil {
				log.Fatal(err)
			}
			go func() {
				for p := range ann6 {
					allchan <- p
				}
			}()

		} else if !*v6only {
			ann4, err := sap.DefaultParamsv4.ListenSAP()
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
			ann, err := param.ListenSAP()
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
	for packet := range allchan {
		tmpl.Execute(os.Stdout, packet)
	}
}
