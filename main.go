package main

import (
	"github.com/OpenWayz/XrayR/cmd"
	log "github.com/sirupsen/logrus"
)

func main() {
	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
