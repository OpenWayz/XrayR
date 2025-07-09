package main

import (
	"github.com/OpenWayz/XrayR/cmd"
	log "github.com/sirupsen/logrus"
)

// Main is the main entry point for XrayR.
// It runs the cobra command line interface and handles the error.
func main() {
	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
