package main

import (
	"flag"
	"os"

	"skybert.net/goliath/iam"
)

var serverPort int
var showHelp bool
var usePKCE bool

func init() {
	flag.IntVar(&serverPort, "port", 8000, "Port to listen to")
	flag.BoolVar(&showHelp, "help", false, "Don't panic")
	flag.BoolVar(&usePKCE, "pkce", false, "Use PKCE instead of client secret")
}

func main() {
	flag.Parse()
	if showHelp {
		flag.PrintDefaults()
		os.Exit(0)
	}
	iam.Run(iam.GoliathCLIArgs{
		PKCE:       usePKCE,
		ServerPort: serverPort,
	})
}
