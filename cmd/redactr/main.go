package main

import (
	"fmt"
	"log"
	"os"

	"github.com/dhoelle/redactr"
	"github.com/dhoelle/redactr/cli"
)

var (
	commit  = "none"
	date    = "unknown"
	version = "dev"
)

func main() {
	tool, err := redactr.New(
		redactr.AESKey(os.Getenv("AES_KEY")),
	)
	must(err, "failed to create redactr tool")

	c, err := cli.New(
		tool,
		tool,
		cli.Commit(commit),
		cli.Date(date),
		cli.Version(version),
	)
	must(err, "failed to create CLI")
	must(c.Run(os.Args), "redactr failed")
}

// must wraps a given error with a message and prints it via
// log.Fatalf with the prefix "[FATAL]: "
func must(err error, f string, args ...interface{}) {
	if err != nil {
		log.Fatalf("[FATAL]: %v: %v", fmt.Sprintf(f, args...), err)
	}
}
