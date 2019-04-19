package main

import (
	"fmt"
	"log"
	"os"

	"github.com/dhoelle/cryptr/cli"
)

func main() {
	c, err := cli.New()
	must(err, "failed to create CLI")
	must(c.Run(os.Args), "failed to run")
}

// must wraps a given error with a message and prints it via
// log.Fatalf with the prefix "[FATAL]: "
func must(err error, f string, args ...interface{}) {
	if err != nil {
		log.Fatalf("[FATAL]: %v: %v", fmt.Sprintf(f, args...), err)
	}
}
