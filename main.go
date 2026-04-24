package main

import (
	"flag"
	"fmt"
	"log"

	tea "charm.land/bubbletea/v2"
)

const version = "0.1.0"

func main() {
	var showVersion bool
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.BoolVar(&showVersion, "v", false, "print version and exit (shorthand)")
	flag.Parse()

	if showVersion {
		fmt.Println(version)
		return
	}

	m := newModel()
	p := tea.NewProgram(m)
	if _, err := p.Run(); err != nil {
		log.Fatalf("Unexpected error: %v", err)
	}
}
