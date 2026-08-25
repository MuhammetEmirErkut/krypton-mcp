package main

import (
	"os"

	"github.com/krypton-mcp/krypton/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
