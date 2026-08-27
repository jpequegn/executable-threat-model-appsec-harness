package main

import (
	"fmt"
	"os"

	"github.com/jpequegn/executable-threat-model-appsec-harness/internal/version"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Println(version.String())
		return
	}

	fmt.Fprintln(os.Stderr, "usage: appsec-harness version")
	os.Exit(2)
}
