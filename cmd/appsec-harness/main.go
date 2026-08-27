package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/jpequegn/executable-threat-model-appsec-harness/internal/contracts"
	"github.com/jpequegn/executable-threat-model-appsec-harness/internal/version"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Println(version.String())
		return
	}
	if len(os.Args) >= 4 && os.Args[1] == "threat-model" {
		if err := runThreatModel(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
	}

	fmt.Fprintln(os.Stderr, "usage: appsec-harness version | threat-model <lint|digest|diff> <path> [other-path]")
	os.Exit(2)
}

func runThreatModel(args []string) error {
	model, err := contracts.LoadThreatModel(args[1])
	if err != nil {
		return err
	}
	switch args[0] {
	case "lint":
		fmt.Printf("valid threat model %s version %s\n", model.ID, model.Version)
		return nil
	case "digest":
		digest, err := contracts.Digest(model)
		if err != nil {
			return err
		}
		fmt.Println(digest)
		return nil
	case "diff":
		if len(args) != 3 {
			return fmt.Errorf("diff requires before and after paths")
		}
		after, err := contracts.LoadThreatModel(args[2])
		if err != nil {
			return err
		}
		output, err := json.MarshalIndent(contracts.DiffThreatModels(model, after), "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(output))
		return nil
	default:
		return fmt.Errorf("unknown threat-model command %q", args[0])
	}
}
