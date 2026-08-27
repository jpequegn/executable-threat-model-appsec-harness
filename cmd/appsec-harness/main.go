package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/jpequegn/executable-threat-model-appsec-harness/internal/contracts"
	"github.com/jpequegn/executable-threat-model-appsec-harness/internal/lifecycle"
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
	if len(os.Args) >= 3 && os.Args[1] == "trial" {
		if err := runTrial(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
	}

	fmt.Fprintln(os.Stderr, "usage: appsec-harness version | threat-model ... | trial <init|step|status> ...")
	os.Exit(2)
}

func runTrial(args []string) error {
	command := args[0]
	flags := flag.NewFlagSet("trial "+command, flag.ContinueOnError)
	root := flags.String("root", "runs", "trial root directory")
	manifestPath := flags.String("manifest", "", "manifest JSON path")
	trialID := flags.String("trial", "", "trial identifier")
	requestPath := flags.String("request", "", "step request JSON path")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	engine := lifecycle.NewEngine(*root)
	switch command {
	case "init":
		var manifest lifecycle.Manifest
		if err := loadStrictJSON(*manifestPath, &manifest); err != nil {
			return err
		}
		snapshot, err := engine.Initialize(manifest)
		if err != nil {
			return err
		}
		return printJSON(snapshot)
	case "step":
		var request lifecycle.StepRequest
		if err := loadStrictJSON(*requestPath, &request); err != nil {
			return err
		}
		receipt, err := engine.Execute(*trialID, request)
		if err != nil {
			return err
		}
		return printJSON(receipt)
	case "status":
		snapshot, err := engine.Load(*trialID)
		if err != nil {
			return err
		}
		return printJSON(snapshot)
	default:
		return fmt.Errorf("unknown trial command %q", command)
	}
}

func loadStrictJSON(path string, target any) error {
	if path == "" {
		return fmt.Errorf("JSON path is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("trailing JSON value")
	}
	return nil
}

func printJSON(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
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
