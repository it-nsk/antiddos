package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	challengeService "github.com/it-nsk/antiddos/internal/challenge"
)

func challengeKeysCommand(args []string, out io.Writer, now time.Time) error {
	if len(args) == 0 || args[0] != "rotate" {
		return errors.New("usage: antiddos challenge-keys rotate [--file PATH] [--revoke-existing]")
	}
	credentialPath := "/etc/antiddos-challenge/keys.json"
	revokeExisting := false
	f := flag.NewFlagSet("challenge-keys rotate", flag.ContinueOnError)
	f.SetOutput(out)
	f.StringVar(&credentialPath, "file", credentialPath, "root-owned challenge credential file")
	f.BoolVar(&revokeExisting, "revoke-existing", false, "immediately invalidate all previously issued pass cookies")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", f.Args())
	}
	if err := challengeService.RotateCredentials(credentialPath, revokeExisting, now); err != nil {
		return err
	}
	mode := "one-hour grace for the previous cookie key"
	if revokeExisting {
		mode = "all previous cookie keys revoked"
	}
	_, err := fmt.Fprintf(out, "challenge keys rotated atomically (%s); restart antiddos-challenge.service to load them\n", mode)
	return err
}
