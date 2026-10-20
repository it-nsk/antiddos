package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/it-nsk/antiddos/internal/webauth"
	"github.com/it-nsk/antiddos/internal/webcontrol"
	"github.com/it-nsk/antiddos/internal/webui"
	"golang.org/x/term"
)

func webCommand(ctx context.Context, args []string, logger *slog.Logger, out io.Writer) error {
	var o webui.Options
	flags := flag.NewFlagSet("web", flag.ContinueOnError)
	flags.SetOutput(out)
	flags.StringVar(&o.UsersDB, "users-db", webauth.DefaultPath, "web users and sessions SQLite database")
	flags.StringVar(&o.Listen, "listen", "127.0.0.1:8080", "loopback listen IP:port")
	flags.StringVar(&o.Origin, "origin", "http://127.0.0.1:8080", "exact browser origin (HTTPS for remote access)")
	flags.StringVar(&o.DaemonSocket, "daemon-socket", webcontrol.DefaultSocketPath, "restricted daemon API socket")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected web arguments")
	}
	return webui.Serve(ctx, o, logger)
}
func userCommand(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: antiddos user add|list|password|delete [--users-db PATH] [--role admin|viewer] [--password-stdin] USERNAME")
	}
	command := args[0]
	if command != "add" && command != "list" && command != "password" && command != "delete" {
		return fmt.Errorf("unknown user command")
	}
	var path, role string
	var stdin bool
	flags := flag.NewFlagSet("user "+command, flag.ContinueOnError)
	flags.SetOutput(out)
	flags.StringVar(&path, "users-db", webauth.DefaultPath, "web users database")
	if command == "add" {
		flags.StringVar(&role, "role", "viewer", "admin or viewer")
	}
	if command == "add" || command == "password" {
		flags.BoolVar(&stdin, "password-stdin", false, "read one password line from stdin")
	}
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if (command == "list" && flags.NArg() != 0) || (command != "list" && flags.NArg() != 1) {
		return fmt.Errorf("provide username after flags (except for list)")
	}
	var password string
	if command == "add" || command == "password" {
		if stdin {
			reader := bufio.NewReader(io.LimitReader(os.Stdin, 74))
			line, err := reader.ReadString('\n')
			if err != nil && err != io.EOF {
				return err
			}
			password = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		} else {
			if !term.IsTerminal(int(os.Stdin.Fd())) {
				return fmt.Errorf("use --password-stdin for non-interactive provisioning")
			}
			fmt.Fprint(out, "Password (12–72 bytes): ")
			value, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(out)
			if err != nil {
				return err
			}
			fmt.Fprint(out, "Confirm password: ")
			confirm, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(out)
			if err != nil {
				return err
			}
			if string(value) != string(confirm) {
				return fmt.Errorf("passwords do not match")
			}
			password = string(value)
		}
	}
	store, err := webauth.Open(path)
	if err != nil {
		return err
	}
	defer store.Close()
	switch command {
	case "add":
		err = store.Add(ctx, flags.Arg(0), password, role)
	case "password":
		err = store.Password(ctx, flags.Arg(0), password)
	case "delete":
		err = store.Delete(ctx, flags.Arg(0))
	case "list":
		users, e := store.Users(ctx)
		if e != nil {
			return e
		}
		for _, u := range users {
			fmt.Fprintf(out, "%s\t%s\n", u.Username, u.Role)
		}
		return nil
	}
	if err == nil {
		_, err = fmt.Fprintln(out, "User updated.")
	}
	return err
}
