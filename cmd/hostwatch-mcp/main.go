package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/sergii-ziborov/hostwatch-mcp/internal/bridge"
)

const usage = `Hostwatch MCP: connect an MCP client to your Hostwatch account.

Usage:
  hostwatch-mcp login [--write] [--no-browser]
  hostwatch-mcp serve
  hostwatch-mcp status
  hostwatch-mcp logout
  hostwatch-mcp version

Run login once, then configure your MCP client to run "hostwatch-mcp serve".
Login opens Hostwatch in your browser, where you can sign in directly or by QR.
Read access is the default. --write requests owner-approved write access.

Environment:
  HOSTWATCH_ORIGIN        Hostwatch HTTPS origin (default https://gethostwatch.com)
  HOSTWATCH_SESSION_FILE  Local OAuth session path (default user config directory)
`

func run(args []string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprint(os.Stdout, usage)
		return nil
	}
	client, err := bridge.NewClient(os.Getenv("HOSTWATCH_ORIGIN"), os.Getenv("HOSTWATCH_SESSION_FILE"))
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	switch args[0] {
	case "version":
		if len(args) != 1 {
			return errors.New("version takes no arguments")
		}
		fmt.Fprintln(os.Stdout, "hostwatch-mcp", bridge.Version)
		return nil
	case "login":
		flags := flag.NewFlagSet("login", flag.ContinueOnError)
		flags.SetOutput(os.Stderr)
		write := flags.Bool("write", false, "request owner-approved write access")
		noBrowser := flags.Bool("no-browser", false, "print authorization URL and accept pasted callback URL")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("login takes no positional arguments")
		}
		return client.Login(ctx, *write, *noBrowser, os.Stdin, os.Stdout)
	case "serve":
		if len(args) != 1 {
			return errors.New("serve takes no arguments")
		}
		return client.ServeStdio(ctx, os.Stdin, os.Stdout)
	case "status":
		if len(args) != 1 {
			return errors.New("status takes no arguments")
		}
		session, err := client.Load()
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "Connected to %s\nScopes: %s\n", session.Origin, session.Scope)
		if time.Now().After(session.ExpiresAt) {
			fmt.Fprintln(os.Stdout, "Access token expired; it will refresh on the next request.")
		} else {
			fmt.Fprintf(os.Stdout, "Access token expires: %s\n", session.ExpiresAt.Local().Format(time.RFC3339))
		}
		return nil
	case "logout":
		if len(args) != 1 {
			return errors.New("logout takes no arguments")
		}
		if err := client.Logout(ctx); err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, "Hostwatch connection revoked.")
		return nil
	default:
		return fmt.Errorf("unknown command %q; use --help", strings.TrimSpace(args[0]))
	}
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "hostwatch-mcp:", err)
		os.Exit(1)
	}
}
