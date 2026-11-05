// Full-stack prototype: everything odoo-doctor's binary must link.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	ts "github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"
	"github.com/spf13/cobra"
)

func main() {
	var url, pg string
	root := &cobra.Command{Use: "proto", RunE: func(*cobra.Command, []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		c := http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}}
		r, err := c.Get(url)
		if err != nil {
			return err
		}
		r.Body.Close()
		conn, err := pgx.Connect(ctx, pg)
		if err != nil {
			return err
		}
		defer conn.Close(ctx)
		var v string
		if err := conn.QueryRow(ctx, "select version()").Scan(&v); err != nil {
			return err
		}
		lang := grammars.PythonLanguage()
		tree, err := ts.NewParser(lang).Parse([]byte("def f():\n    return 1\n"))
		if err != nil {
			return err
		}
		out, _ := json.Marshal(map[string]any{"http": r.StatusCode, "pg": v[:15], "root": tree.RootNode().Type(lang)})
		t := template.Must(template.New("r").Parse("<pre>{{.}}</pre>\n"))
		return t.Execute(os.Stdout, string(out))
	}}
	root.Flags().StringVar(&url, "url", "", "")
	root.Flags().StringVar(&pg, "pg", "", "")
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
