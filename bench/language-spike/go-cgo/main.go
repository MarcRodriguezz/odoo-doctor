// Language spike: same detection rules as ../python/scan.py, on a pure Go
// tree-sitter parser. Usage: spike <dir> [--workers N] [--details out.txt]
package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"

	tspy "github.com/tree-sitter/tree-sitter-python/bindings/go"
	ts "github.com/tree-sitter/go-tree-sitter"
)

type result struct {
	sudo, sql, public []int
	err               int
}

type scanner struct {
	src  []byte
	res  *result
}

func (s *scanner) typ(n *ts.Node) string { return n.Kind() }

func (s *scanner) field(n *ts.Node, name string) *ts.Node { return n.ChildByFieldName(name) }

func (s *scanner) unwrap(n *ts.Node) *ts.Node {
	for n != nil && s.typ(n) == "parenthesized_expression" && n.NamedChildCount() == 1 {
		n = n.NamedChild(0)
	}
	return n
}

func (s *scanner) hasInterpolation(n *ts.Node) bool {
	for i := uint(0); i < n.NamedChildCount(); i++ {
		c := n.NamedChild(i)
		switch s.typ(c) {
		case "interpolation":
			return true
		case "string", "concatenated_string":
			if s.hasInterpolation(c) {
				return true
			}
		}
	}
	return false
}

func (s *scanner) isCursor(n *ts.Node) bool {
	n = s.unwrap(n)
	if n == nil {
		return false
	}
	name := ""
	switch s.typ(n) {
	case "identifier":
		name = n.Utf8Text(s.src)
	case "attribute":
		if a := s.field(n, "attribute"); a != nil {
			name = a.Utf8Text(s.src)
		}
	}
	return name == "cr" || name == "_cr" || name == "cursor"
}

func (s *scanner) isDynamicSQL(n *ts.Node) bool {
	n = s.unwrap(n)
	if n == nil {
		return false
	}
	switch s.typ(n) {
	case "string", "concatenated_string":
		return s.hasInterpolation(n)
	case "binary_operator":
		if op := s.field(n, "operator"); op != nil {
			t := s.typ(op)
			return t == "%" || t == "+"
		}
	case "call":
		if f := s.unwrap(s.field(n, "function")); f != nil && s.typ(f) == "attribute" {
			if a := s.field(f, "attribute"); a != nil {
				return a.Utf8Text(s.src) == "format"
			}
		}
	}
	return false
}

func firstPositional(args *ts.Node, s *scanner) *ts.Node {
	for i := uint(0); i < args.NamedChildCount(); i++ {
		c := args.NamedChild(i)
		switch s.typ(c) {
		case "comment":
			continue
		case "keyword_argument", "dictionary_splat", "list_splat":
			if s.typ(c) == "keyword_argument" {
				continue
			}
			return nil
		default:
			return c
		}
	}
	return nil
}

func (s *scanner) visitCall(n *ts.Node) {
	f := s.unwrap(s.field(n, "function"))
	if f == nil || s.typ(f) != "attribute" {
		return
	}
	attr := s.field(f, "attribute")
	if attr == nil {
		return
	}
	switch attr.Utf8Text(s.src) {
	case "sudo":
		s.res.sudo = append(s.res.sudo, int(attr.EndPosition().Row)+1)
	case "execute":
		args := s.field(n, "arguments")
		if args == nil || s.typ(args) != "argument_list" || !s.isCursor(s.field(f, "object")) {
			return
		}
		if first := firstPositional(args, s); first != nil && s.isDynamicSQL(first) {
			s.res.sql = append(s.res.sql, int(n.StartPosition().Row)+1)
		}
	}
}

func (s *scanner) visitDecorated(n *ts.Node) {
	def := s.field(n, "definition")
	if def == nil || s.typ(def) != "function_definition" {
		return
	}
	for i := uint(0); i < n.NamedChildCount(); i++ {
		dec := n.NamedChild(i)
		if s.typ(dec) != "decorator" || dec.NamedChildCount() == 0 {
			continue
		}
		call := dec.NamedChild(0)
		if s.typ(call) != "call" {
			continue
		}
		f := s.field(call, "function")
		if f == nil || s.typ(f) != "attribute" {
			continue
		}
		if a := s.field(f, "attribute"); a == nil || a.Utf8Text(s.src) != "route" {
			continue
		}
		args := s.field(call, "arguments")
		if args == nil {
			continue
		}
		for j := uint(0); j < args.NamedChildCount(); j++ {
			kw := args.NamedChild(j)
			if s.typ(kw) != "keyword_argument" {
				continue
			}
			if nm := s.field(kw, "name"); nm == nil || nm.Utf8Text(s.src) != "auth" {
				continue
			}
			if v := s.field(kw, "value"); v != nil && s.typ(v) == "string" && strings.Trim(v.Utf8Text(s.src), `'"`) == "public" {
				s.res.public = append(s.res.public, int(dec.StartPosition().Row)+1)
			}
		}
	}
}

func scanFile(p *ts.Parser, path string) result {
	var r result
	src, err := os.ReadFile(path)
	if err != nil {
		r.err = 1
		return r
	}
	tree := p.Parse(src, nil)
	if tree == nil {
		r.err = 1
		return r
	}
	defer tree.Close()
	root := tree.RootNode()
	if root.HasError() {
		r.err = 1
	}
	s := &scanner{src: src, res: &r}
	stack := []*ts.Node{root}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		switch s.typ(n) {
		case "call":
			s.visitCall(n)
		case "decorated_definition":
			s.visitDecorated(n)
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			stack = append(stack, n.NamedChild(i))
		}
	}
	return r
}

func main() {
	root := os.Args[1]
	workers, details := runtime.NumCPU(), ""
	for i := 2; i < len(os.Args)-1; i++ {
		switch os.Args[i] {
		case "--workers":
			workers, _ = strconv.Atoi(os.Args[i+1])
		case "--details":
			details = os.Args[i+1]
		}
	}
	var files []string
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".py") {
			files = append(files, p)
		}
		return nil
	})
	sort.Strings(files)
	lang := ts.NewLanguage(tspy.Language())
	results := make([]result, len(files))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := ts.NewParser()
			defer p.Close()
			_ = p.SetLanguage(lang)
			for i := range jobs {
				results[i] = scanFile(p, files[i])
			}
		}()
	}
	for i := range files {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	totals := map[string]int{"files": len(files)}
	var lines []string
	for i, r := range results {
		rel, _ := filepath.Rel(root, files[i])
		totals["err"] += r.err
		for kind, ls := range map[string][]int{"sudo": r.sudo, "sql": r.sql, "public": r.public} {
			totals[kind] += len(ls)
			for _, l := range ls {
				lines = append(lines, fmt.Sprintf("%s %s:%d", kind, rel, l))
			}
		}
	}
	if details != "" {
		sort.Strings(lines)
		_ = os.WriteFile(details, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
	}
	out, _ := json.Marshal(totals)
	fmt.Println(string(out))
}
