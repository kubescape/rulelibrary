package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: lint-projection DIR [DIR ...]")
		os.Exit(2)
	}
	var files []string
	for _, dir := range os.Args[1:] {
		matches, err := walkYAMLs(dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "walk %s: %v\n", dir, err)
			os.Exit(2)
		}
		files = append(files, matches...)
	}
	findings := lintFiles(files)
	for _, f := range findings {
		fmt.Println(f.String())
	}
	for _, f := range findings {
		if f.Severity == SeverityError {
			os.Exit(1)
		}
	}
}

func walkYAMLs(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
			out = append(out, path)
		}
		return nil
	})
	return out, err
}
