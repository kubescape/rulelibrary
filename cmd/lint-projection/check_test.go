package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLintFile(t *testing.T) {
	cases := []struct {
		path           string
		wantSeverities []Severity
		wantSubstrs    []string
	}{
		{"testdata/valid-required.yaml", nil, nil},
		{"testdata/valid-optional-all.yaml", nil, nil},
		{"testdata/valid-notrequired-no-decl.yaml", nil, nil},
		{"testdata/error-required-missing.yaml", []Severity{SeverityError}, []string{"C1", "must be present"}},
		{"testdata/error-required-empty.yaml", []Severity{SeverityError}, []string{"C1", "at least one surface"}},
		{"testdata/error-bad-pattern-multikey.yaml", []Severity{SeverityError}, []string{"C2", "exactly one"}},
		{"testdata/error-field-empty.yaml", []Severity{SeverityError}, []string{"C2", "at least one pattern"}},
		{"testdata/warn-notrequired-with-decl.yaml", []Severity{SeverityWarn}, []string{"C4"}},
		{"testdata/error-bad-dependency-value.yaml", []Severity{SeverityError}, []string{"C5", "unrecognized profileDependency"}},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			findings := lintFile(c.path)
			require.Len(t, findings, len(c.wantSeverities), "unexpected finding count: %v", findings)
			for i, sev := range c.wantSeverities {
				assert.Equal(t, sev, findings[i].Severity)
			}
			joined := ""
			for _, f := range findings {
				joined += f.String() + "\n"
			}
			for _, s := range c.wantSubstrs {
				assert.True(t, strings.Contains(joined, s), "expected %q in output:\n%s", s, joined)
			}
		})
	}
}

func TestLintExitCode(t *testing.T) {
	findings := lintFiles([]string{"testdata/valid-required.yaml", "testdata/error-required-missing.yaml"})
	hasError := false
	for _, f := range findings {
		if f.Severity == SeverityError {
			hasError = true
		}
	}
	assert.True(t, hasError)
}
