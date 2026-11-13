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
		{"testdata/valid-agent-version.yaml", nil, nil},
		{"testdata/error-agent-version-invalid.yaml", []Severity{SeverityError}, []string{"C6", `"0.3.307+"`, "not a valid semver constraint"}},
		{"testdata/valid-event-types.yaml", nil, nil},
		{"testdata/error-event-type-unknown.yaml", []Severity{SeverityError}, []string{"C7", `ruleExpression[1] has unknown eventType "Open"`}},
		{"testdata/error-event-type-missing.yaml", []Severity{SeverityError}, []string{"C7", `ruleExpression[0] has unknown eventType ""`}},
		{"testdata/error-duplicate-id.yaml", []Severity{SeverityError}, []string{"error-duplicate-id.yaml:5: R1000", "C8", "already declared at testdata/error-duplicate-id.yaml:3", "only one rule per ID"}},
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

func TestCheckAgentVersionRequirement(t *testing.T) {
	cases := []struct {
		requirement string
		wantError   bool
	}{
		{"", false},
		{">=0.3.307", false},
		{">= 0.3.307", false},
		{">=0.3.307, <0.4.0", false},
		{"~0.3", false},
		{"0.3.307+", true},
		{"latest", true},
		{" ", true},
	}
	for _, c := range cases {
		t.Run(c.requirement, func(t *testing.T) {
			findings := checkAgentVersionRequirement("rule.yaml", 1, "R0000", c.requirement)
			if !c.wantError {
				assert.Empty(t, findings)
				return
			}
			require.Len(t, findings, 1)
			assert.Equal(t, SeverityError, findings[0].Severity)
			assert.Equal(t, "C6", findings[0].Check)
		})
	}
}

func TestCheckEventTypes(t *testing.T) {
	for eventType := range ruleEventTypes {
		t.Run(eventType, func(t *testing.T) {
			assert.Empty(t, checkEventTypes("rule.yaml", 1, "R0000", []string{eventType}))
		})
	}
	for _, eventType := range []string{"", "Exec", "file", "all", " exec"} {
		t.Run("unknown "+eventType, func(t *testing.T) {
			findings := checkEventTypes("rule.yaml", 1, "R0000", []string{"exec", eventType})
			require.Len(t, findings, 1)
			assert.Equal(t, SeverityError, findings[0].Severity)
			assert.Equal(t, "C7", findings[0].Check)
			assert.Contains(t, findings[0].Message, "ruleExpression[1]")
		})
	}
}

func TestDuplicateIDsAcrossFiles(t *testing.T) {
	findings := lintFiles([]string{"testdata/valid-notrequired-no-decl.yaml", "testdata/valid-agent-version.yaml"})
	require.Len(t, findings, 1, "unexpected findings: %v", findings)
	assert.Equal(t, SeverityError, findings[0].Severity)
	assert.Equal(t, "C8", findings[0].Check)
	assert.Equal(t, "testdata/valid-agent-version.yaml", findings[0].File)
	assert.Equal(t, 3, findings[0].Line)
	assert.Contains(t, findings[0].Message, "testdata/valid-notrequired-no-decl.yaml:3")
}

func TestCheckDuplicateIDs(t *testing.T) {
	findings := checkDuplicateIDs([]ruleRef{
		{ID: "R0001", File: "a.yaml", Line: 3},
		{ID: "", File: "a.yaml", Line: 9},
		{ID: "R0002", File: "b.yaml", Line: 3},
		{ID: "", File: "b.yaml", Line: 9},
		{ID: "R0001", File: "c.yaml", Line: 3},
		{ID: "R0001", File: "d.yaml", Line: 3},
	})
	require.Len(t, findings, 2, "unexpected findings: %v", findings)
	for i, file := range []string{"c.yaml", "d.yaml"} {
		assert.Equal(t, file, findings[i].File)
		assert.Equal(t, "R0001", findings[i].RuleID)
		assert.Contains(t, findings[i].Message, "a.yaml:3")
	}
}
