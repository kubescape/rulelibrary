package r0005unexpecteddomainrequest

import (
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kubescape/rulelibrary/pkg/common"
	"github.com/stretchr/testify/require"
	"testing"
)

// The rule delegates baseline matching to the agent. Mock that boundary here;
// learning, profile readiness and persistence are integration-tested in node-agent.
func TestR0005DNSBaseline(t *testing.T) {
	rule, err := common.LoadRuleFromYAML("unexpected-domain-request.yaml")
	require.NoError(t, err)
	require.EqualValues(t, 0, rule.Rules[0].ProfileDependency)
	for _, tc := range []struct {
		name, domain, qr, rcode           string
		answers                           int64
		known, unavailable, want, wantErr bool
	}{
		{name: "learned DNS only", domain: "example.com.", qr: "R", rcode: "Success", answers: 1, known: true},
		{name: "learned cluster name", domain: "db.default.svc.cluster.local.", qr: "R", rcode: "Success", answers: 1, known: true},
		{name: "unlearned cluster name", domain: "new.default.svc.cluster.local.", qr: "R", rcode: "Success", answers: 1, want: true},
		{name: "new name", domain: "new.example.com.", qr: "R", rcode: "Success", answers: 1, want: true},
		{name: "connection does not teach DNS", domain: "connection-only.example.", qr: "R", rcode: "Success", answers: 1, want: true},
		{name: "unavailable baseline", domain: "new.example.com.", qr: "R", rcode: "Success", answers: 1, unavailable: true, wantErr: true},
		{name: "query", domain: "new.example.com.", qr: "Q"},
		{name: "NXDOMAIN", domain: "new.example.com.", qr: "R", rcode: "NameError"},
		{name: "empty answer", domain: "new.example.com.", qr: "R", rcode: "Success"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			env, err := cel.NewEnv(cel.Variable("event", cel.MapType(cel.StringType, cel.DynType)), cel.Function("cp.was_dns_resolved", cel.Overload("test_dns_baseline", []*cel.Type{cel.StringType, cel.StringType}, cel.BoolType, cel.BinaryBinding(func(id, name ref.Val) ref.Val {
				calls++
				require.Equal(t, "container", id.Value())
				require.Equal(t, tc.domain, name.Value())
				if tc.unavailable {
					return types.NewErr("profile not available")
				}
				return types.Bool(tc.known)
			}))))
			require.NoError(t, err)
			ast, issues := env.Compile(rule.Rules[0].Expressions.RuleExpression[0].Expression)
			require.NoError(t, issues.Err())
			program, err := env.Program(ast)
			require.NoError(t, err)
			result, _, err := program.Eval(map[string]any{"event": map[string]any{"containerId": "container", "name": tc.domain, "qr": tc.qr, "numAnswers": tc.answers, "rcode": tc.rcode}})
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, result.Value())
			if tc.qr != "R" || tc.answers == 0 || tc.rcode != "Success" {
				require.Zero(t, calls)
			} else {
				require.Equal(t, 1, calls)
			}
		})
	}
}
