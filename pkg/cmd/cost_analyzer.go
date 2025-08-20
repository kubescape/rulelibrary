package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker"
	"github.com/google/cel-go/ext"
	"github.com/goradd/maps"
	"gopkg.in/yaml.v3"

	// Mock dependencies for library initialization
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/objectcache"
	objectcachev1 "github.com/kubescape/node-agent/pkg/objectcache/v1"

	// Import the actual agent libraries
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/applicationprofile"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/k8s"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/net"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/networkneighborhood"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/parse"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/process"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
)

// =====================================================================================
// 1. YAML Parsing Structs
// =====================================================================================

type Rules struct {
	Spec typesv1.RulesSpec `yaml:"spec"`
}

// =====================================================================================
// 2. Composite Cost Estimator
// This combines all individual library estimators into one.
// =====================================================================================

type CompositeCostEstimator struct {
	estimators []checker.CostEstimator
}

func NewCompositeCostEstimator(estimators ...checker.CostEstimator) checker.CostEstimator {
	var nonNilEstimators []checker.CostEstimator
	for _, e := range estimators {
		if e != nil {
			nonNilEstimators = append(nonNilEstimators, e)
		}
	}
	return &CompositeCostEstimator{estimators: nonNilEstimators}
}

func (c *CompositeCostEstimator) EstimateCallCost(function, overloadID string, target *checker.AstNode, args []checker.AstNode) *checker.CallEstimate {
	for _, e := range c.estimators {
		if estimate := e.EstimateCallCost(function, overloadID, target, args); estimate != nil {
			return estimate
		}
	}
	return nil
}

func (c *CompositeCostEstimator) EstimateSize(element checker.AstNode) *checker.SizeEstimate {
	for _, e := range c.estimators {
		if estimate := e.EstimateSize(element); estimate != nil {
			return estimate
		}
	}
	return nil
}

// =====================================================================================
// 3. Main Application Logic
// =====================================================================================

// createAnalyzerEnvAndEstimator initializes a CEL environment using the real agent libraries
// and constructs a composite cost estimator from them.
func createAnalyzerEnvAndEstimator() (*cel.Env, checker.CostEstimator, error) {
	// Create mock dependencies required by the library constructors
	objCache := &objectcachev1.RuleObjectCacheMock{
		ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
	}
	cfg := config.Config{}

	// Instantiate all of the agent's real libraries
	allLibraries := []libraries.Library{
		applicationprofile.New(objCache, cfg),
		k8s.New(objCache.K8sObjectCache(), cfg),
		networkneighborhood.New(objCache, cfg),
		parse.New(cfg),
		net.New(cfg),
		process.New(cfg),
	}

	var envOptions []cel.EnvOption
	var costEstimators []checker.CostEstimator

	// Collect EnvOptions and CostEstimators from each library
	for _, lib := range allLibraries {
		envOptions = append(envOptions, cel.Lib(lib))
		if estimator := lib.CostEstimator(); estimator != nil {
			costEstimators = append(costEstimators, estimator)
		}
	}

	compositeEstimator := NewCompositeCostEstimator(costEstimators...)

	// Add standard variables and extensions
	envOptions = append(envOptions,
		cel.Variable("event", cel.AnyType),
		ext.Strings(),
	)

	env, err := cel.NewEnv(envOptions...)
	return env, compositeEstimator, err
}

func main() {
	rulesPath := "pkg/rules"
	if len(os.Args) > 1 {
		rulesPath = os.Args[1]
	}

	fmt.Printf("Analyzing CEL rule costs in: %s\n", rulesPath)
	fmt.Println("--------------------------------------------------")

	// Create the fully-featured CEL Environment and the estimator
	env, estimator, err := createAnalyzerEnvAndEstimator()
	if err != nil {
		log.Fatalf("Failed to create CEL environment: %v", err)
	}

	// Walk the directory to find all rule files.
	err = filepath.Walk(rulesPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && (strings.HasSuffix(info.Name(), ".yaml") || strings.HasSuffix(info.Name(), ".yml")) {
			processRuleFile(path, env, estimator)
		}
		return nil
	})

	if err != nil {
		log.Fatalf("Error walking the path %q: %v\n", rulesPath, err)
	}
}

// processRuleFile reads a YAML file, extracts the CEL expression, and estimates its cost.
func processRuleFile(filePath string, env *cel.Env, estimator checker.CostEstimator) {
	yamlFile, err := os.ReadFile(filePath)
	if err != nil {
		log.Printf("WARN: Failed to read file %s: %v", filePath, err)
		return
	}

	var rules Rules
	err = yaml.Unmarshal(yamlFile, &rules)
	if err != nil {
		log.Printf("WARN: Failed to unmarshal YAML for %s: %v", filePath, err)
		return
	}

	if len(rules.Spec.Rules) == 0 {
		return // Not a rule file, skip silently.
	}

	rule := rules.Spec.Rules[0]
	if len(rule.Expressions.RuleExpression) == 0 {
		fmt.Printf("Rule: %s\n", rule.Name)
		fmt.Printf("  Path: %s\n", filePath)
		fmt.Printf("  Cost: [No rule_expression found]\n\n")
		return
	}

	expression := rule.Expressions.RuleExpression[0].Expression

	// Compile the expression to get an AST.
	ast, issues := env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		fmt.Printf("Rule: %s\n", rule.Name)
		fmt.Printf("  Path: %s\n", filePath)
		fmt.Printf("  ERROR compiling expression: %v\n\n", issues.Err())
		return
	}

	// Estimate the cost of the compiled AST using our composite estimator.
	cost, err := env.EstimateCost(ast, estimator)
	if err != nil {
		fmt.Printf("Rule: %s\n", rule.Name)
		fmt.Printf("  Path: %s\n", filePath)
		fmt.Printf("  ERROR estimating cost: %v\n\n", err)
		return
	}

	// Print the final result.
	fmt.Printf("Rule: %s\n", rule.Name)
	fmt.Printf("  Path: %s\n", filePath)
	fmt.Printf("  Cost: [Min: %d, Max: %d]\n\n", cost.Min, cost.Max)
}
