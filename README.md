# Kubescape Rule Library

Kubescape's CEL (Common Expression Language) runtime threat detection rules library. This repository contains a collection of security rules that can be used for runtime threat detection in Kubernetes environments.

## Overview

The rule library provides a structured way to define security rules using YAML format. Each rule is defined as a Custom Resource Definition (CRD) instance that can be deployed to Kubernetes clusters for runtime threat detection.

## Rule Format

Each rule is defined in a YAML file with the following structure:

```yaml
apiVersion: kubescape.io/v1
kind: Rules
metadata:
  name: rule-name-rule
  namespace: kubescape
  labels:
    app: kubescape
spec:
  rules:
    - name: "Rule Display Name"
      enabled: true
      id: "R####"
      description: "Description of what the rule detects"
      expressions:
        message: "CEL expression for alert message"
        uniqueId: "CEL expression for unique identifier"
        ruleExpression:
          - eventType: "eventType_name"
            expression: "CEL expression for detection logic"
      profileDependency: 0  # 0=Required, 1=Optional, 2=NotRequired
      severity: 1
      supportPolicy: false
      tags:
        - "tag1"
        - "tag2"
```

### Rule Fields

| Field | Type | Description | Required |
|-------|------|-------------|----------|
| `name` | string | Human-readable rule name | Yes |
| `enabled` | boolean | Whether the rule is active | Yes |
| `id` | string | Unique rule identifier (format: R####) | Yes |
| `description` | string | Detailed description of the rule | Yes |
| `expressions.message` | string | CEL expression for alert message | Yes |
| `expressions.uniqueId` | string | CEL expression for unique event ID | Yes |
| `expressions.ruleExpression` | array | Array of detection expressions | Yes |
| `profileDependency` | integer | Profile dependency level (0,1,2) | Yes |
| `profileDataRequired` | object | Profile surfaces the expressions query (see [Declaring `profileDataRequired`](#declaring-profiledatarequired)) | When `profileDependency` is 0 or 1 |
| `severity` | integer | Rule severity level | Yes |
| `supportPolicy` | boolean | Whether rule supported by rule policy | Yes |
| `isTriggerAlert` | boolean | Copied onto every alert the rule raises so the backend can tell triggering alerts from informational ones. R0003, R0005 and R0007, for example, set it to `false` | No |
| `mitreTactic` | string | MITRE ATT&CK tactic ID, for example `TA0002` | No |
| `mitreTechnique` | string | MITRE ATT&CK technique ID, for example `T1059` | No |
| `tags` | array | Array of tags for categorization | Yes |
| `state` | object | Default pre-filter parameters (see [Pre-filter parameters](#pre-filter-parameters-state)) | No |
| `agentVersionRequirement` | string | Semver constraint on the node-agent version, for example `">=0.3.307"` (see [Agent version requirement](#agent-version-requirement)) | No |

### Context Tags

The `tags` list includes machine-readable `context:*` labels that help agents decide where a rule should run. Context tags are additive, not exclusive, so a single rule may carry more than one when the behavior is meaningful in multiple environments.

| Context tag | Meaning |
|-------------|---------|
| `context:host` | The behavior is meaningful from the host's point of view, such as host processes or host-mounted resources. |
| `context:container` | The behavior is meaningful at the container boundary regardless of orchestrator. Use this for rules that should run for Kubernetes, ECS, or standalone container agents. |
| `context:kubernetes` | The rule is valid in Kubernetes deployments. Keep this tag on container rules for backward compatibility with older agents, and use it by itself for Kubernetes-specific signals such as `kubectl exec`, `port-forward`, or service-account behavior. |

Examples:

- R0010 carries `context:host` and `context:container` because `/etc/shadow` access can be meaningful from a host workload or from a container that can see that file.
- R2000 and R2001 remain Kubernetes-only because they are driven by Kubernetes API activity, not generic container behavior.

The `Platforms` row in each rule README is human-facing documentation. The `context:*` tags are routing metadata, so they often overlap but are not interchangeable.

### Supported Event Types

- `exec` - Process execution events
- `open` - File access events
- `capabilities` - Linux capability events
- `dns` - DNS query events
- `network` - Network connection events
- `syscall` - System call events
- `randomx` - XMRig mining events
- `symlink` - Symbolic link events
- `hardlink` - Hard link events
- `ssh` - SSH connection events
- `http` - HTTP request events
- `ptrace` - Process tracing events
- `iouring` - IO_uring events
- `fork` - Process fork events
- `exit` - Process exit events
- `procfs` - Proc filesystem events
- `bpf` - `bpf()` system call events
- `kmod` - Kernel module load events
- `unshare` - `unshare()` system call events
- `k8s-admission` - Kubernetes API requests seen by the Kubescape operator's admission webhook, not by the node-agent (see [Testing `k8s-admission` rules](docs/testing-admission-rules.md))

### Pre-filter parameters (`state`)

The node-agent reads a small set of keys from `state` and uses them to skip events before any
CEL expression runs, which is much cheaper than rejecting them in CEL. Unknown keys are ignored
by the pre-filter.

| Key | Applies to | An event is skipped when |
|-----|-----------|--------------------------|
| `includePrefixes` | `open` (`event.path`), `exec` (`event.exepath`) | the path is not equal to, or under, any listed prefix |
| `ignorePrefixes` | `open` (`event.path`), `exec` (`event.exepath`) | the path is equal to, or under, a listed prefix |
| `ports` | `network`, `ssh` | the destination port is not in the list |
| `direction` | `http` | the request direction differs from the given `inbound` or `outbound` |
| `methods` | `http` | the request method is not in the list, for example `["GET", "POST"]` |
| `excludeProcesses` | `exec` | a `{name, path}` entry matches the process `comm` (truncated to 15 characters by the kernel) and `exepath` |
| `excludeParentProcesses` | `exec` | a `{name, path}` entry matches the parent's `pcomm` and executable path |

Prefixes are compared by path component, so `/proc` matches `/proc/1/environ` but not
`/process`, and trailing slashes are ignored. A rule binding can set the same keys as
parameters, and a binding value replaces the rule's default for that key. For example R1009:

```yaml
      state:
        ports:
          - 3333
          - 45700
```

The pre-filter only narrows which events reach CEL. It lets an event through when the field
is empty, and a binding can replace the defaults, so keep the full condition in the
`ruleExpression` as well. R1009 still checks `event.dstPort in [3333, 45700]`. The CEL
tests in `rule_test.go` evaluate expressions without the pre-filter.

### Agent version requirement

Set `agentVersionRequirement` when an expression uses an event field or CEL function that
older node-agents do not have. The node-agent compares the constraint with its `AGENT_VERSION`
environment variable using semantic versioning and does not load the rule if the version does
not satisfy it, instead of failing to compile the expression. When `AGENT_VERSION` is not set,
the rule is loaded. R1000 uses `">=0.3.307"` because `event.file` was added in that release.

## Writing Rules

### 1. Create Rule Directory

Create a new directory in `pkg/rules/` with the naming convention:
```
r####-descriptive-name/
```

Example:
```
pkg/rules/r0001-unexpected-process-launched/
```

### 2. Create Rule YAML File

Create a YAML file in your rule directory with the rule definition (see example [unexpected-process-launched.yaml](pkg/rules/r0001-unexpected-process-launched/unexpected-process-launched.yaml))

### 3. Add Test Cases

Create a `rule_test.go` file in your rule directory (see example [rule_test.go](pkg/rules/r0001-unexpected-process-launched/rule_test.go))

### 4. Test Your Rule

Run the tests to ensure your rule works correctly:

```bash
go test -v ./pkg/rules/r0001-unexpected-process-launched/
```

## Rule Generation Script

The `gen.sh` script automatically combines all individual rule YAML files into a single CRD instance. The
recommended entrypoint is the Make target below, which wraps the script.

### Usage

```bash
make generate-rules-crd
```

### What it does

1. **Scans** the `pkg/rules/` directory for all YAML files
2. **Combines** all individual rule definitions into a single Rule instance
3. **Generates** `rules-crd.yaml` with all rules in the spec array
4. **Validates** the generated YAML (if `yq` is available)

### Output

The script generates `rules-crd.yaml` containing:

```yaml
apiVersion: kubescape.io/v1
kind: Rules
metadata:
  name: kubescape-rules
  namespace: kubescape
  labels:
    app: kubescape
spec:
  rules:
    - name: "Rule 1"
      # ... rule 1 definition
    - name: "Rule 2"
      # ... rule 2 definition
    # ... all other rules
```

### Prerequisites

- `bash` shell
- `yq` (optional, for YAML validation)

## Development Workflow

1. **Create a new rule** following the directory structure and naming conventions
2. **Write the rule YAML** with proper CEL expressions
3. **Add comprehensive tests** in `rule_test.go`
4. **Test your rule** with `go test -v ./pkg/rules/your-rule/`
5. **Generate the combined CRD** with `make generate-rules-crd`
6. **Deploy** the generated `rules-crd.yaml` to your Kubernetes cluster

## Testing

### Run all tests
```bash
go test -v ./pkg/rules/...
```

### Run specific rule tests
```bash
go test -v ./pkg/rules/r0001-unexpected-process-launched/
```

### Test the generation script
```bash
make generate-rules-crd
# Check the generated rules-crd.yaml file
```

## CEL Expressions

Rules use Common Expression Language (CEL) for expressions. Event fields are read from the
`event` variable by their node-agent names, which start with a lower-case letter: `event.comm`,
`event.pid`, `event.exepath`, `event.args`, `event.containerId`. `k8s-admission` rules are the
exception: they use the operator's names, such as `event.Kind` and `event.UserInfo.Username`.
When a rule has expressions for more than one event type, the `eventType` variable holds the
type of the current event. Key concepts, using R0001's expressions as the example:

### Message Expression
Defines the alert message format:
```cel
'Unexpected process launched: ' + event.comm + ' with PID ' + string(event.pid)
```

### Unique ID Expression
Creates a unique identifier for deduplication:
```cel
event.comm + '_' + event.exepath
```

### Rule Expression
Defines the detection logic. Profile lookups go through helper functions such as
`ap.was_executed`, and the profile surfaces they query must be declared in
`profileDataRequired`:
```cel
!ap.was_executed(event.containerId, (event.exepath != "" ? event.exepath : parse.get_exec_path(event.args, event.comm)))
```

See [`docs/writing-optimized-cel.md`](docs/writing-optimized-cel.md) for how to keep
expressions cheap.

## Best Practices

1. **Use descriptive names** for rules and directories
2. **Follow the ID numbering convention** (R####)
3. **Write comprehensive tests** for each rule
4. **Use appropriate tags** for categorization
5. **Set correct severity levels** based on impact
6. **Document complex CEL expressions** with comments
7. **Test both positive and negative scenarios**
8. **Validate generated YAML** before deployment

## Declaring `profileDataRequired`

When a rule's `profileDependency` is `Required` (0) or `Optional` (1), it must declare
`profileDataRequired` listing which profile surfaces the rule queries at runtime. Look at
every CEL guard that passes an event field to a profile helper (`ap.*` / `nn.*`) and
translate the argument into a pattern under the correct surface key:

| Event field | Surface key |
|---|---|
| `event.path` / `event.exepath` (open events) | `opens` |
| `event.path` / `event.exepath` (exec events) | `execs` |
| `event.syscallName` | `syscalls` |
| `event.capName` | `capabilities` |
| `event.name` (DNS) | `egressDomains` |
| `event.dstAddr` / `event.dstIp` (network) | `egressAddresses` |
| `event.endpoint` (HTTP) | `endpoints` |

| Guard operator | Pattern type |
|---|---|
| `==` | `exact` |
| `.startsWith(...)` | `prefix` |
| `.endsWith(...)` | `suffix` |
| `.contains(...)` | `contains` |

If the helper receives a fully dynamic argument with no co-located literal guard, declare
the surface as `all`.

Example:

```yaml
profileDependency: 0
profileDataRequired:
  opens:
    - exact: "/var/run/docker.sock"
    - prefix: "/etc/cron.d/"
  execs: all
```

The lint at `cmd/lint-projection/` enforces that declarations are present and schema-valid.
Run it locally with `make lint-projection`. Getting the patterns right is the rule author's
responsibility — runtime metrics in node-agent catch drift after deployment.

Rules with `profileDependency: 2` (NotRequired) must **not** declare `profileDataRequired`;
the lint emits a warning if they do.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add your rule following the guidelines
4. Write comprehensive tests
5. Run the generation script
6. Submit a pull request
