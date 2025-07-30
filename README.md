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
        unique_id: "CEL expression for unique identifier"
        rule_expression:
          - event_type: "event_type_name"
            expression: "CEL expression for detection logic"
      profile_dependency: 0  # 0=Required, 1=Optional, 2=NotRequired
      severity: 1
      support_policy: false
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
| `expressions.unique_id` | string | CEL expression for unique event ID | Yes |
| `expressions.rule_expression` | array | Array of detection expressions | Yes |
| `profile_dependency` | integer | Profile dependency level (0,1,2) | Yes |
| `severity` | integer | Rule severity level | Yes |
| `support_policy` | boolean | Whether rule supported by rule policy | Yes |
| `tags` | array | Array of tags for categorization | Yes |
| `state` | object | Rule state | No |

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

The `gen.sh` script automatically combines all individual rule YAML files into a single CRD instance.

### Usage

```bash
./gen.sh
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
5. **Generate the combined CRD** with `./gen.sh`
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
./gen.sh
# Check the generated rules-crd.yaml file
```

## CEL Expressions

Rules use Common Expression Language (CEL) for expressions. Key concepts:

### Message Expression
Defines the alert message format:
```cel
"'Unexpected process launched: ' + data.event.Comm + ' with PID ' + string(data.event.Pid)"
```

### Unique ID Expression
Creates a unique identifier for deduplication:
```cel
"data.event.Comm + '_' + string(data.event.Pid) + '_' + data.event.ExePath"
```

### Rule Expression
Defines the detection logic:
```cel
"!data.profile_checks.exec_path"
```

## Best Practices

1. **Use descriptive names** for rules and directories
2. **Follow the ID numbering convention** (R####)
3. **Write comprehensive tests** for each rule
4. **Use appropriate tags** for categorization
5. **Set correct severity levels** based on impact
6. **Document complex CEL expressions** with comments
7. **Test both positive and negative scenarios**
8. **Validate generated YAML** before deployment

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add your rule following the guidelines
4. Write comprehensive tests
5. Run the generation script
6. Submit a pull request
