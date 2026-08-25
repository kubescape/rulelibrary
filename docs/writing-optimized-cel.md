# Writing Optimized CEL

How to write rule expressions that produce the **same detection outcome** for **less CPU and
memory**. None of the techniques here change what a rule matches — they only change how cheaply the
node-agent CEL engine evaluates it.

## Why it matters

Every enabled rule is evaluated on **every matching event**, on every node. A busy fleet pushes
thousands of `exec`/`open`/`dns` events per second through the rule engine, so per-event cost is a
multiplier: an expression that is 3× cheaper per event is 3× cheaper on the hot path forever.

## The one mechanism you need to understand

The node-agent CEL engine compiles each rule through two static optimizers
(`kubescape/node-agent`, `pkg/rulemanager/cel/cel.go`):

- **Set-membership optimizer** (`ext.NewSetMembershipOptimizer`) — turns `x in [...]` and
  `x in {...}` into an efficient set lookup **at compile time**.
- **Constant-folding optimizer** (`NewConstantFoldingOptimizer`) — evaluates constant
  sub-expressions (like a literal list or map of strings) **once at compile time** instead of
  rebuilding them for every event.

**The consequence that drives everything below:** a chain of `x == 'a' || x == 'b' || …` is
**invisible** to these optimizers — the engine evaluates it as N separate comparisons on every
event. Rewrite it as `x in ['a', 'b', …]` and the optimizer collapses it to a single set lookup and
folds the list literal once. Same result, a fraction of the work.

---

## The techniques

### 1. Collapse `==` OR-chains into a list — `x in [...]`

The highest-value rewrite, because it unlocks the set-membership optimizer.

```cel
// ✗ before — N comparisons per event, optimizer can't see it
event.comm == 'nc' || event.comm == 'netcat'
event.path == '/var/log/auth.log' || event.path == '/var/log/secure' || event.path == '/var/log/syslog'

// ✓ after — one set lookup, list folded once
event.comm in ['nc', 'netcat']
event.path in ['/var/log/auth.log', '/var/log/secure', '/var/log/syslog']
```

### 2. For large exact-match sets, use a map literal — `x in {...}`

A list membership is a linear scan; a **map** literal is a hash lookup — O(1) instead of O(n). Once
a set gets big (roughly a dozen-plus entries: DNS domain blocklists, process-name lists), prefer the
map form with `: true` values.

```cel
// ✓ big exact-match set — hash lookup
event.pcomm in {
  'mysql': true, 'mysqld': true, 'postgres': true, 'postmaster': true, 'psql': true,
  'mongod': true, 'redis-server': true, 'sqlservr': true, 'oracle': true,
  'cassandra': true, 'influxd': true, 'elasticsearch': true, 'neo4j': true,
  'mariadb': true, 'clickhouse-server': true
}
```

Use a **list** for small sets (2–10) and where readability wins; use a **map** for large exact-match
sets. Both are optimizer-friendly; the map just scales better.

### 3. Collapse substring/prefix/suffix OR-chains with the `.exists` macro over a list

`==` becomes `in`, but `endsWith` / `startsWith` / `contains` can't — they aren't equality. Fold the
*needles* into a list literal and test them with one `.exists` macro. The list is constant-folded
once, and the field (`event.exepath`) is evaluated once instead of per branch.

```cel
// ✗ before — N endsWith calls, event.exepath dereferenced N times
event.exepath.endsWith('/nmap') || event.exepath.endsWith('/masscan') || event.exepath.endsWith('/nikto') || …

// ✓ after — list folded once, exepath read once
['/nmap', '/masscan', '/nikto', …].exists(s, event.exepath.endsWith(s))
```

Same shape for `startsWith` (path prefixes) and `contains` (path fragments):

```cel
['/etc/crontab', '/etc/cron.d/', '/var/spool/cron/'].exists(p, event.path.startsWith(p))
['/python', '/perl', '/ruby', '/node'].exists(s, event.exepath.contains(s))
```

When a rule mixes exact matches and suffix matches, keep both idioms and OR them:

```cel
(['python', 'python3', 'perl', 'ruby', 'node'].exists(s, event.exepath.endsWith(s)) ||
 ['/python', '/perl', '/ruby', '/node'].exists(s, event.exepath.contains(s)))
```

### 4. Iterate a collection **once**, don't re-scan it per needle

When the field is itself a list (`event.args`, `event.flags`), the wrong pattern scans the whole
collection once per needle. Push the alternatives *inside* a single `.exists` so you traverse the
collection one time.

```cel
// ✗ before — three full passes over event.args
event.args.exists(a, a == 'add') || event.args.exists(a, a == 'install') || event.args.exists(a, a == 'remove')

// ✓ after — one pass; inner test is a set lookup
event.args.exists(a, a in ['add', 'install', 'remove'])
```

**Prefer iterating the list to `join(' ').contains(...)`.** `event.flags.join(' ').contains('O_WRONLY')`
allocates a new joined string on every event, and repeating it per flag allocates repeatedly. Test
the elements directly instead:

```cel
// ✗ before — builds a joined string per event, several times
event.flags.join(' ').contains('O_WRONLY') || event.flags.join(' ').contains('O_RDWR') || event.flags.join(' ').contains('O_TRUNC')

// ✓ after — no allocation, one pass over flags
event.flags.exists(f, f in ['O_WRONLY', 'O_RDWR', 'O_TRUNC', 'O_CREAT'])
```

(If you must keep `join(' ')` — e.g. matching a substring that spans tokens — at least fold the
needles: `['a','b','c'].exists(s, event.args.join(' ').contains(s))` so the join happens once, not
once per needle.)

### 5. Order predicates cheap-and-selective first (`&&` short-circuits)

CEL evaluates `&&` left-to-right and stops at the first `false`. Put the cheapest, most-selective
predicate first so the expensive ones rarely run:

- A plain field compare (`event.containerId != ''`, `event.comm in [...]`) is cheaper than a
  library/profile call (`ap.was_executed(...)`, `nn.is_domain_in_egress(...)`, `parse.*`).
- Profile-lookup and negation gates like `!ap.was_path_opened(...)` are the natural **last** term —
  they only need to run for the tiny fraction of events that already matched the signature.

```cel
// signature first (cheap, filters ~all events), profile lookup last (expensive, rarely reached)
event.comm in ['nc', 'netcat'] &&
['-e ', '-c '].exists(s, event.args.join(' ').contains(s)) &&
!ap.was_executed(event.containerId, parse.get_exec_path(event.args, event.comm))
```

---

## Checklist before shipping a rule

- [ ] No `x == 'a' || x == 'b' || …` chains — use `x in [...]` (or `in {...}` if large).
- [ ] No repeated `field.endsWith/startsWith/contains(...)` — use `[...].exists(s, field.op(s))`.
- [ ] No repeated `list.join(' ').contains(...)` — iterate the list with `list.exists(e, e in [...])`.
- [ ] No `coll.exists(x, x==a) || coll.exists(x, x==b)` — one `coll.exists(x, x in [a,b])`.
- [ ] Cheapest / most-selective predicate first; profile (`ap.*`/`nn.*`) gates last.
- [ ] Behavior unchanged — the rule's tests fire and no-fire exactly as before.
