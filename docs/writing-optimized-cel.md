# Writing Optimized CEL

How to write rule expressions that produce the **same detection outcome** for **less CPU and
memory**. None of the techniques here change what a rule matches — they only change how cheaply the
node-agent CEL engine evaluates it.

## Why it matters

Every enabled rule is evaluated on **every matching event**, on every node. A busy fleet pushes
thousands of `exec`/`open`/`dns` events per second through the rule engine, so per-event cost is a
multiplier.

## The one mechanism you need to understand

The node-agent CEL engine compiles each rule through two static optimizers
(`kubescape/node-agent`, `pkg/rulemanager/cel/cel.go`, cel-go **v0.26.1**):

- **Set-membership optimizer** (`ext.NewSetMembershipOptimizer`). Per `cel-go@v0.26.1/ext/sets.go`,
  it rewrites `x in [<list of constants>]` — where every element is a constant
  `string`/`int`/`uint`/`bool` — into a **map-keyed lookup** at compile time. It matches on the
  **`in` operator only**, with **no size threshold** (it fires even for two elements).
- **Constant-folding optimizer** (`NewConstantFoldingOptimizer`) — evaluates constant
  sub-expressions (a literal list or map of strings) **once at compile time** rather than rebuilding
  them per event.

**Two consequences drive everything below:**

1. A chain of `x == 'a' || x == 'b' || …` is a `||`/`==` spine — **not** an `in` expression — so the
   set-membership optimizer never sees it and it stays N comparisons per event. Rewrite it to
   `x in ['a', 'b', …]` and the optimizer turns it into a single map lookup. **This is the real win.**
2. Because the optimizer *already* converts a constant `in [...]` list to a map, writing the map
   literal yourself (`x in {'a': true, …}`) buys **no additional runtime speed** for constant sets —
   it is a readability choice, not an O(1)-vs-O(n) choice.

---

## Techniques that are genuine CPU wins

### 1. Collapse `==` OR-chains into `x in [...]`

The highest-value rewrite, because it converts an unoptimizable spine into an optimizer-backed map
lookup.

```cel
// ✗ before — N comparisons per event; the optimizer can't see a || / == spine
event.comm == 'nc' || event.comm == 'netcat'
event.path == '/var/log/auth.log' || event.path == '/var/log/secure' || event.path == '/var/log/syslog'

// ✓ after — compiles to a single map-keyed lookup
event.comm in ['nc', 'netcat']
event.path in ['/var/log/auth.log', '/var/log/secure', '/var/log/syslog']
```

### 2. Fold repeated `.exists` on the same collection into a single pass

When the field is itself a list (`event.args`, `event.flags`), don't scan it once per needle. Push
the alternatives *inside one* `.exists` so you traverse the collection a single time — and the inner
`x in [<constants>]` is itself map-optimized.

```cel
// ✗ before — three full passes over event.args
event.args.exists(a, a == 'add') || event.args.exists(a, a == 'install') || event.args.exists(a, a == 'remove')

// ✓ after — one pass; inner membership test is map-optimized
event.args.exists(a, a in ['add', 'install', 'remove'])
```

**Correctness caveat.** This is outcome-preserving only when you are matching **whole elements**.
`event.args.join(' ').contains('rm -rf')` matches a substring *inside* an element and can match a
sequence that **spans element boundaries**; `event.args.exists(a, a in ['rm -rf'])` matches neither.
Only convert `join(' ').contains(...)` to element membership when the needle is a complete token
(e.g. an `O_*` flag, an exact arg). Otherwise keep the `join`.

---

## Rewrites that are readability, not CPU

These make rules easier to read and maintain and are worth doing — but be honest that they are
roughly CPU-neutral, so don't rewrite a working rule *for performance* alone.

### 3. List vs. map literal — a readability choice

For a set of constants, `x in ['a', 'b', …]` and `x in {'a': true, …}` compile to the **same**
map-keyed lookup (see the mechanism above). Use the list form by default; reach for a map literal
only when it genuinely reads better (very large sets), or in the rare case the elements are **not**
all constants — then the optimizer bails on the list and an explicit map avoids a linear scan.

### 4. `endsWith`/`startsWith`/`contains` chains → `[...].exists(s, x.op(s))`

Suffix/prefix/substring tests are **not** equality, so they cannot become `in` and the
set-membership optimizer does **not** apply — the `.exists` macro still calls `endsWith` once per
element, the same count as the OR-chain. The gain is readability plus a constant-folded list literal,
**not** algorithmic speed.

```cel
// same number of endsWith calls either way — the list form is just cleaner
['/nmap', '/masscan', '/nikto', …].exists(s, event.exepath.endsWith(s))
['/etc/crontab', '/etc/cron.d/', '/var/spool/cron/'].exists(p, event.path.startsWith(p))
```

When a rule mixes exact and suffix matches, OR the two idioms into one expression (note the `||`):

```cel
(['python', 'python3', 'perl', 'ruby', 'node'].exists(s, event.exepath.endsWith(s)) ||
 ['/python', '/perl', '/ruby', '/node'].exists(s, event.exepath.contains(s)))
```

### 5. Repeated `join(' ')` — what does and doesn't help

`event.flags.join(' ').contains('O_WRONLY')` allocates a joined string. Two things to know:

- Where the needles are **whole tokens**, prefer iterating the list — this avoids the join
  allocation entirely and is one pass (technique 2). Keep the alternative set **identical** to the
  original so the outcome doesn't change:

  ```cel
  // ✗ before
  event.flags.join(' ').contains('O_WRONLY') || event.flags.join(' ').contains('O_RDWR') || event.flags.join(' ').contains('O_TRUNC')
  // ✓ after — same three tokens, no join, one pass
  event.flags.exists(f, f in ['O_WRONLY', 'O_RDWR', 'O_TRUNC'])
  ```

- Where you must keep `join(' ')` (substring or cross-token match), folding the needles into a list
  **does not** make the join run once — `['a','b','c'].exists(s, event.args.join(' ').contains(s))`
  re-evaluates `join(' ')` on **every iteration** (up to once per needle). It only consolidates the
  needles into one predicate; it is **not** a single-join optimization. `join` is not constant, so
  constant folding can't hoist it. If the repeated join is genuinely hot, the fix is host-side, not
  in the expression.

### 6. Order predicates cheap-and-selective first (`&&` short-circuits)

CEL evaluates `&&` left-to-right and stops at the first `false`. Put the cheapest, most-selective
predicate first so the expensive ones rarely run:

- A plain field compare (`event.containerId != ''`, `event.comm in [...]`) is cheaper than a
  library/profile call (`ap.was_executed(...)`, `nn.is_domain_in_egress(...)`, `parse.*`).
- Profile-lookup / negation gates like `!ap.was_path_opened(...)` are the natural **last** term —
  they only run for the tiny fraction of events that already matched the signature.

```cel
event.comm in ['nc', 'netcat'] &&
event.args.exists(a, a in ['-e', '-c']) &&
!ap.was_executed(event.containerId, parse.get_exec_path(event.args, event.comm))
```

## Checklist before shipping a rule

- [ ] No `x == 'a' || x == 'b' || …` chains — use `x in [...]` (technique 1, real win).
- [ ] No `coll.exists(x, x==a) || coll.exists(x, x==b)` — one `coll.exists(x, x in [a,b])` (technique 2).
- [ ] `join(' ').contains(...)` collapsed to element membership **only** where the needle is a whole
      token; substring / cross-token matches keep the `join`.
- [ ] Cheapest / most-selective predicate first; `ap.*` / `nn.*` gates last.
- [ ] `in [...]`-vs-`in {...}` and `endsWith`-chain-vs-`.exists` chosen for **readability** — don't
      claim a CPU win the optimizer already gives you or doesn't give at all.
- [ ] Behavior unchanged — the rule's tests fire and no-fire exactly as before, and any "before/after"
      you write keeps the **same** match set.
