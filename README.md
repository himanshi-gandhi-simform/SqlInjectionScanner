# SQL Injection Pattern Scanner

An AI agent that audits .NET/C# codebases for SQL injection, packaged with a scored
proof-of-concept that measures whether it actually works.

**Target:** .NET 10 / ASP.NET Core · **Standards:** CWE-89, OWASP A03:2021

| Document | Purpose |
|---|---|
| [`COMMANDS.md`](COMMANDS.md) | Every command — setup, build, run, verify, troubleshoot |
| [`REMEDIATION.md`](REMEDIATION.md) | The 12 patterns: what the issue is and how to fix it |
| [`verification/VERIFY.md`](verification/VERIFY.md) | How to score a run |
| [`verification/EXPECTED_FINDINGS.md`](verification/EXPECTED_FINDINGS.md) | Ground truth — **do not show the agent** |

---

## Why this exists

Finding string concatenation next to a `SELECT` is easy. Three harder things decide
whether a scanner is worth running:

1. **Not flagging safe code.** A tool that reports every dynamic-looking query trains its
   readers to ignore it, and an ignored audit is worse than none.
2. **Seeing taint that isn't local.** A value written to the database yesterday and
   concatenated into a query today never appears next to an HTTP parameter.
3. **Fixing what parameters can't fix.** `ORDER BY` columns and table names cannot be
   bound. A remediation that says "use `@parameter`" there does not run.

So this repo ships the agent *and* a codebase with a known answer, because "it seems to
work" is not a claim you can act on. The compiler's own analyzer catches **1** of the 14
seeded flaws — that gap is the argument.

---

## Quick start

```bash
dotnet build VulnerableShop.sln
```

Open the repository root in Claude Code. The agent is discovered from `.claude/agents/`.
In a **fresh session**, ask:

```
Use the sql-injection-scanner agent to audit src/VulnerableShop.Api
```

The report is written to `reports/sql-injection-audit-vulnerableshop-api.md`, with the
executive summary printed to the conversation. Score it with
[`verification/VERIFY.md`](verification/VERIFY.md).

> **Keep `verification/` out of that session.** It contains the answer key. If the agent
> reads it, the run proves nothing.

Full command reference in [`COMMANDS.md`](COMMANDS.md).

---

## Layout

```
.
├─ .claude/agents/
│  └─ sql-injection-scanner.md      The agent
├─ src/VulnerableShop.Api/          POC target — analyzed, never executed
│  ├─ Controllers/                  Untrusted input surface
│  ├─ Data/
│  │  ├─ AdoNetProductRepository.cs   Raw ADO.NET  — 3 flaws, 2 decoys
│  │  ├─ DapperOrderRepository.cs     Dapper       — 3 flaws, 1 decoy
│  │  ├─ EfCoreCustomerRepository.cs  EF Core      — 3 flaws, 1 decoy
│  │  └─ ReportQueryBuilder.cs        Dynamic SQL  — 4 flaws
│  └─ Services/AuditService.cs      Second-order — 1 flaw, 1 decoy
├─ reports/                         Agent output
├─ verification/                    Answer key and scoring
├─ COMMANDS.md
├─ REMEDIATION.md
└─ VulnerableShop.sln
```

---

## How the agent works

Four phases, each gating the next.

**Phase 0 — Detect.** Reads `*.csproj`, `Program.cs`, and `appsettings*.json` to establish
framework, data-access technology, provider, and input surface *before* forming any
opinion. Guessing the ORM produces fixes for the wrong API. Absent signals are reported
as `Not determined`, never as a plausible default.

**Phase 1 — Root cause.** Runs a fixed 12-rule sweep so coverage does not depend on what
the model happens to notice, then traces `Source → Path → Sink` for each hit. A candidate
is vulnerable when untrusted input reaches query text as **structure** rather than as a
**bound value**. Mitigations found along the path — binding, allow-lists, or simply a
non-string CLR type — lower confidence rather than being ignored.

Findings carry **severity** (how bad if real) and **confidence** (how sure it is real)
*separately*. A Critical/Low means "confirm this now"; a Low/High means "real, fix it next
sprint". Collapsing the two is how reports become unactionable.

**Phase 2 — Prove.** Every High and Medium gets an `Input:` / `Yields:` pair — the literal
attacker value and the resulting SQL, so the structural break is visible in two lines.
Proofs are benign (`@@version`, `1=1`): demonstrating reachability, not causing damage. An
unprovable finding gets its confidence lowered and the blocker stated.

**Phase 3 — Fix.** Corrected code matching the stack found in Phase 0, with an effort
rating (Trivial / Moderate / Invasive). Where binding cannot apply, the fix is an
allow-list and says so explicitly.

### Report shape

The report is deliberately compact — a work order, not an essay. It opens with a
**total-issue table**, then gives each finding *issue → why it matters → how to fix* in
about 15 lines. See [`reports/SAMPLE-REPORT.md`](reports/SAMPLE-REPORT.md) for the exact
format.

### Guardrails

| Rule | How it is enforced |
|---|---|
| No finding without a `file:line` actually read | Agent instruction |
| Unresolvable cases → *Insufficient Evidence*, never a guess | Agent instruction |
| Safe code must not be flagged | Agent instruction + decoys in the POC |
| Grep locates, reading confirms | Agent instruction |
| Writes only to `reports/` | Agent instruction |
| Stable ordering across runs | Agent instruction |

The agent has `Read`, `Grep`, `Glob`, and `Write`. `Write` exists so it can save its
report; the instruction restricting it to `reports/` is the only thing keeping it out of
your source, so **verify rather than trust**:

```bash
git diff --exit-code -- src
```

Exit code 0 means the audited code is untouched. For a hard guarantee instead of an
instructed one, delete `Write` from the agent's frontmatter — it will then print the
report rather than save it, and becomes structurally incapable of modifying anything.

---

## Detection rules

| Rule | Detects |
|---|---|
| `SQLI-001` | Raw ADO.NET command text |
| `SQLI-002` | EF Core raw escape hatches (`FromSqlRaw`, `ExecuteSqlRaw`) |
| `SQLI-003` | Dapper entry points |
| `SQLI-004` | SQL literals anywhere in source |
| `SQLI-005` | `ORDER BY` by concatenation — **parameters cannot fix** |
| `SQLI-006` | `LIKE` wildcards by concatenation |
| `SQLI-007` | Indirect assembly (`string.Format`, `StringBuilder`) |
| `SQLI-008` | Dynamic table/schema names — **parameters cannot fix** |
| `SQLI-009` | Untrusted entry points |
| `SQLI-010` | Paging values spliced into text |
| `SQLI-011` | Mitigations — used to **clear** code, not condemn it |
| `SQLI-012` | Injection surviving into a stored procedure |

Each rule maps to a numbered section in [`REMEDIATION.md`](REMEDIATION.md).

---

## The POC target

`VulnerableShop.Api` deliberately mixes **raw ADO.NET, Dapper, and EF Core**, because an
agent that recognizes only one stack silently under-reports on real code. It contains
**14 genuine vulnerabilities** and **5 safe decoys**.

**No `// VULNERABLE` comments appear anywhere in `src/`.** An agent that passes by reading
labels has demonstrated nothing.

### The cases that separate reasoning from pattern matching

**The decisive decoy** — seven lines apart in the same file:

```csharp
.FromSqlRaw("SELECT * FROM Customers WHERE Email = '" + email + "'")   // injectable
.FromSql($"SELECT * FROM Customers WHERE City = {city}")               // safe
```

The *interpolated* one is safe: EF Core's `FromSql` parameterizes its holes. Telling them
apart needs API knowledge, not matching on `$"`. **Flagging the safe one fails the run.**

**Concatenation beside a real parameter** — treating "has parameters" as "is safe" misses
this:

```csharp
var sql = $"UPDATE Orders SET Status = '{newStatus}' WHERE Id = @OrderId";
return await connection.ExecuteAsync(sql, new { OrderId = orderId });
```

**Second-order taint** — no HTTP parameter in sight; the value was stored earlier:

```csharp
var sql = "INSERT INTO AuditLog (CustomerId, Detail) VALUES ("
          + customer.Id + ", '" + customer.Notes + "')";
```

**Unparameterizable positions** — `ORDER BY` and table names. Any fix proposing
`@parameter` is wrong.

**Type-constrained decoys** — `"TOP " + pageSize` where `pageSize` is `int`. No payload
survives the CLR type. Low with that reasoning is fine; High is a false positive.

---

## Grading

```
Recall    = true positives found / 14
Precision = true positives found / total reported
```

| Grade | Bar |
|---|---|
| **Strong** | 14/14, zero false positives, second-order and mixed-parameter cases caught |
| **Pass** | Recall ≥ 12/14, zero decoys flagged High, `FromSql` decoy explicitly cleared |
| **Fail** | `FromSql` decoy reported as vulnerable, **or** recall < 10/14 |

Flagging the safe `FromSql` fails regardless of recall. Precision decides whether anyone
keeps reading the reports; a tool at 100% recall and 50% precision gets muted in a week.

### Independent corroboration

`dotnet build` emits **EF1003** on the unsafe `FromSqlRaw` and stays silent on the safe
`FromSql` — confirming that decoy pair from a tool with no knowledge of the answer key.

It also catches 1 of 14. Nothing on Dapper, raw ADO.NET, `ORDER BY`, dynamic table names,
or second-order taint.

---

## Limitations

Worth stating plainly, since a scanner presented as complete is more dangerous than one
that names its edges:

- **Intra-procedural by default.** Taint crossing many layers may land in *Insufficient
  Evidence* rather than confirmed.
- **No compiled semantic model.** The agent reads source; it does not resolve the full
  type graph the way a Roslyn analyzer would.
- **Stored procedure bodies are out of scope.** Injection *inside* a proc is invisible
  from C#.
- **Sample size is 19 cases.** A pass indicates competence on these patterns, not a
  guarantee on unfamiliar ones.
- **Findings need human review.** This is triage that shortens the list, not a substitute
  for a security engineer.

---

## Scope and safety

`src/VulnerableShop.Api` is a **scanner test fixture**. It is intentionally insecure, has
no database behind it, and is not a reference for writing data access. Do not copy from
it — [`REMEDIATION.md`](REMEDIATION.md) shows how each pattern should have been written
instead.

Everything here is original work written for this POC.
