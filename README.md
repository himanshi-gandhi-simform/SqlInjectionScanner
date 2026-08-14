# SQL Injection Pattern Scanner

An AI agent that audits .NET/C# codebases for SQL injection, packaged with a scored
proof-of-concept that measures whether it actually works.

**Status:** POC · **Target:** .NET 10 / ASP.NET Core · **Build:** clean on SDK 10.0.301

---

## Contents

- [Why this exists](#why-this-exists)
- [Quick start](#quick-start)
- [Requirements](#requirements)
- [Project structure](#project-structure)
- [How the agent works](#how-the-agent-works)
- [Detection rules](#detection-rules)
- [The POC target](#the-poc-target)
- [Verifying a run](#verifying-a-run)
- [Sample output](#sample-output)
- [Troubleshooting](#troubleshooting)
- [Limitations](#limitations)
- [FAQ](#faq)

---

## Why this exists

Finding string concatenation next to a `SELECT` is easy. Three harder things decide
whether a scanner is worth running:

1. **Not flagging safe code.** A tool that reports every dynamic-looking query trains
   its readers to ignore it, and an ignored audit is worse than none.
2. **Seeing taint that isn't local.** A value written to the database yesterday and
   concatenated into a query today never appears next to an HTTP parameter.
3. **Fixing what parameters can't fix.** `ORDER BY` columns and table names cannot be
   bound. A fix that says "use `@parameter`" there doesn't compile.

So this repo ships the agent *and* a codebase with a known answer, because "it seems to
work" isn't a claim you can act on.

The built-in compiler analyzer catches **1** of the 14 flaws in the sample. That gap is
the argument.

---

## Quick start

```bash
cd C:\Users\himanshi.gandhi\Desktop\SqlInjectionScanner
```

Open that folder in Claude Code. The agent is discovered automatically from
`.claude/agents/`. In a **fresh session**, ask:

```
Use the sql-injection-scanner agent to audit src/VulnerableShop.Api
```

Then score the report against [`verification/VERIFY.md`](verification/VERIFY.md).

> **Keep `verification/` out of that session.** It contains the answer key. If the agent
> reads it, the run proves nothing — start over in a new session.

To point the agent at your own code instead, open your repo, copy
`.claude/agents/sql-injection-scanner.md` into it, and name your path in the request.

---

## Requirements

| | |
|---|---|
| .NET SDK | 10.0.100 or later (developed on 10.0.301) |
| Claude Code | Any recent version |
| Database | **None.** The sample never connects — it is analyzed, not executed |
| Network | Only for the first `dotnet restore` |

Verify your SDK:

```bash
dotnet --version
```

---

## Project structure

```
SqlInjectionScanner\
├─ .claude\agents\
│  └─ sql-injection-scanner.md      The agent definition
│
├─ src\VulnerableShop.Api\          POC target — analyzed, never run
│  ├─ Controllers\
│  │  ├─ CatalogController.cs       Untrusted input surface
│  │  └─ ReportsController.cs       Untrusted input surface
│  ├─ Data\
│  │  ├─ AdoNetProductRepository.cs Raw ADO.NET  — 3 flaws, 2 decoys
│  │  ├─ DapperOrderRepository.cs   Dapper       — 3 flaws, 1 decoy
│  │  ├─ EfCoreCustomerRepository.cs EF Core     — 3 flaws, 1 decoy
│  │  ├─ ReportQueryBuilder.cs      Dynamic SQL  — 4 flaws
│  │  └─ ShopDbContext.cs
│  ├─ Models\Entities.cs
│  ├─ Services\AuditService.cs      Second-order — 1 flaw, 1 decoy
│  └─ Program.cs
│
├─ verification\
│  ├─ EXPECTED_FINDINGS.md          Ground truth — do not show the agent
│  └─ VERIFY.md                     Scoring procedure and checklist
│
├─ VulnerableShop.sln
└─ README.md
```

---

## How the agent works

Four phases, each gating the next.

### Phase 0 — Detect the environment

Reads `*.csproj`, `Program.cs`, and `appsettings*.json` to establish target framework,
data-access technology, database provider, and how HTTP input arrives — **before**
forming any opinion. Guessing the ORM produces fixes for the wrong API, so this phase
runs first and reports `Not determined` rather than a plausible default.

### Phase 1 — Identify root causes

Runs a fixed [12-rule sweep](#detection-rules) so coverage doesn't depend on what the
model happens to notice, then reasons over every hit:

```
Source  →  Path  →  Sink
```

A candidate is vulnerable when untrusted input reaches query text as **structure**
rather than as a **bound value**. Mitigations found along the path — parameter binding,
allow-lists, `int.TryParse`, or simply a non-string CLR type — reduce confidence
honestly rather than being ignored.

Confidence is **High** (unmitigated path), **Medium** (real path with an unresolved
condition), or **Low** (pattern matches, exploitation needs an unevidenced
precondition). Each finding also carries secondary factors: connection privileges,
error leakage, whether the endpoint is authenticated.

### Phase 2 — Reproduce

Every High and Medium gets a concrete attacker input, the resulting SQL after
substitution, and a standalone C# snippet. If a repro can't be built, confidence drops
and the blocker is stated — an unprovable finding is a weaker finding.

### Phase 3 — Fix

Before/After patches ordered by confidence, matching the data-access technology found
in Phase 0. Where binding doesn't apply, the fix is an allow-list and says so.
Behavioral changes — `LIKE` escaping, culture-sensitive comparison — are called out,
because a fix that silently changes results is a bug you filed.

### Guardrails

| Rule | Enforcement |
|---|---|
| No finding without a `file:line` actually read | Agent instruction |
| Unresolvable cases → *Insufficient Evidence*, never a guess | Agent instruction |
| Safe code must not be flagged | Agent instruction + decoys in the POC |
| Grep locates, reading confirms | Agent instruction |
| Never modify the audited repo | **Tool list** — `Read`, `Grep`, `Glob` only |
| Stable ordering across runs | Agent instruction |

Read-only is the one guardrail that could damage a real repository, so it isn't left to
instruction-following: the agent is granted no write tools and *cannot* edit, even if
asked.

---

## Detection rules

| Rule | Detects |
|---|---|
| `SQLI-001` | Raw ADO.NET command text (`CommandText`, `new SqlCommand`, Npgsql, MySql) |
| `SQLI-002` | EF Core raw escape hatches (`FromSqlRaw`, `ExecuteSqlRaw`) |
| `SQLI-003` | Dapper entry points (`Query<`, `QueryAsync`, `Execute`) |
| `SQLI-004` | SQL literals anywhere in source |
| `SQLI-005` | `ORDER BY` built by concatenation — **not fixable with parameters** |
| `SQLI-006` | `LIKE` wildcards built by concatenation |
| `SQLI-007` | Indirect assembly (`string.Format`, `StringBuilder`, `string.Concat`) |
| `SQLI-008` | Dynamic table or schema names — **not fixable with parameters** |
| `SQLI-009` | Untrusted entry points (`[FromQuery]`, `[FromRoute]`, `[FromBody]`, `Request.*`) |
| `SQLI-010` | Paging values spliced into text (`TOP`, `OFFSET`, `FETCH`) |
| `SQLI-011` | Mitigations — used to **clear** code, not condemn it |
| `SQLI-012` | Injection surviving into a stored procedure (`sp_executesql`, `EXEC(`) |

---

## The POC target

`VulnerableShop.Api` deliberately mixes **raw ADO.NET, Dapper, and EF Core**, because an
agent that recognizes only one stack silently under-reports on real codebases.

It contains **14 genuine vulnerabilities** and **5 safe decoys**.

### The cases that separate reasoning from pattern matching

**The decoy that matters most** — these sit seven lines apart in the same file:

```csharp
.FromSqlRaw("SELECT * FROM Customers WHERE Email = '" + email + "'")   // line 14 — injectable
.FromSql($"SELECT * FROM Customers WHERE City = {city}")               // line 21 — safe
```

The *interpolated* one is safe: EF Core's `FromSql` parameterizes its holes. Telling
these apart requires knowing the API, not matching on `$"`. **Flagging line 21 fails the
run outright.**

**Concatenation beside a real parameter** — a scanner treating "has parameters" as
"is safe" misses this:

```csharp
var sql = $"UPDATE Orders SET Status = '{newStatus}' WHERE Id = @OrderId";
return await connection.ExecuteAsync(sql, new { OrderId = orderId });
```

**Second-order taint** — never touches an HTTP parameter; the value was stored earlier
and is re-read:

```csharp
var customer = await _dbContext.Customers...;
var sql = "INSERT INTO AuditLog (CustomerId, Detail) VALUES ("
          + customer.Id + ", '" + customer.Notes + "')";
```

**Unparameterizable positions** — `ORDER BY` columns and table names. Any fix proposing
`@parameter` here is wrong.

**Type-constrained decoys** — `"TOP " + pageSize` where `pageSize` is `int`. No string
payload survives the CLR type. Reporting as Low with that reasoning is fine; High is a
false positive.

> **No `// VULNERABLE` comments appear anywhere in `src/`.** An agent that passes by
> reading labels has demonstrated nothing.

---

## Verifying a run

Full procedure in [`verification/VERIFY.md`](verification/VERIFY.md). In summary:

```
Recall    = true positives found / 14
Precision = true positives found / total reported
```

| Grade | Bar |
|---|---|
| **Strong** | 14/14, zero false positives, second-order and mixed-parameter cases caught |
| **Pass** | Recall ≥ 12/14, zero decoys flagged High, `FromSql` decoy explicitly cleared |
| **Fail** | `FromSql` decoy reported as vulnerable, **or** recall < 10/14 |

Beyond the counts, check that Phase 0 named all three data-access stacks, that
`ORDER BY` and table-name fixes use allow-lists, and that the repo is untouched:

```bash
git status --porcelain
```

Empty output means clean. Any change under `src/` is a hard fail.

### Independent corroboration

```bash
dotnet build VulnerableShop.sln
```

Roslyn emits **EF1003** on `EfCoreCustomerRepository.cs:14` and stays silent on line 21
— confirming that decoy pair from a tool with no knowledge of the answer key.

It also catches **1 of 14**. Nothing on Dapper, raw ADO.NET, `ORDER BY`, dynamic table
names, or second-order taint.

---

## Sample output

Shape of a passing report:

```
# SQL Injection Audit — src/VulnerableShop.Api

## Phase 0 — Environment
net10.0 · ASP.NET Core Web API · EF Core 10 + Dapper 2.1 + raw ADO.NET
Provider: SQL Server · Input: [FromQuery], [FromRoute], [FromBody]

## Phase 1 — Findings
| ID  | File:Line                          | Rule      | Confidence |
| F01 | Data/AdoNetProductRepository.cs:16 | SQLI-006  | High       |
| F02 | Data/DapperOrderRepository.cs:37   | SQLI-005  | High       |
...

### F01 — LIKE clause built by concatenation
Source  [FromQuery] term  (CatalogController.cs:17)
Path    term → SearchByNameAsync(term) → sql
Sink    new SqlCommand(sql, connection)   AdoNetProductRepository.cs:19
Secondary: unauthenticated endpoint; errors surface to caller

## Phase 2 — Reproduction
F01 input:  %' UNION SELECT 1,@@version,1,1--
Resulting SQL: ... WHERE Name LIKE '%%' UNION SELECT 1,@@version,1,1--%'

## Phase 3 — Fixes
F01 Before / After ...

## Cleared (not vulnerabilities)
EfCoreCustomerRepository.cs:21 — FromSql parameterizes interpolation holes

## Coverage
14 files read · 12 rules run · migrations not examined
```

The **Cleared** section matters: silence about safe code is indistinguishable from
having missed it.

---

## Troubleshooting

**`NU1605` package downgrade on build**
EF Core 10 requires `Microsoft.Data.SqlClient` ≥ 6.1.1. Already pinned in the csproj;
if you change versions, keep that floor.

**`dotnet sln` says the solution can't be found**
.NET 10 creates `.slnx` by default. This repo ships classic `.sln` — use
`dotnet new sln --format sln` if regenerating.

**EF1003 warning on build**
Expected, and correct. It's the compiler flagging the real `FromSqlRaw` flaw on line 14.

**The agent doesn't appear**
It's discovered from `.claude/agents/` relative to the folder you opened. Open
`SqlInjectionScanner` itself, not a parent directory.

**Findings differ between runs**
Determinism is part of the spec. Re-run in two fresh sessions and diff the IDs; drift
means the agent is leaning on intuition where the rule table should drive it.

---

## Limitations

Worth stating plainly, since a scanner presented as complete is more dangerous than one
that admits its edges:

- **Intra-procedural by default.** Taint crossing many layers may be reported as
  *Insufficient Evidence* rather than confirmed.
- **No build-time semantic model.** The agent reads source; it does not resolve the full
  type graph the way a compiled Roslyn analyzer would.
- **Stored procedure bodies are out of scope.** Injection *inside* a proc isn't visible
  from C#.
- **Sample size is 19 cases.** A pass indicates competence on these patterns, not a
  guarantee on unfamiliar ones.
- **Findings need human review.** This is triage that shortens the list, not a substitute
  for a security engineer.

---

## FAQ

**Can I run the agent against my own repo?**
Yes. Copy `.claude/agents/sql-injection-scanner.md` into your repo and name your path.
It has no dependency on the sample.

**Does the sample need a database?**
No. It is analyzed, never executed. The connection string is a placeholder.

**Why isn't there a compiled Roslyn analyzer?**
The rule sweep gives reproducible coverage with no build step, so it works on any repo
including ones that don't compile. The build here does show what a real analyzer
contributes — and where it stops.

**Can the agent modify my code?**
No. It has `Read`, `Grep`, `Glob` and no write tools. Patches are report text you apply
yourself.

**Why do the decoys matter so much?**
Precision decides whether anyone keeps reading the reports. A tool at 100% recall and
50% precision gets muted within a week.

---

## Scope and safety

`src/VulnerableShop.Api` is a **scanner test fixture**. It is intentionally insecure and
is not a reference for writing data access. Don't copy from it into real code — see
[`verification/EXPECTED_FINDINGS.md`](verification/EXPECTED_FINDINGS.md) for how each
pattern should have been written instead.

Everything here is original work, written for this POC.
