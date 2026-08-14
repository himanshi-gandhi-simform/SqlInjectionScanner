# SQL Injection Pattern Scanner — Agent + POC

An AI agent that audits .NET/C# code for SQL injection, and a measurable proof that it
works.

The hard part of a scanner like this is not finding string concatenation. It is telling
apart code that is dangerous from code that merely looks dangerous, and doing it without
inventing findings. So this POC is built around a scored test, not a demo.

## What is here

```
SqlInjectionScanner\
├─ .claude\agents\
│  └─ sql-injection-scanner.md      The agent
├─ src\VulnerableShop.Api\          The POC target — a Web API with seeded flaws
├─ verification\
│  ├─ EXPECTED_FINDINGS.md          Answer key: 14 real flaws, 5 safe decoys
│  └─ VERIFY.md                     How to run and score it
└─ VulnerableShop.sln
```

## The agent

`.claude/agents/sql-injection-scanner.md` runs four phases:

| Phase | What it does |
|-------|--------------|
| 0 | Detect the stack from files — framework, ORM, provider, input surface — before any verdict |
| 1 | Run a fixed 12-rule grep sweep, then trace source → path → sink and assign Low/Medium/High |
| 2 | Prove each finding with an attacker input, the resulting SQL, and a standalone repro snippet |
| 3 | Before/After patches, ordered by confidence |

The determinism comes from the rule table (`SQLI-001`…`SQLI-012`), which fixes coverage
so it does not depend on what the model happens to notice. The reasoning layer then
judges each hit and catches what grep structurally cannot — second-order taint, and the
difference between two API calls that look identical.

Guardrails are in the agent definition: no finding without a `file:line` it actually
read, unresolvable cases go to *Insufficient Evidence* instead of becoming guesses,
safe code must not be flagged, and the audited repository is never modified. The agent
is granted `Read`, `Grep`, `Glob` and nothing else, so read-only is enforced by the tool
list rather than by asking politely.

## The POC target

`VulnerableShop.Api` is an ASP.NET Core Web API on .NET 10 that deliberately mixes
**raw ADO.NET, Dapper, and EF Core** — because an agent that recognizes only one stack
will silently under-report on a real codebase.

It contains **14 genuine vulnerabilities** and **5 safe decoys**. The decoys are the
point. Any tool can flag every `+` near a `SELECT`; the test is whether it leaves
correct code alone. The sharpest pair sits seven lines apart:

```csharp
.FromSqlRaw("SELECT * FROM Customers WHERE Email = '" + email + "'")   // line 14 — injectable
.FromSql($"SELECT * FROM Customers WHERE City = {city}")               // line 21 — safe
```

The second interpolates and is safe, because EF Core's `FromSql` parameterizes its
holes. Getting this right needs API knowledge, not pattern matching.

**No `// VULNERABLE` comments appear anywhere in the sample.** An agent that passes by
reading labels has demonstrated nothing.

## Running it

```bash
cd C:\Users\himanshi.gandhi\Desktop\SqlInjectionScanner
```

Then, in a **fresh** Claude Code session:

```
Use the sql-injection-scanner agent to audit src/VulnerableShop.Api
```

Score the result with `verification/VERIFY.md`. Keep `verification/` out of the
session — an agent that reads the answer key voids the run.

Passing is recall ≥ 12/14 with zero decoys flagged High. Flagging the `FromSql` decoy
fails the run outright regardless of recall.

## Build

```bash
dotnet build VulnerableShop.sln
```

Builds clean on .NET SDK 10.0.301, with one expected warning: **EF1003** on
`EfCoreCustomerRepository.cs:14`.

That warning is useful evidence. The compiler independently confirms the unsafe
`FromSqlRaw` and stays silent on the safe `FromSql` — corroborating two entries of the
answer key from a tool that has never seen it. It also shows the limit: Roslyn catches
1 of the 14. It says nothing about Dapper, raw ADO.NET, `ORDER BY`, dynamic table
names, or the second-order case. That gap is what the agent is for.

## Scope

The sample app is a **scanner test fixture**. It is intentionally insecure, has no
database behind it, and is not a reference for how to write data access. Do not copy
from `src/` into anything real — read `verification/EXPECTED_FINDINGS.md` for how each
pattern should have been written instead.
