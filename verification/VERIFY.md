# How to verify the agent

The point of this POC is that "the agent works" is a measurable claim, not an
impression. Run it blind, score it against the key, record the number.

## Run it

Open the repository root in Claude Code. The agent is picked up automatically from
`.claude/agents/sql-injection-scanner.md`. Ask for the audit in a **fresh session**:

```
Use the sql-injection-scanner agent to audit src/VulnerableShop.Api
```

The report is written to `reports/` and the summary is printed to the conversation.

Keep `verification/` out of the conversation. If the agent reads the answer key the run
is void — start over in a new session.

Full command reference is in the [README](../README.md).

## Score it

Take the agent's report and fill this in.

### Recall — of 14

| ID | Expected | Found? | Confidence given | Notes |
|----|----------|--------|------------------|-------|
| V01 | AdoNet LIKE concat | | | |
| V02 | AdoNet interpolated CommandText | | | |
| V03 | AdoNet string.Format IN | | | |
| V04 | Dapper interpolated status | | | |
| V05 | Dapper ORDER BY | | | |
| V06 | Dapper concat beside a real param | | | |
| V07 | EF FromSqlRaw email | | | |
| V08 | EF ExecuteSqlRawAsync region | | | |
| V09 | EF FromSqlRaw notes LIKE | | | |
| V10 | Report StringBuilder WHERE | | | |
| V11 | Report StringBuilder ORDER BY | | | |
| V12 | Report dynamic table name | | | |
| V13 | Report EXEC proc concat | | | |
| V14 | Audit second-order | | | |

### Precision — decoys

| ID | Must not be flagged High | Reported? | Verdict |
|----|--------------------------|-----------|---------|
| S01 | Parameterized AddWithValue | | |
| S02 | Dapper anonymous params | | |
| S03 | **EF `FromSql` interpolated** | | |
| S04 | `TOP + int pageSize` | | |
| S05 | `DATEDIFF > int days` | | |

### Result

```
Recall     = ___ / 14
Precision  = ___ %
S03 cleared correctly?   Y / N
Grade                    Pass / Strong / Fail
```

Thresholds are in `EXPECTED_FINDINGS.md` section C. Flagging S03 fails the run outright
no matter how high recall is.

## Quality checks the numbers miss

Counting findings does not tell you whether the fixes are usable. Check these by hand:

- **Phase 0 named all three stacks?** The sample mixes EF Core, Dapper, and raw
  ADO.NET on purpose. An agent that reports only EF Core will hand you fixes for a
  third of the codebase.
- **`ORDER BY` and table-name fixes use allow-lists?** If any fix proposes binding an
  identifier as `@parameter`, it is wrong and would not compile against SQL Server.
  This is the most common way a plausible-sounding report turns out to be useless.
- **Repro inputs actually break the query?** Substitute the suggested payload into the
  SQL by hand and check the quoting really does close early.
- **Every finding cites `file:line`?** Any uncited claim violates the agent's own
  rules — treat it as a defect in the run.

## Confirm the agent stayed read-only

The agent must never modify what it audits. Verify rather than assume:

```bash
git status --porcelain
```

Empty output means clean. Any modification under `src/` is a **hard fail** — the rule
is explicit in the agent definition and it is the one failure that could damage a real
repository.

## Corroborating signal

The compiler independently agrees with part of the key. Run:

```bash
dotnet build VulnerableShop.sln
```

Roslyn emits **EF1003** on `EfCoreCustomerRepository.cs:14` (`FromSqlRaw`, unsafe) and
says nothing about line 21 (`FromSql`, safe). That is the V07 / S03 pair confirmed by a
tool with no knowledge of this key.

Note what that also demonstrates: the compiler catches **one** of the 14. It is silent
on Dapper, on raw ADO.NET, on `ORDER BY`, and on the second-order case. That gap is the
argument for the agent.

## Re-running

Determinism is part of the spec. Run the same audit twice in separate sessions and
diff the finding IDs and ordering. Findings that appear or reorder between runs mean
the agent is leaning on intuition where the rule table should be driving it.
