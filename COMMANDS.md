# Commands

Every command needed to set up, run, verify, and troubleshoot the scanner. Run them from
the repository root unless a step says otherwise.

Windows shells differ: `&&` does not work in Windows PowerShell 5.1. Chain with `;` there,
or run each command on its own line. All commands below are single commands for that
reason.

---

## 1. Prerequisites

Check the SDK. Needs 10.0.100 or later:

```bash
dotnet --version
```

List all installed SDKs if the above is not what you expect:

```bash
dotnet --list-sdks
```

Confirm Claude Code is available:

```bash
claude --version
```

No database and no connection string are required. The sample is analyzed, never
executed.

---

## 2. Get the code

```bash
git clone <your-repository-url> SqlInjectionScanner
```

```bash
cd SqlInjectionScanner
```

---

## 3. Build

Restore packages:

```bash
dotnet restore VulnerableShop.sln
```

Build:

```bash
dotnet build VulnerableShop.sln
```

**Expected result:** `Build succeeded` with **1 warning** — `EF1003` on
`EfCoreCustomerRepository.cs:14`.

That warning is correct and must not be suppressed. It is the compiler independently
confirming one of the seeded flaws, and it corroborates part of the answer key.

Build quietly, showing only warnings and errors:

```bash
dotnet build VulnerableShop.sln -v q --nologo
```

Confirm the EF warning is present and on the expected line:

```bash
dotnet build VulnerableShop.sln --nologo 2>&1 | Select-String "EF1003"
```

---

## 4. Run the audit

Open the repository root in Claude Code. The agent is discovered automatically from
`.claude/agents/`.

Start a **fresh session**, then ask:

```
Use the sql-injection-scanner agent to audit src/VulnerableShop.Api
```

> **Do not let `verification/` into the session.** It holds the answer key. If the agent
> reads it, the run proves nothing — start a new session.

The agent writes its report to:

```
reports/sql-injection-audit-vulnerableshop-api.md
```

and prints the executive summary and findings table to the conversation.

### Other useful prompts

Audit a narrower path:

```
Use the sql-injection-scanner agent to audit src/VulnerableShop.Api/Data
```

Audit your own project after copying the agent into it:

```
Use the sql-injection-scanner agent to audit src/YourProject
```

Re-check only what you just fixed:

```
Use the sql-injection-scanner agent to re-audit src/VulnerableShop.Api/Data/DapperOrderRepository.cs and confirm the previous findings are resolved
```

---

## 5. Use the agent on another repository

Copy the agent definition into the target repository:

```bash
Copy-Item .claude\agents\sql-injection-scanner.md C:\path\to\your-repo\.claude\agents\ -Force
```

Create the folder first if the target has no `.claude/agents`:

```bash
New-Item -ItemType Directory -Force -Path C:\path\to\your-repo\.claude\agents
```

Then open that repository in Claude Code and ask for the audit as above. The agent has no
dependency on this sample.

---

## 6. Verify the run

Score the report against [`verification/VERIFY.md`](verification/VERIFY.md) —
14 true positives, 5 decoys.

Confirm the agent modified nothing it audited:

```bash
git status --porcelain
```

Expect either empty output, or only the new file under `reports/`. **Any change under
`src/` is a hard fail.**

See exactly what changed, if anything did:

```bash
git diff --stat
```

Prove the source tree is byte-for-byte unchanged:

```bash
git diff --exit-code -- src
```

Exit code 0 means clean. Non-zero means the agent wrote to the code under audit, which
violates its own rules.

List generated reports:

```bash
Get-ChildItem reports -Filter *.md
```

---

## 7. Check determinism

The same codebase must produce the same report twice. Run the audit again in a second
fresh session, saving to a different name, then compare:

```bash
git diff --no-index reports\run-1.md reports\run-2.md
```

Finding IDs that appear, vanish, or reorder between runs mean the agent is leaning on
intuition where the rule table should be driving it.

---

## 8. Verify the seeded fixtures

Count the SQL sinks the sweep should find. Expect **14**:

```bash
(Get-ChildItem src -Recurse -Filter *.cs | Select-String -Pattern "FromSqlRaw|ExecuteSqlRaw|CommandText|QueryAsync|ExecuteAsync").Count
```

Note the `Get-ChildItem -Recurse` pipe rather than a `src\**\*.cs` path. Windows
PowerShell 5.1 does not expand `**` reliably — it silently matches only part of the tree,
which is worse than failing, because the count looks plausible.

Inspect the decisive decoy pair — unsafe `FromSqlRaw` on line 14, safe `FromSql` on
line 21:

```bash
Get-Content src\VulnerableShop.Api\Data\EfCoreCustomerRepository.cs | Select-Object -Skip 12 -First 12
```

Confirm no answer-key markers leaked into the sample. This must return **0**:

```bash
(Get-ChildItem src -Recurse -Filter *.cs | Select-String -CaseSensitive -Pattern "VULNERABLE|SQLI-|EXPECTED FINDING|DECOY").Count
```

`-CaseSensitive` is required. Without it, the `VulnerableShop` namespace matches
`VULNERABLE` on 26 lines and the check appears to fail when the fixture is fine.

Any genuine hit means the fixture is contaminated and the test is invalid.

---

## 9. Reset between runs

Delete generated reports:

```bash
Remove-Item reports\*.md -Force
```

Discard any accidental change to the sample app:

```bash
git checkout -- src
```

Clean build output:

```bash
dotnet clean VulnerableShop.sln
```

Remove `bin`/`obj` entirely if a build behaves strangely:

```bash
Get-ChildItem -Path src -Include bin,obj -Recurse -Directory | Remove-Item -Recurse -Force
```

---

## 10. Troubleshooting

**`NU1605` package downgrade**

EF Core 10 requires `Microsoft.Data.SqlClient` ≥ 6.1.1. Inspect the resolved graph:

```bash
dotnet list src\VulnerableShop.Api\VulnerableShop.Api.csproj package --include-transitive
```

**`Could not find solution or directory VulnerableShop.sln`**

.NET 10 creates `.slnx` by default. This repo uses classic `.sln`. If regenerating:

```bash
dotnet new sln -n VulnerableShop --format sln
```

```bash
dotnet sln VulnerableShop.sln add src\VulnerableShop.Api\VulnerableShop.Api.csproj
```

**The agent does not appear**

It is discovered relative to the folder you opened. Confirm the file is where Claude Code
expects it:

```bash
Get-ChildItem .claude\agents
```

Open the repository root itself, not a parent directory.

**Restore fails behind a proxy**

```bash
dotnet nuget list source
```

**Report was not written**

The agent needs `reports/` to exist:

```bash
New-Item -ItemType Directory -Force -Path reports
```

---

## Quick reference

| Task | Command |
|---|---|
| Check SDK | `dotnet --version` |
| Restore | `dotnet restore VulnerableShop.sln` |
| Build | `dotnet build VulnerableShop.sln` |
| Confirm EF1003 | `dotnet build VulnerableShop.sln --nologo 2>&1 \| Select-String "EF1003"` |
| Run audit | Ask in Claude Code: `Use the sql-injection-scanner agent to audit src/VulnerableShop.Api` |
| Prove source untouched | `git diff --exit-code -- src` |
| List reports | `Get-ChildItem reports -Filter *.md` |
| Reset reports | `Remove-Item reports\*.md -Force` |
| Clean | `dotnet clean VulnerableShop.sln` |
