<!--
  ILLUSTRATIVE SAMPLE — shows the report format only.

  The findings below come from a fictional "LegacyBilling" project that does not exist in
  this repository. They are deliberately NOT the seeded findings in src/VulnerableShop.Api,
  so this file can be read at any time without contaminating a scan run.
-->

# SQL Injection Audit — src/LegacyBilling.Api

Two endpoints let an unauthenticated caller restructure queries; one reaches a `DELETE`.
Fix issue 1 first — it is trivial and the highest severity.

**Total: 3 issues** — 1 critical, 1 high, 1 low · 2 cleared as safe

| # | Severity | Confidence | File:Line | Issue | Fix |
|---|---|---|---|---|---|
| 1 | Critical | High | `Data/InvoiceRepository.cs:41` | Invoice number concatenated into `DELETE` | Bind `@invoiceNo` |
| 2 | High | High | `Data/InvoiceRepository.cs:58` | Sort column concatenated into `ORDER BY` | Allow-list columns |
| 3 | Low | Medium | `Services/RetryService.cs:22` | Retry count spliced into `TOP`, currently `int` | Type the boundary |

**Stack:** net10.0 · Dapper 2.1 + raw ADO.NET · SQL Server · `[FromQuery]`, `[FromRoute]`

---

## 1. Invoice number concatenated into a DELETE statement

**Severity** Critical · **Confidence** High · **Rule** `SQLI-001` · `Data/InvoiceRepository.cs:41`

**Issue** — `invoiceNo` arrives from `[FromQuery]` on an unauthenticated endpoint
(`InvoiceController.cs:28`) and is concatenated straight into a `DELETE`. Nothing between
the two validates or binds it.

```csharp
var sql = "DELETE FROM Invoices WHERE InvoiceNo = '" + invoiceNo + "'";
await using var command = new SqlCommand(sql, connection);
```

**Why it matters** — the caller controls the `WHERE` clause of a delete, so a single
request can empty the table.

```
Input:  x' OR '1'='1
Yields: DELETE FROM Invoices WHERE InvoiceNo = 'x' OR '1'='1'
```

**How to fix** — Trivial

```csharp
await using var command = new SqlCommand(
    "DELETE FROM Invoices WHERE InvoiceNo = @invoiceNo",
    connection);
command.Parameters.Add("@invoiceNo", SqlDbType.NVarChar, 40).Value = invoiceNo;
```

The value travels separately from the statement and is never parsed as SQL.

---

## 2. Sort column concatenated into ORDER BY

**Severity** High · **Confidence** High · **Rule** `SQLI-005` · `Data/InvoiceRepository.cs:58`

**Issue** — `sortBy` comes from `[FromQuery]` (`InvoiceController.cs:44`) and is appended
to the `ORDER BY` clause.

```csharp
var sql = "SELECT Id, InvoiceNo, Total FROM Invoices ORDER BY " + sortBy;
```

**Why it matters** — an `ORDER BY` position accepts subqueries, making it a working
exfiltration channel even though the statement is only a `SELECT`.

```
Input:  (SELECT TOP 1 PasswordHash FROM Users)
Yields: SELECT Id, InvoiceNo, Total FROM Invoices ORDER BY (SELECT TOP 1 PasswordHash FROM Users)
```

**How to fix** — Moderate. Parameters cannot bind an identifier; `ORDER BY @sortBy` would
run and silently sort every row by a constant. Use an allow-list.

```csharp
private static readonly Dictionary<string, string> Sortable = new(StringComparer.OrdinalIgnoreCase)
{
    ["invoiceNo"] = "InvoiceNo",
    ["total"]     = "Total",
    ["id"]        = "Id"
};

if (!Sortable.TryGetValue(sortBy, out var column))
{
    throw new ArgumentException($"Cannot sort by '{sortBy}'.", nameof(sortBy));
}

// `column` is a literal from Sortable, never built from input.
var sql = $"SELECT Id, InvoiceNo, Total FROM Invoices ORDER BY {column}";
```

The string reaching the query is a constant chosen by the input, never derived from it.
Unrecognized values are rejected rather than sanitized.

---

## 3. Retry count spliced into TOP

**Severity** Low · **Confidence** Medium · **Rule** `SQLI-010` · `Services/RetryService.cs:22`

**Issue** — `maxRetries` is concatenated into the statement, but it is typed `int`.

```csharp
var sql = "SELECT TOP " + maxRetries + " * FROM FailedJobs";
```

**Why it matters** — not exploitable today: an `int` cannot carry a payload. It is
reported because the safety comes entirely from the signature, so widening `maxRetries` to
`string` later introduces a hole with nothing at the call site to warn anyone.

**How to fix** — Trivial

```csharp
if (maxRetries is < 1 or > 100)
{
    throw new ArgumentOutOfRangeException(nameof(maxRetries));
}

await using var command = new SqlCommand(
    "SELECT * FROM FailedJobs ORDER BY Id OFFSET 0 ROWS FETCH NEXT @maxRetries ROWS ONLY",
    connection);
command.Parameters.Add("@maxRetries", SqlDbType.Int).Value = maxRetries;
```

`OFFSET`/`FETCH` accept parameters where `TOP` does not. The bound check is about resource
limits, not injection.

---

## Cleared — reviewed, not vulnerable

| File:Line | Why it is safe |
|---|---|
| `Data/InvoiceRepository.cs:19` | Dapper `@CustomerId` with an anonymous parameter object |
| `Data/CustomerRepository.cs:33` | EF Core `FromSql` — interpolation holes are parameterized |

## Coverage

Scanned: `src/LegacyBilling.Api` (11 files) · Not examined: stored procedure bodies, not
visible from C#
Rule hits: SQLI-001: 4 · SQLI-002: 1 · SQLI-003: 3 · SQLI-004: 9 · SQLI-005: 1 ·
SQLI-006: 0 · SQLI-007: 0 · SQLI-008: 0 · SQLI-009: 6 · SQLI-010: 1 · SQLI-011: 2 ·
SQLI-012: 0
