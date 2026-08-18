# Remediation Guide — SQL Injection in .NET

For each pattern the scanner reports: what the issue is, why it matters, and how to fix
it.

**Organized by pattern, not by file, on purpose.** A guide listing line numbers would be
a second answer key and would contaminate a scan run. This one is safe to keep open
while auditing, and it transfers to any codebase.

CWE-89 · OWASP Top 10 A03:2021 Injection

---

## Contents

| # | Pattern | Rules | Fix |
|---|---|---|---|
| [1](#1-concatenation-into-command-text) | Concatenation into command text | `SQLI-001` `SQLI-004` | Bind a parameter |
| [2](#2-string-interpolation-into-raw-sql) | Interpolation into raw SQL | `SQLI-001` `SQLI-002` | Bind, or switch to `FromSql` |
| [3](#3-ef-core-fromsqlraw-and-executesqlraw) | EF Core `FromSqlRaw` / `ExecuteSqlRaw` | `SQLI-002` | Use `FromSql` / `ExecuteSql` |
| [4](#4-dapper-with-concatenated-sql) | Dapper with concatenated SQL | `SQLI-003` | Anonymous parameter object |
| [5](#5-dynamic-order-by) | Dynamic `ORDER BY` | `SQLI-005` | **Allow-list** |
| [6](#6-like-wildcards-by-concatenation) | `LIKE` wildcards by concatenation | `SQLI-006` | Bind + escape wildcards |
| [7](#7-indirect-assembly-stringformat-stringbuilder) | `string.Format` / `StringBuilder` | `SQLI-007` | Bind per branch |
| [8](#8-dynamic-table-or-column-names) | Dynamic table/column names | `SQLI-008` | **Allow-list** |
| [9](#9-paging-values-spliced-into-text) | `TOP` / `OFFSET` spliced in | `SQLI-010` | Bind, or validate as int |
| [10](#10-in-clause-from-a-csv-string) | `IN (...)` from a CSV string | `SQLI-004` | Parse + bind each |
| [11](#11-stored-procedure-misuse) | Stored procedure misuse | `SQLI-012` | `CommandType.StoredProcedure` |
| [12](#12-second-order-injection) | Second-order injection | `SQLI-004` | Bind on **every** read |

Two rules cover most of this document:

> **Values get bound. Identifiers get allow-listed.**
> If it is a value — a name, an email, a date, a number — pass it as a parameter.
> If it is *part of the query's structure* — a column, a table, a sort direction —
> parameters cannot help. Map the input to a fixed set of known-good identifiers.

---

## 1. Concatenation into command text

**Issue.** User input is joined into the SQL string, so the input can close a quote and
append its own clauses.

**Why it matters.** The attacker controls query structure, not just data. Depending on
the statement and the connection's privileges this yields data disclosure, modification,
or destruction.

**Vulnerable**
```csharp
var sql = "SELECT Id, Name FROM Products WHERE Category = '" + category + "'";
await using var command = new SqlCommand(sql, connection);
```

Input `x' OR '1'='1` returns every row. Input `x'; DROP TABLE Products--` does worse.

**Fixed**
```csharp
await using var command = new SqlCommand(
    "SELECT Id, Name FROM Products WHERE Category = @category",
    connection);
command.Parameters.Add("@category", SqlDbType.NVarChar, 100).Value = category;
```

**Why it holds.** The value travels to the server separately from the statement. It is
never parsed as SQL, so quotes in it are just characters.

**Note.** `Parameters.Add` with an explicit type is preferable to `AddWithValue`, which
infers the type from the value and can cause implicit conversions that discard an index.
Both are safe from injection; only one is predictable for performance.

---

## 2. String interpolation into raw SQL

**Issue.** `$"..."` is not safer than `+`. It compiles to the same concatenation.

**Why it matters.** Interpolation reads as modern and deliberate, so it survives review
more often than `+` does.

**Vulnerable**
```csharp
command.CommandText = $"SELECT * FROM Products WHERE Id = {id}";
```

Unquoted numeric context is *worse*, not better — the attacker needs no quote to escape.
`1; DELETE FROM Products--` is enough. This is a real risk whenever the parameter is
typed `string`.

**Fixed**
```csharp
command.CommandText = "SELECT * FROM Products WHERE Id = @id";
command.Parameters.Add("@id", SqlDbType.Int).Value = id;
```

Better still, take the right type at the boundary so the value can never be a payload:

```csharp
public async Task<Product?> GetByIdAsync(int id, CancellationToken cancellationToken)
```

**Why it holds.** An `int` parameter cannot carry SQL. Typing the boundary correctly
removes the class of bug rather than patching one instance.

---

## 3. EF Core `FromSqlRaw` and `ExecuteSqlRaw`

**Issue.** The `Raw` variants pass your string through untouched. The non-`Raw` variants
parameterize interpolation holes.

**Why it matters.** This is the most misread pair in EF Core, in both directions —
`FromSql` gets "fixed" unnecessarily, and `FromSqlRaw` gets waved through because it
"has an interpolated string, so it's parameterized."

**Vulnerable**
```csharp
_dbContext.Customers.FromSqlRaw("SELECT * FROM Customers WHERE Email = '" + email + "'")
_dbContext.Database.ExecuteSqlRaw($"UPDATE Customers SET IsActive = 0 WHERE Region = '{region}'")
```

**Safe — do not "fix" this**
```csharp
_dbContext.Customers.FromSql($"SELECT * FROM Customers WHERE City = {city}")
```

`FromSql` turns each hole into a `DbParameter`. Note there are no quotes around `{city}`
— adding them would break it, because the parameter supplies its own quoting.

**Fixed**
```csharp
_dbContext.Customers.FromSql($"SELECT * FROM Customers WHERE Email = {email}")

_dbContext.Database.ExecuteSql($"UPDATE Customers SET IsActive = 0 WHERE Region = {region}")
```

**How to tell them apart.** Judge by the **method name**, never by the `$`:

| Method | Interpolation | Verdict |
|---|---|---|
| `FromSql` | Parameterized | Safe |
| `FromSqlInterpolated` | Parameterized | Safe (older name for the same thing) |
| `FromSqlRaw` | Inserted literally | Unsafe with any untrusted input |
| `ExecuteSql` | Parameterized | Safe |
| `ExecuteSqlRaw` | Inserted literally | Unsafe with any untrusted input |

**The compiler helps.** `FromSqlRaw` with a concatenated argument raises **EF1003**.
Do not suppress it project-wide.

**When you genuinely need `Raw`** — a dynamic identifier — combine it with an allow-list
(§5, §8) and pass values as explicit `SqlParameter`s alongside.

---

## 4. Dapper with concatenated SQL

**Issue.** Dapper parameterizes willingly, but only for the values you actually hand it.

**Why it matters.** A call can bind one value and concatenate another on the same line.
The presence of a parameter object makes it *look* handled, so this survives review well.

**Vulnerable**
```csharp
var sql = $"SELECT * FROM Orders WHERE Status = '{status}'";
return await connection.QueryAsync<Order>(sql);
```

**Vulnerable, and easy to miss** — one value bound, one concatenated:
```csharp
var sql = $"UPDATE Orders SET Status = '{newStatus}' WHERE Id = @OrderId";
return await connection.ExecuteAsync(sql, new { OrderId = orderId });
```

**Fixed**
```csharp
const string sql = """
    SELECT Id, CustomerId, Status, PlacedOn, Total
    FROM Orders
    WHERE Status = @Status
    """;

return await connection.QueryAsync<Order>(sql, new { Status = status });
```

**Why it holds.** Dapper turns each property of the anonymous object into a
`DbParameter`.

**Review heuristic.** `const string` for SQL is a useful convention: a constant cannot be
concatenated with a runtime value, so the compiler enforces what review would otherwise
have to catch.

---

## 5. Dynamic `ORDER BY`

**Issue.** A sort column arrives from the caller and is concatenated in.

**Why it matters.** **Parameters cannot fix this.** `ORDER BY @column` sorts every row by
a constant string — it runs, returns wrong results, and looks like it worked. This is the
single most common bogus "fix" in SQL injection remediation.

**Vulnerable**
```csharp
var sql = "SELECT * FROM Orders ORDER BY " + sortColumn + " " + sortDirection;
```

An `ORDER BY` position is also a working exfiltration channel via subqueries, even when
the surrounding query is otherwise locked down.

**Fixed — map input to identifiers you wrote**
```csharp
private static readonly Dictionary<string, string> SortableColumns = new(StringComparer.OrdinalIgnoreCase)
{
    ["placedOn"] = "PlacedOn",
    ["total"]    = "Total",
    ["status"]   = "Status",
    ["id"]       = "Id"
};

public async Task<IEnumerable<Order>> GetSortedAsync(string sortColumn, string sortDirection)
{
    if (!SortableColumns.TryGetValue(sortColumn, out var column))
    {
        throw new ArgumentException($"Cannot sort by '{sortColumn}'.", nameof(sortColumn));
    }

    var direction = sortDirection.Equals("desc", StringComparison.OrdinalIgnoreCase)
        ? "DESC"
        : "ASC";

    var sql = $"SELECT Id, CustomerId, Status, PlacedOn, Total FROM Orders ORDER BY {column} {direction}";

    return await connection.QueryAsync<Order>(sql);
}
```

**Why it holds.** The string reaching the query is a literal from the dictionary, chosen
by the input but never built from it. Unrecognized input is rejected, not sanitized —
allow-list, never deny-list.

The interpolation on the final line is safe *because* `column` and `direction` provably
originate from constants in this file. Add a comment saying so, or the next reader will
"fix" it.

**Alternative.** Sort in LINQ with EF Core (`IQueryable.OrderBy` over a mapped
expression), and no raw SQL is involved.

---

## 6. `LIKE` wildcards by concatenation

**Issue.** A search term is concatenated between wildcards.

**Why it matters.** Two separate problems. Injection, plus an availability issue:
unescaped `%` from a caller turns a targeted search into a full scan.

**Vulnerable**
```csharp
var sql = "SELECT * FROM Products WHERE Name LIKE '%" + term + "%'";
```

**Fixed**
```csharp
await using var command = new SqlCommand(
    "SELECT Id, Name FROM Products WHERE Name LIKE @term ESCAPE '\\'",
    connection);

var escaped = term
    .Replace("\\", "\\\\")
    .Replace("%", "\\%")
    .Replace("_", "\\_")
    .Replace("[", "\\[");

command.Parameters.Add("@term", SqlDbType.NVarChar, 200).Value = $"%{escaped}%";
```

**Why it holds.** Wildcards belong to the *value*, so they go in the parameter, not the
statement. `ESCAPE` plus escaping neutralizes caller-supplied wildcards.

**Behavioral note.** This changes results: previously a user searching `50%` matched
anything containing `50`; now it matches a literal `50%`. That is the correct behavior,
but it *is* a change — flag it, and check for tests asserting the old behavior.

---

## 7. Indirect assembly (`string.Format`, `StringBuilder`)

**Issue.** The query is assembled in pieces, so no single line looks wrong.

**Why it matters.** Grep-based tools miss this because the SQL literal and the untrusted
value are on different lines. Conditional filter builders are where it usually lives.

**Vulnerable**
```csharp
var sql = new StringBuilder("SELECT * FROM OrderSummary WHERE 1 = 1");

if (!string.IsNullOrWhiteSpace(filter.Category))
{
    sql.Append(" AND Category = '").Append(filter.Category).Append('\'');
}
```

**Fixed — build placeholders, collect parameters**
```csharp
var sql = new StringBuilder("SELECT * FROM OrderSummary WHERE 1 = 1");
var parameters = new DynamicParameters();

if (!string.IsNullOrWhiteSpace(filter.Category))
{
    sql.Append(" AND Category = @Category");
    parameters.Add("@Category", filter.Category);
}

if (!string.IsNullOrWhiteSpace(filter.Region))
{
    sql.Append(" AND Region = @Region");
    parameters.Add("@Region", filter.Region);
}

return await connection.QueryAsync(sql.ToString(), parameters);
```

**Why it holds.** Dynamic *shape* is fine. Only the placeholder name is concatenated;
values go through `DynamicParameters`.

**Bonus.** This also improves plan reuse — the previous version produced a distinct query
text per input, poisoning the plan cache.

---

## 8. Dynamic table or column names

**Issue.** A table or schema name comes from the caller.

**Why it matters.** Like `ORDER BY`, **parameters cannot bind an identifier**. It also
usually indicates a design problem: an endpoint exposing arbitrary table names is an
authorization hole even without injection, since it bypasses per-entity checks.

**Vulnerable**
```csharp
var sql = $"SELECT TOP {rowLimit} * FROM {tableName}";
```

**Fixed — expose report names, not table names**
```csharp
private static readonly Dictionary<string, string> ExportableTables = new(StringComparer.OrdinalIgnoreCase)
{
    ["orders"]    = "dbo.OrderSummary",
    ["products"]  = "dbo.Products",
    ["customers"] = "dbo.CustomerPublic"
};

public async Task<IEnumerable<dynamic>> ExportAsync(string dataset, int rowLimit)
{
    if (!ExportableTables.TryGetValue(dataset, out var table))
    {
        throw new ArgumentException($"Unknown dataset '{dataset}'.", nameof(dataset));
    }

    if (rowLimit is < 1 or > 10_000)
    {
        throw new ArgumentOutOfRangeException(nameof(rowLimit));
    }

    // `table` is a constant from ExportableTables; `rowLimit` is a validated int.
    var sql = $"SELECT TOP {rowLimit} * FROM {table}";

    return await connection.QueryAsync(sql);
}
```

**Why it holds.** The caller picks from a set you defined. They never name a table, so
they cannot reach one you did not intend — including views that exist to hide columns.

**Do not** try to sanitize identifiers by escaping or bracket-quoting. `QUOTENAME` is
better than nothing but still permits any table the connection can see, which leaves the
authorization problem intact.

---

## 9. Paging values spliced into text

**Issue.** `TOP`, `OFFSET`, or `FETCH` values concatenated into the statement.

**Why it matters.** Severity depends entirely on the CLR type, which is why this needs
judgment rather than a blanket rule.

**Not exploitable today, but fragile**
```csharp
var sql = "SELECT TOP " + pageSize + " * FROM Products";   // pageSize is int
```

An `int` cannot carry a payload. There is no injection here — reporting it as a
vulnerability is a false positive. But the safety comes from the signature, so widening
`pageSize` to `string` later silently introduces a hole, with nothing at the call site to
warn you.

**Genuinely vulnerable**
```csharp
var sql = "SELECT TOP " + pageSize + " * FROM Products";   // pageSize is string
```

**Fixed**
```csharp
if (pageSize is < 1 or > 500)
{
    throw new ArgumentOutOfRangeException(nameof(pageSize));
}

await using var command = new SqlCommand(
    "SELECT * FROM Products ORDER BY Id OFFSET 0 ROWS FETCH NEXT @pageSize ROWS ONLY",
    connection);
command.Parameters.Add("@pageSize", SqlDbType.Int).Value = pageSize;
```

**Why it holds.** `OFFSET`/`FETCH` accept parameters, unlike `TOP` in older syntax. The
bound check is about resource exhaustion, not injection.

---

## 10. `IN (...)` from a CSV string

**Issue.** A comma-separated list is dropped straight into an `IN` clause.

**Why it matters.** Frequently a `DELETE` or `UPDATE`, so severity is high. Developers
reach for concatenation here because parameterizing a variable-length list is genuinely
awkward.

**Vulnerable**
```csharp
var sql = string.Format("DELETE FROM Products WHERE Id IN ({0})", csvIds);
```

**Fixed — parse, then bind each element**
```csharp
public async Task<int> DeleteManyAsync(string csvIds, CancellationToken cancellationToken)
{
    var ids = csvIds
        .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .Select(part => int.TryParse(part, out var value) ? value : (int?)null)
        .ToArray();

    if (ids.Length == 0 || ids.Any(id => id is null))
    {
        throw new ArgumentException("Ids must be a comma-separated list of integers.", nameof(csvIds));
    }

    if (ids.Length > 500)
    {
        throw new ArgumentException("Cannot delete more than 500 products at once.", nameof(csvIds));
    }

    var names = ids.Select((_, i) => $"@id{i}").ToArray();

    await using var command = new SqlCommand(
        $"DELETE FROM Products WHERE Id IN ({string.Join(", ", names)})",
        connection);

    for (var i = 0; i < ids.Length; i++)
    {
        command.Parameters.Add($"@id{i}", SqlDbType.Int).Value = ids[i]!.Value;
    }

    return await command.ExecuteNonQueryAsync(cancellationToken);
}
```

**Why it holds.** Only generated placeholder names are concatenated. Every value is
bound, and each was proven to be an integer before reaching the query.

**With Dapper** it is one line, because Dapper expands a collection itself:
```csharp
await connection.ExecuteAsync("DELETE FROM Products WHERE Id IN @Ids", new { Ids = ids });
```

**With EF Core**, prefer no raw SQL at all:
```csharp
await _dbContext.Products.Where(p => ids.Contains(p.Id)).ExecuteDeleteAsync(cancellationToken);
```

---

## 11. Stored procedure misuse

**Issue.** A procedure is invoked by building an `EXEC` string.

**Why it matters.** Calling a procedure is widely believed to be inherently safe. It is
not — if you build the call by concatenation, you have injection before the procedure
runs. And a procedure that itself concatenates into `sp_executesql` is vulnerable no
matter how carefully you call it.

**Vulnerable**
```csharp
var sql = "EXEC sp_RunReport '" + reportName + "'";
return await connection.QueryAsync(sql);
```

**Fixed**
```csharp
await using var command = new SqlCommand("sp_RunReport", connection)
{
    CommandType = CommandType.StoredProcedure
};
command.Parameters.Add("@reportName", SqlDbType.NVarChar, 100).Value = reportName;
```

**Why it holds.** With `CommandType.StoredProcedure` the driver sends an RPC call with
typed arguments. There is no statement text for input to break out of.

**Also review the procedure body.** If it contains `EXEC(@sql)` or `sp_executesql` over a
concatenated string, the vulnerability is inside the database and this C# fix does not
reach it. That is outside the scanner's visibility, so it needs a manual check.

---

## 12. Second-order injection

**Issue.** A value is stored safely, then read back later and concatenated into a new
query.

**Why it matters.** The dangerous line contains no HTTP parameter, so it looks like it
operates on trusted internal data. Storage is not a sanitizer — it is a delay. The write
path being parameterized is exactly what makes this easy to miss: the payload sits in the
table until something concatenates it.

**Vulnerable**
```csharp
var customer = await _dbContext.Customers
    .FirstOrDefaultAsync(c => c.Id == customerId, cancellationToken);

var sql = "INSERT INTO AuditLog (CustomerId, Detail) VALUES ("
          + customer.Id
          + ", '" + customer.Notes + "')";
```

`Notes` is user-editable. A profile saved with `', 1); DROP TABLE AuditLog--` executes
whenever reconciliation runs — asynchronously, under whatever privileges the background
job holds, with no request to correlate it to.

**Fixed**
```csharp
await using var command = new SqlCommand(
    "INSERT INTO AuditLog (CustomerId, Detail) VALUES (@customerId, @detail)",
    connection);
command.Parameters.Add("@customerId", SqlDbType.Int).Value = customer.Id;
command.Parameters.Add("@detail", SqlDbType.NVarChar, -1).Value = customer.Notes;
```

**Why it holds.** Binding does not care where a value came from. That is the point: it
removes the need to track trust across time.

**The rule.** Treat any value that ever left your process as untrusted when it comes
back, including from your own database, cache, message queue, or config. "Where did this
come from?" is a question you will eventually get wrong; binding every value means you
never have to ask.

---

## Verification checklist

After applying fixes:

- [ ] `dotnet build` is clean, with no **EF1003** and no `#pragma warning disable` added
      to hide one.
- [ ] Every `ORDER BY`, table-name, and column-name fix uses an allow-list — grep the
      diff for `ORDER BY @` and `FROM @`, which do not work.
- [ ] Tests cover a rejected allow-list value, not only accepted ones.
- [ ] `LIKE` behavior change reviewed against existing search tests (§6).
- [ ] Re-run the scanner; the fixed findings should appear under **Cleared**, not vanish
      silently.

## Defense in depth

Parameterizing is the fix. These reduce the damage when something is missed:

- **Least privilege.** The application's SQL login should not own the schema. A
  `DROP TABLE` that succeeds is a permissions failure as much as an injection one.
- **No error detail to callers.** Return a generic problem response; log the exception
  server-side. Detailed errors turn a blind hole into a guided one.
- **Views instead of base tables** for reporting, so a mistake exposes only intended
  columns.
- **Treat EF1003 as an error** in CI once the existing findings are cleared:
  `<WarningsAsErrors>$(WarningsAsErrors);EF1003</WarningsAsErrors>`.
- **Query timeouts and row caps**, so a `UNION`-based dump is throttled.

None of these prevent injection. They keep a single missed line from becoming a breach.
