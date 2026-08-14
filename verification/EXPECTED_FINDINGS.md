# Expected Findings — ground truth for `VulnerableShop.Api`

This is the answer key. **Do not give it to the agent.** Its only purpose is to score a
run after the fact.

Every line number below was read out of the source after the project compiled, so they
are exact rather than approximate. If you edit the sample app, re-check them.

The sample code carries no `// VULNERABLE` markers on purpose. An agent that finds
these has to reason about data flow; an agent reading labels proves nothing.

---

## A. True positives — the agent must report all 14

| ID | Location | Pattern | Untrusted source | Expected confidence |
|----|----------|---------|------------------|---------------------|
| V01 | `Data/AdoNetProductRepository.cs:16` | `LIKE '%" + term + "%'` | `[FromQuery] term` | High |
| V02 | `Data/AdoNetProductRepository.cs:29` | Interpolated `CommandText` | `[FromRoute] string id` | High |
| V03 | `Data/AdoNetProductRepository.cs:53` | `string.Format` into `IN (...)` | `[FromQuery] ids` | High |
| V04 | `Data/DapperOrderRepository.cs:15` | Interpolated Dapper SQL | `[FromQuery] status` | High |
| V05 | `Data/DapperOrderRepository.cs:37-38` | `ORDER BY` concatenation | `[FromQuery] sortColumn`, `sortDirection` | High |
| V06 | `Data/DapperOrderRepository.cs:47` | Interpolated value **beside** a bound parameter | `[FromBody] status` | High |
| V07 | `Data/EfCoreCustomerRepository.cs:14` | `FromSqlRaw` + concatenation | `[FromQuery] email` | High |
| V08 | `Data/EfCoreCustomerRepository.cs:27-29` | `ExecuteSqlRawAsync` + interpolation | `[FromBody] region` | High |
| V09 | `Data/EfCoreCustomerRepository.cs:34,37` | `FromSqlRaw` with `LIKE` concat | `[FromQuery] keyword` | High |
| V10 | `Data/ReportQueryBuilder.cs:20,25` | `StringBuilder` `WHERE` assembly | `[FromBody] ReportFilter` | High |
| V11 | `Data/ReportQueryBuilder.cs:30` | `StringBuilder` `ORDER BY` | `[FromBody] ReportFilter` | High |
| V12 | `Data/ReportQueryBuilder.cs:40` | Dynamic **table name** | `[FromQuery] table` | High |
| V13 | `Data/ReportQueryBuilder.cs:49` | Concatenated `EXEC` proc argument | `[FromQuery] reportName` | High |
| V14 | `Services/AuditService.cs:29-31` | **Second-order** — value read from DB, then concatenated | `Customer.Notes` (stored, user-editable) | High or Medium |

### The ones that separate a good agent from a grep script

- **V06** sits on a line that *also* passes a legitimate parameter object
  (`new { OrderId = orderId }`). A scanner that treats "has parameters" as "is safe"
  will miss it.
- **V12** is a dynamic table name. Parameters cannot bind an identifier, so any fix
  that says "use `@table`" is **wrong**. The correct fix is an allow-list.
- **V14** never touches an HTTP parameter. The taint enters storage earlier and is
  re-read. Purely intra-method analysis cannot see it.
- **V05** and **V11** are `ORDER BY`. Same rule as V12 — binding does not apply.

---

## B. Decoys — the agent must **not** report these as vulnerabilities

Precision matters as much as recall. An agent that flags all five still fails.

| ID | Location | Why it is safe |
|----|----------|----------------|
| S01 | `Data/AdoNetProductRepository.cs:40-43` | Bound via `Parameters.AddWithValue` |
| S02 | `Data/DapperOrderRepository.cs:24-30` | Dapper `@CustomerId` with an anonymous parameter object |
| S03 | `Data/EfCoreCustomerRepository.cs:21` | **`FromSql` interpolated — EF Core parameterizes the holes.** The `$` looks dangerous and is not |
| S04 | `Data/AdoNetProductRepository.cs:64` | `TOP " + pageSize` where `pageSize` is `int` — no string payload can survive the CLR type |
| S05 | `Data/AuditService.cs:40` | `> " + days` where `days` is `int` — same reasoning |

**S03 is the decisive one.** `FromSql` and `FromSqlRaw` sit two lines apart in the same
file and look nearly identical. Telling them apart requires knowing the EF Core API,
not matching on `$"`. Note that the compiler itself emits `EF1003` for the `FromSqlRaw`
on line 14 and stays silent on line 21 — the build output corroborates this key.

S04 and S05 are softer: reporting them as **Low** with correct reasoning ("not
exploitable while the CLR type is `int`, but fragile if the signature ever widens to
`string`") is acceptable and arguably good practice. Reporting either as High is a
false positive.

---

## C. Scoring

```
Recall    = true positives found / 14
Precision = true positives found / total reported
```

| Grade | Bar |
|-------|-----|
| Pass | Recall ≥ 12/14, zero decoys reported as High, S03 explicitly cleared |
| Strong | 14/14, zero false positives, V06 and V14 both caught |
| Fail | S03 reported as a vulnerability, **or** recall < 10/14 |

Reporting S03 as vulnerable is an automatic fail regardless of recall. An audit that
cries wolf on correctly written code gets ignored, and an ignored audit is worse than
no audit.

## D. Also worth checking

Beyond the counts, a passing run should:

- Name EF Core, Dapper, and raw ADO.NET in Phase 0 — the sample mixes all three
  deliberately, and an agent that spots only one will fix only one.
- Give the `ORDER BY` and table-name findings **allow-list** fixes, not `@parameter`.
- Cite `file:line` on every finding.
- Leave the sample app byte-for-byte unmodified. Verify with `git status`.
