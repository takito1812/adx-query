# adx-query

`adx-query` is a lightweight offline LDAP query engine for Sysinternals **ADExplorer** snapshots (`*.dat`). It lets you run real RFC‑4515 LDAP filters directly against a snapshot without touching a live domain controller.

In practice, it behaves like a passive `ldapsearch`: fast, silent, and ideal for Red Team operators, and large AD enumerations where direct LDAP queries would be noisy or monitored.

Unlike tools that convert snapshots or extract only a subset of attributes (e.g., scripts built for BloodHound preprocessing), `adx-query` preserves **all LDAP attributes** present in the ADExplorer file and streams them on demand.

## Key Features

- Streaming binary reader (`dat_reader.py`) with GUID/SID decoding.
- RFC 4515 filter parser (`filter_engine.py`) supporting equality, presence, substring, AND/OR/NOT, case-insensitive comparisons, and DN helpers.
- Query engine (`query_engine.py`) with optional result limits and benchmark statistics.
- Output utilities (`formatters.py`) for table (default), JSON, CSV, and Excel (with native filtering enabled).

## Requirements

- Python **3.9+**
- `openpyxl` (installed via `requirements.txt`)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Example Usage

```bash
python adx_query.py \
  --snapshot ./snapshot.dat \
  --filter "(&(objectClass=user)(company=1234)(streetAddress=HQ-*))" \
  --attributes distinguishedName sAMAccountName mail \
  --format excel \
  --limit 20 \
  --benchmark \
  --output results.xlsx
```

> Excel output requires `--output` with an `.xlsx` path. The workbook includes a formatted table with built‑in filters.

### Command Line Options

- `--snapshot PATH` - path to the ADExplorer snapshot.
- `--filter FILTER` - LDAP filter (RFC 4515).
- `--attributes ATTR ...` - optional list of attributes to include.
- `--format {table,json,csv,excel}` - output format (default: `table`).
- `--limit N` - maximum number of returned entries.
- `--ignore-case` - perform case‑insensitive comparisons.
- `--benchmark` - show evaluation stats.
- `--dump-header` - display snapshot metadata.
- `--output FILE` - write results to a file.

## Handy Filters

| Purpose | Filter |
|---------|--------|
| All user objects | `(objectClass=user)` |
| Users in company 1234 with addresses starting `HQ-` | `(&(objectClass=user)(company=1234)(streetAddress=HQ-*))` |
| Objects with mail or `sAMAccountName` starting with `A` | `(\|(mail=*)(sAMAccountName=A*))` |
| Objects not in a given company | `(!(company=AcmeCorp))` |
| Entries with a street address | `(streetAddress=*)` |

## Notes

- Table output adjusts column widths; for very large outputs, CSV/JSON may be faster.
- Excel export uses `openpyxl` and includes native filtering.
- Unknown binary attributes are displayed as hexadecimal.
- Future ADExplorer format changes may require small adjustments to the parser.

If this tool helps you, feel free to open issues or submit improvements.
