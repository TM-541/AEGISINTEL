# Supported Sigma subset

AEGISINTEL evaluates a **documented subset** of the [Sigma](https://sigmahq.io/) rule format
in-process against normalized events. It does **not** claim full Sigma compatibility.
Rules that use anything outside this subset are **rejected at load time** with a reason shown
on the *Detections & ATT&CK* page. They are never partially evaluated.

Implementation: [`threatlens/integrations/sigma.py`](../threatlens/integrations/sigma.py) ·
Tests: [`tests/test_detection.py`](../tests/test_detection.py)

## Why not pySigma?
`pySigma` parses Sigma and converts it into backend query languages (Splunk, Elastic, …). It does
not execute rules against in-memory events, and AEGISINTEL has no SIEM backend. A small
evaluator behind a clear interface is easier to audit and test than a converter plus a query
engine. If a SIEM adapter is added later, pySigma would be the right tool for that adapter.

## Supported

| Area | Supported |
|---|---|
| Rule fields | `title`, `id` (must be a UUID), `status`, `description`, `author`, `logsource`, `detection`, `level`, `tags`, `falsepositives` |
| `level` | `informational`, `low`, `medium`, `high`, `critical` |
| `logsource` | `product: windows` (or omitted); `category: process_creation`, `authentication`, or omitted (= all events) |
| Selections | map of `field[|modifiers]: value` (keys AND-ed; list values OR-ed) or a list of such maps (OR) |
| `null` value | matches when the field is absent |
| Modifiers | `contains`, `startswith`, `endswith`, `all`, `re` (case-sensitive; add `i` for case-insensitive) |
| Wildcards | `*` and `?` in plain values |
| Conditions | selection names, `and`, `or`, `not`, parentheses, `1 of pattern*`, `all of pattern*`, `1 of them`, `all of them` |
| ATT&CK tags | `attack.tNNNN[.NNN]` tags are validated against the loaded ATT&CK dataset. A revoked or unknown ID rejects the rule |

String comparisons are case-insensitive, as the Sigma specification requires.

### Field mapping
Sigma field names map to normalized columns as follows. Any other field is looked up
case-insensitively in the original record.

| Sigma field | AEGISINTEL column |
|---|---|
| `Image` | `process_name` |
| `CommandLine` | `command_line` |
| `ParentImage` | `parent_process` |
| `User`, `TargetUserName` | `username` |
| `Computer`, `ComputerName` | `host` |
| `IpAddress`, `SourceIp` | `src_ip` |
| `DestinationIp` | `dest_ip` |
| `EventType` | `event_type` |
| `EventID` | original `EventID` / `event_id` / `event_type` value |

## Not supported (rejected)
- Aggregations and pipes (`| count() by ...`), `near`, `timeframe`
- Sigma correlation rules (meta-rules). Use the Python correlation rules instead
- Modifiers: `base64`, `base64offset`, `utf16*`, `wide`, `windash`, `cidr`, `exists`,
  `expand`, `fieldref`, `gt`/`lt` and friends
- Keyword (field-less) selections
- Placeholders and pipelines/processing items

## Interpreting results
A rule match means **the event matches a pattern** associated with a technique. It is not
proof that an attack happened. Every finding records the rule, the matched field values and
the supporting event IDs so an analyst can check it.

## Safety notes
- Rules are loaded with `yaml.safe_load`, so YAML tags such as `!!python/...` are rejected.
- Regular expressions are length-limited and compiled at load time. Python's `re` has no
  timeout, so rule files are a **trusted, admin-controlled input** (`rules/sigma/`). The
  application provides no upload path for rules.
