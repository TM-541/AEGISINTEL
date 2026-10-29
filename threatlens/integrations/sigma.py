"""A deliberately small, documented Sigma subset evaluator.

Supported (see docs/SIGMA_SUBSET.md):
* Rule fields: title, id, status, description, logsource, detection, level, tags, falsepositives
* logsource: product windows; category process_creation | authentication | (none = any)
* Selections: a map of ``field[|modifier...]: value | [values]`` (list = OR, map keys = AND),
  or a list of such maps (OR). ``null`` matches a missing field.
* Modifiers: contains, startswith, endswith, all, re (case-sensitive unless followed by ``i``)
* Conditions: identifiers, and, or, not, parentheses, ``1 of x*``, ``all of x*``,
  ``1 of them``, ``all of them``

Everything else, including aggregation pipes (``| count()``), ``near``, base64/windash/cidr
modifiers and correlation rules, is **rejected at load time**. It is not silently ignored.
String comparisons are case-insensitive, as Sigma specifies.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from threatlens.integrations.attack import AttackCatalog, UnknownTechniqueError

SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "all", "re", "i"}
LEVELS = {"informational", "low", "medium", "high", "critical"}
MAX_RULE_BYTES = 64 * 1024
MAX_REGEX_LEN = 256

# Sigma (Windows) field names → normalized event columns.
FIELD_MAP = {
    "image": "process_name",
    "commandline": "command_line",
    "parentimage": "parent_process",
    "user": "username",
    "targetusername": "username",
    "computer": "host",
    "computername": "host",
    "ipaddress": "src_ip",
    "sourceip": "src_ip",
    "destinationip": "dest_ip",
    "eventtype": "event_type",
    "message": "message",
}
LOGSOURCE_FILTERS: dict[str | None, Callable[[dict[str, Any]], bool]] = {
    None: lambda e: True,
    "process_creation": lambda e: e.get("event_type") == "process.create",
    "authentication": lambda e: e.get("category") == "authentication",
}


class SigmaRuleError(ValueError):
    pass


# --- matching primitives -----------------------------------------------------------------


@dataclass(frozen=True)
class FieldMatcher:
    field: str
    modifiers: tuple[str, ...]
    values: tuple[Any, ...]

    def _one(self, actual: str, expected: Any) -> bool:
        if "re" in self.modifiers:
            flags = re.IGNORECASE if "i" in self.modifiers else 0
            return re.search(str(expected), actual, flags) is not None
        a, e = actual.lower(), str(expected).lower()
        if "contains" in self.modifiers:
            return e in a
        if "startswith" in self.modifiers:
            return a.startswith(e)
        if "endswith" in self.modifiers:
            return a.endswith(e)
        return a == e if not any(c in e for c in "*?") else fnmatch.fnmatchcase(a, e)

    def match(self, event_view: dict[str, Any]) -> tuple[bool, Any]:
        actual = lookup(event_view, self.field)
        if self.values == (None,):
            return actual is None, None
        if actual is None:
            return False, None
        actual_s = str(actual)
        checks = [self._one(actual_s, v) for v in self.values if v is not None]
        ok = all(checks) if "all" in self.modifiers else any(checks)
        return ok, actual_s


def lookup(view: dict[str, Any], sigma_field: str) -> Any:
    key = sigma_field.lower()
    raw = view["_raw_lower"]
    if key == "eventid":
        return raw.get("eventid") or raw.get("event_id") or raw.get("event_type")
    if key in FIELD_MAP and view.get(FIELD_MAP[key]) is not None:
        return view[FIELD_MAP[key]]
    return raw.get(key)


@dataclass(frozen=True)
class Selection:
    name: str
    alternatives: tuple[tuple[FieldMatcher, ...], ...]  # OR of ANDs

    def match(self, view: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
        for group in self.alternatives:
            hits: dict[str, Any] = {}
            for matcher in group:
                ok, value = matcher.match(view)
                if not ok:
                    break
                hits[matcher.field] = value
            else:
                return True, hits
        return False, {}


# --- condition parser (recursive descent) -------------------------------------------------

_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*]+)")


def _tokenize(text: str) -> list[str]:
    if "|" in text:
        raise SigmaRuleError("aggregation conditions ('|') are not supported")
    pos, tokens = 0, []
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            if text[pos:].strip() == "":
                break
            raise SigmaRuleError(f"unexpected character in condition at {pos}")
        tokens.append(m.group(1))
        pos = m.end()
    return tokens


Node = Callable[[dict[str, tuple[bool, dict[str, Any]]]], tuple[bool, dict[str, Any]]]


class _ConditionParser:
    def __init__(self, tokens: list[str], names: list[str]) -> None:
        self.tokens = tokens
        self.i = 0
        self.names = names

    def peek(self) -> str | None:
        return self.tokens[self.i] if self.i < len(self.tokens) else None

    def take(self) -> str:
        tok = self.peek()
        if tok is None:
            raise SigmaRuleError("unexpected end of condition")
        self.i += 1
        return tok

    def parse(self) -> Node:
        node = self.parse_or()
        if self.peek() is not None:
            raise SigmaRuleError(f"unexpected token '{self.peek()}' in condition")
        return node

    def parse_or(self) -> Node:
        left = self.parse_and()
        while self.peek() == "or":
            self.take()
            left = _or(left, self.parse_and())
        return left

    def parse_and(self) -> Node:
        left = self.parse_not()
        while self.peek() == "and":
            self.take()
            left = _and(left, self.parse_not())
        return left

    def parse_not(self) -> Node:
        if self.peek() == "not":
            self.take()
            inner = self.parse_not()
            return lambda r: (not inner(r)[0], {})
        return self.parse_atom()

    def parse_atom(self) -> Node:
        tok = self.take()
        if tok == "(":
            node = self.parse_or()
            if self.take() != ")":
                raise SigmaRuleError("unbalanced parentheses")
            return node
        if tok in {"1", "all"}:
            if self.take() != "of":
                raise SigmaRuleError("expected 'of'")
            pattern = self.take()
            targets = (
                list(self.names)
                if pattern == "them"
                else [n for n in self.names if fnmatch.fnmatchcase(n, pattern)]
            )
            if not targets:
                raise SigmaRuleError(f"'{pattern}' matches no selection")
            return _quantifier(targets, require_all=(tok == "all"))
        if tok in self.names:
            return _ref(tok)
        raise SigmaRuleError(f"unknown identifier '{tok}' in condition")


def _ref(name: str) -> Node:
    def node(r: dict[str, tuple[bool, dict[str, Any]]]) -> tuple[bool, dict[str, Any]]:
        return r[name]

    return node


def _or(a: Node, b: Node) -> Node:
    def node(r):
        ra = a(r)
        return ra if ra[0] else b(r)

    return node


def _and(a: Node, b: Node) -> Node:
    def node(r):
        ra, rb = a(r), b(r)
        return (ra[0] and rb[0], {**ra[1], **rb[1]} if ra[0] and rb[0] else {})

    return node


def _quantifier(targets: list[str], *, require_all: bool) -> Node:
    def node(r):
        results = [r[t] for t in targets]
        ok = all(x[0] for x in results) if require_all else any(x[0] for x in results)
        hits: dict[str, Any] = {}
        for matched, h in results:
            if matched:
                hits.update(h)
        return ok, hits if ok else {}

    return node


# --- rules -------------------------------------------------------------------------------


@dataclass
class SigmaRule:
    id: str
    title: str
    level: str
    description: str
    logsource_category: str | None
    selections: dict[str, Selection]
    condition_text: str
    condition: Node
    techniques: list[str]
    falsepositives: list[str] = field(default_factory=list)
    source_path: str = ""
    version: str = ""  # "<modified|date|undated>+sha256:<12 hex of rule text>"

    def evaluate(self, view: dict[str, Any]) -> dict[str, Any] | None:
        if not LOGSOURCE_FILTERS[self.logsource_category](view):
            return None
        results = {name: sel.match(view) for name, sel in self.selections.items()}
        ok, hits = self.condition(results)
        return hits if ok else None


def _parse_matchers(name: str, block: Any) -> Selection:
    groups = block if isinstance(block, list) else [block]
    alternatives = []
    for group in groups:
        if not isinstance(group, dict) or not group:
            raise SigmaRuleError(f"selection '{name}': keyword lists are not supported")
        matchers = []
        for key, value in group.items():
            fname, *mods = str(key).split("|")
            unknown = set(mods) - SUPPORTED_MODIFIERS
            if unknown:
                raise SigmaRuleError(
                    f"selection '{name}': unsupported modifier(s) {sorted(unknown)}"
                )
            values = tuple(value) if isinstance(value, list) else (value,)
            if any(isinstance(v, dict | list) for v in values):
                raise SigmaRuleError(f"selection '{name}': nested values are not supported")
            if "re" in mods:
                for v in values:
                    if len(str(v)) > MAX_REGEX_LEN:
                        raise SigmaRuleError("regular expression too long")
                    try:
                        re.compile(str(v))
                    except re.error as exc:
                        raise SigmaRuleError(f"invalid regular expression: {exc}") from exc
            matchers.append(FieldMatcher(fname, tuple(mods), values))
        alternatives.append(tuple(matchers))
    return Selection(name, tuple(alternatives))


def parse_rule(text: str, catalog: AttackCatalog, *, source_path: str = "") -> SigmaRule:
    if len(text.encode("utf-8")) > MAX_RULE_BYTES:
        raise SigmaRuleError("rule file too large")
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise SigmaRuleError("invalid YAML") from exc
    if not isinstance(doc, dict):
        raise SigmaRuleError("rule must be a YAML mapping")
    for required in ("title", "id", "logsource", "detection", "level"):
        if required not in doc:
            raise SigmaRuleError(f"missing required field '{required}'")
    try:
        rule_id = str(uuid.UUID(str(doc["id"])))
    except ValueError as exc:
        raise SigmaRuleError("id must be a UUID") from exc
    level = str(doc["level"]).lower()
    if level not in LEVELS:
        raise SigmaRuleError(f"unsupported level '{level}'")
    logsource = doc["logsource"] or {}
    if logsource.get("product") not in (None, "windows"):
        raise SigmaRuleError("only product 'windows' is supported")
    category = logsource.get("category")
    if category not in LOGSOURCE_FILTERS:
        raise SigmaRuleError(f"unsupported logsource category '{category}'")

    detection = dict(doc["detection"] or {})
    if "timeframe" in detection:
        raise SigmaRuleError("'timeframe' is not supported")
    condition_text = detection.pop("condition", None)
    if not isinstance(condition_text, str):
        raise SigmaRuleError("detection.condition must be a single string")
    selections = {name: _parse_matchers(name, block) for name, block in detection.items()}
    condition = _ConditionParser(_tokenize(condition_text), list(selections)).parse()

    techniques = []
    for tag in doc.get("tags") or []:
        tag = str(tag).lower()
        if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", tag):
            tid = tag.removeprefix("attack.").upper()
            try:
                catalog.get(tid)
            except UnknownTechniqueError as exc:
                raise SigmaRuleError(f"tag {tid}: {exc}") from exc
            techniques.append(tid)

    return SigmaRule(
        id=rule_id,
        title=str(doc["title"])[:200],
        level=level,
        description=str(doc.get("description", ""))[:1000],
        logsource_category=category,
        selections=selections,
        condition_text=condition_text,
        condition=condition,
        techniques=techniques,
        falsepositives=[str(x) for x in doc.get("falsepositives") or []],
        source_path=source_path,
        version=f"{doc.get('modified') or doc.get('date') or 'undated'}"
        f"+sha256:{hashlib.sha256(text.encode('utf-8')).hexdigest()[:12]}",
    )


@dataclass
class RuleLoadResult:
    rules: list[SigmaRule]
    errors: list[tuple[str, str]]


def load_rules(directory: Path, catalog: AttackCatalog) -> RuleLoadResult:
    rules, errors, seen = [], [], set()
    for path in sorted(directory.glob("*.yml")):
        try:
            rule = parse_rule(path.read_text("utf-8"), catalog, source_path=path.name)
            if rule.id in seen:
                raise SigmaRuleError("duplicate rule id")
            seen.add(rule.id)
            rules.append(rule)
        except (SigmaRuleError, OSError, UnicodeDecodeError) as exc:
            errors.append((path.name, str(exc)))
    return RuleLoadResult(rules, errors)


def event_view(row: dict[str, Any]) -> dict[str, Any]:
    """Normalized columns + lower-cased raw keys, for field lookup."""
    view = dict(row)
    try:
        raw = json.loads(row.get("raw_json") or "{}")
    except ValueError:
        raw = {}
    view["_raw_lower"] = (
        {str(k).lower(): v for k, v in raw.items()} if isinstance(raw, dict) else {}
    )
    return view
