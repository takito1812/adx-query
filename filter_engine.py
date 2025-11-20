"""
LDAP filter parser and evaluator tailored for ADExplorer snapshot queries.

The parser supports the subset required by RFC 4515 for:
 - Equality match (attr=value)
 - Presence (attr=*)
 - Substring matching (attr=pre*mid*suf)
 - Boolean operators: AND, OR, NOT

Filter values honour hexadecimal escapes (\\xx) and allow literal asterisks via
the \\2a escape sequence.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Iterator, List, Optional, Sequence

from dat_reader import PropertyDefinition, SnapshotEntry, SnapshotReader


class FilterSyntaxError(ValueError):
    pass


@dataclass
class FilterValue:
    raw: bytes

    def as_bytes(self) -> bytes:
        return self.raw

    def as_str(self) -> str:
        try:
            return self.raw.decode("utf-8")
        except UnicodeDecodeError:
            return self.raw.decode("latin-1", errors="ignore")


@dataclass
class SubstringPattern:
    initial: Optional[str]
    any: List[str]
    final: Optional[str]

    def normalised(self, casefold: bool) -> "SubstringPattern":
        if not casefold:
            return self
        return SubstringPattern(
            initial=self.initial.casefold() if self.initial is not None else None,
            any=[segment.casefold() for segment in self.any],
            final=self.final.casefold() if self.final is not None else None,
        )

    def matches(self, candidate: str) -> bool:
        pos = 0
        if self.initial is not None:
            if not candidate.startswith(self.initial):
                return False
            pos = len(self.initial)

        for segment in self.any:
            idx = candidate.find(segment, pos)
            if idx == -1:
                return False
            pos = idx + len(segment)

        if self.final is not None:
            return candidate.endswith(self.final)

        return True


@dataclass
class EvaluationContext:
    reader: SnapshotReader
    entry: SnapshotEntry
    ignore_case: bool

    def get_property(self, attr: str) -> Optional[PropertyDefinition]:
        return self.reader.get_property(attr)


class FilterNode:
    def evaluate(self, ctx: EvaluationContext) -> bool:  # pragma: no cover - overridden
        raise NotImplementedError


def _extract_rdn_value(dn: str) -> Optional[str]:
    if "=" not in dn:
        return None
    first = dn.split(",", 1)[0]
    if "=" not in first:
        return None
    return first.split("=", 1)[1].strip()


class AndNode(FilterNode):
    def __init__(self, nodes: Sequence[FilterNode]):
        self.nodes = list(nodes)

    def evaluate(self, ctx: EvaluationContext) -> bool:
        return all(node.evaluate(ctx) for node in self.nodes)


class OrNode(FilterNode):
    def __init__(self, nodes: Sequence[FilterNode]):
        self.nodes = list(nodes)

    def evaluate(self, ctx: EvaluationContext) -> bool:
        return any(node.evaluate(ctx) for node in self.nodes)


class NotNode(FilterNode):
    def __init__(self, node: FilterNode):
        self.node = node

    def evaluate(self, ctx: EvaluationContext) -> bool:
        return not self.node.evaluate(ctx)


class PresenceNode(FilterNode):
    def __init__(self, attr: str):
        self.attr = attr

    def evaluate(self, ctx: EvaluationContext) -> bool:
        prop = ctx.get_property(self.attr)
        if prop is None:
            return False
        try:
            values = ctx.entry.get_attribute_values(prop.name)
        except KeyError:
            return False
        return len(values) > 0


class EqualityNode(FilterNode):
    def __init__(self, attr: str, value: FilterValue):
        self.attr = attr
        self.value = value

    def evaluate(self, ctx: EvaluationContext) -> bool:
        prop = ctx.get_property(self.attr)
        if prop is None:
            return False

        try:
            values = ctx.entry.get_attribute_values(prop.name)
        except KeyError:
            return False

        typed_value = self._prepare_value(values, self.value)
        if typed_value is None:
            return False

        for candidate in values:
            if self._compare(candidate, typed_value):
                return True
        return False

    @staticmethod
    def _prepare_value(sample_values: Sequence[object], needle: FilterValue):
        sample = sample_values[0] if sample_values else None

        if isinstance(sample, bool):
            raw = needle.as_str().lower()
            if raw in {"true", "1"}:
                return True
            if raw in {"false", "0"}:
                return False
            return None

        if isinstance(sample, int):
            try:
                return int(needle.as_str(), 0)
            except ValueError:
                return None

        if isinstance(sample, bytes):
            return needle.as_bytes()

        return needle.as_str().casefold()

    @staticmethod
    def _compare(value: object, needle: object) -> bool:
        if needle is None:
            return False

        if isinstance(value, bool) and isinstance(needle, bool):
            return value is needle

        if isinstance(value, int) and isinstance(needle, int):
            return value == needle

        if isinstance(value, bytes) and isinstance(needle, bytes):
            return value == needle

        value_str = str(value)
        value_norm = value_str.casefold()
        needle_norm = str(needle).casefold()
        if value_norm == needle_norm:
            return True

        rdn = _extract_rdn_value(value_str)
        if rdn is not None and rdn.casefold() == needle_norm:
            return True

        return False


class SubstringNode(FilterNode):
    def __init__(self, attr: str, pattern: SubstringPattern):
        self.attr = attr
        self.pattern = pattern

    def evaluate(self, ctx: EvaluationContext) -> bool:
        prop = ctx.get_property(self.attr)
        if prop is None:
            return False

        try:
            values = ctx.entry.get_attribute_values(prop.name)
        except KeyError:
            return False

        if not values:
            return False

        pattern = self.pattern.normalised(True)
        for value in values:
            if not isinstance(value, str):
                value = str(value)
            candidate = value.casefold()
            if pattern.matches(candidate):
                return True
        return False


class Parser:
    def __init__(self, data: str):
        self.data = data
        self.length = len(data)
        self.pos = 0

    def parse(self) -> FilterNode:
        node = self._parse_filter()
        self._skip_spaces()
        if self.pos != self.length:
            raise FilterSyntaxError("Unexpected trailing characters in filter")
        return node

    # -- parsing helpers ---------------------------------------------------------

    def _parse_filter(self) -> FilterNode:
        self._skip_spaces()
        self._expect("(")
        self._skip_spaces()

        ch = self._peek()
        if ch == "&":
            self._consume()
            nodes = []
            while True:
                self._skip_spaces()
                if self._peek() != "(":
                    break
                nodes.append(self._parse_filter())
            self._expect(")")
            if not nodes:
                raise FilterSyntaxError("Empty AND expression")
            return AndNode(nodes)

        if ch == "|":
            self._consume()
            nodes = []
            while True:
                self._skip_spaces()
                if self._peek() != "(":
                    break
                nodes.append(self._parse_filter())
            self._expect(")")
            if not nodes:
                raise FilterSyntaxError("Empty OR expression")
            return OrNode(nodes)

        if ch == "!":
            self._consume()
            node = self._parse_filter()
            self._expect(")")
            return NotNode(node)

        attr = self._parse_attribute()
        self._expect("=")
        segments, star_count = self._parse_value_segments()

        if star_count == 1 and segments == [b"", b""]:
            self._expect(")")
            return PresenceNode(attr)

        if star_count >= 1:
            pattern = self._build_substring_pattern(attr, segments)
            self._expect(")")
            return SubstringNode(attr, pattern)

        value = FilterValue(segments[0])
        self._expect(")")
        return EqualityNode(attr, value)

    def _parse_attribute(self) -> str:
        start = self.pos
        while self.pos < self.length:
            ch = self.data[self.pos]
            if ch in "=~><":
                break
            if ch == "(":
                break
            self.pos += 1
        if start == self.pos:
            raise FilterSyntaxError("Missing attribute name")
        return self.data[start:self.pos].strip()

    def _parse_value_segments(self) -> (List[bytes], int):
        segments: List[bytes] = []
        buf = bytearray()
        star_count = 0

        while True:
            if self.pos >= self.length:
                raise FilterSyntaxError("Unterminated filter value")
            ch = self._peek()
            if ch == ")":
                segments.append(bytes(buf))
                break
            if ch == "*":
                segments.append(bytes(buf))
                buf.clear()
                star_count += 1
                self._consume()
                continue
            if ch == "\\":
                self._consume()
                buf.append(self._parse_escape())
                continue
            buf.append(ord(ch))
            self._consume()

        return segments, star_count

    def _build_substring_pattern(self, attr: str, segments: List[bytes]) -> SubstringPattern:
        if not segments:
            raise FilterSyntaxError(f"Malformed substring filter for {attr}")

        segments_str = [FilterValue(seg).as_str() for seg in segments]
        initial: Optional[str] = None
        final: Optional[str] = None
        any_segments: List[str] = []

        if segments_str[0] != "":
            initial = segments_str[0]
        segments_middle = segments_str[1:-1]
        for seg in segments_middle:
            if seg != "":
                any_segments.append(seg)
        if segments_str[-1] != "":
            final = segments_str[-1]

        # Handle edge cases where pattern starts/ends with wildcards
        if segments_str[0] == "":
            initial = None
        if segments_str[-1] == "":
            final = None

        return SubstringPattern(initial=initial, any=any_segments, final=final)

    def _parse_escape(self) -> int:
        if self.pos + 2 > self.length:
            raise FilterSyntaxError("Incomplete escape sequence")
        hex_pair = self.data[self.pos : self.pos + 2]
        self.pos += 2
        try:
            return int(hex_pair, 16)
        except ValueError as exc:
            raise FilterSyntaxError(f"Invalid escape sequence \\{hex_pair}") from exc

    def _peek(self) -> str:
        if self.pos >= self.length:
            raise FilterSyntaxError("Unexpected end of filter")
        return self.data[self.pos]

    def _consume(self) -> None:
        self.pos += 1

    def _expect(self, token: str) -> None:
        for ch in token:
            if self._peek() != ch:
                raise FilterSyntaxError(f"Expected '{token}'")
            self._consume()

    def _skip_spaces(self) -> None:
        while self.pos < self.length and self.data[self.pos].isspace():
            self.pos += 1


def parse_filter(data: str) -> FilterNode:
    return Parser(data).parse()
