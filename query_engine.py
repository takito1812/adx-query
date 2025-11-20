"""
Query engine that evaluates LDAP-style filters against ADExplorer snapshot
entries in a streaming fashion.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional, Sequence, Tuple

from dat_reader import SnapshotEntry, SnapshotReader
from filter_engine import EvaluationContext, FilterNode


@dataclass
class QueryStats:
    entries_evaluated: int = 0
    matches: int = 0
    duration_seconds: float = 0.0


class QueryEngine:
    def __init__(
        self,
        reader: SnapshotReader,
        filter_node: FilterNode,
        ignore_case: bool = False,
        attributes: Optional[Sequence[str]] = None,
        limit: Optional[int] = None,
    ):
        self.reader = reader
        self.filter_node = filter_node
        self.ignore_case = ignore_case
        self.limit = limit
        (
            self._selected_attributes,
            self._unknown_attributes,
        ) = self._normalise_attributes(attributes)
        self.stats = QueryStats()

    @property
    def selected_attributes(self) -> Optional[Sequence[str]]:
        return self._selected_attributes

    @property
    def unknown_attributes(self) -> Sequence[str]:
        return self._unknown_attributes

    def search(self) -> Iterator[SnapshotEntry]:
        start = time.perf_counter()
        matches = 0
        evaluated = 0
        for entry in self.reader.iter_entries():
            evaluated += 1
            ctx = EvaluationContext(
                reader=self.reader, entry=entry, ignore_case=self.ignore_case
            )
            if self.filter_node.evaluate(ctx):
                matches += 1
                yield entry
                if self.limit is not None and matches >= self.limit:
                    break
        end = time.perf_counter()
        self.stats = QueryStats(
            entries_evaluated=evaluated,
            matches=matches,
            duration_seconds=end - start,
        )

    def materialise(self, entry: SnapshotEntry) -> Dict[str, object]:
        return entry.to_dict(self._selected_attributes)

    # -- helpers -----------------------------------------------------------------

    def _normalise_attributes(
        self, attributes: Optional[Sequence[str]]
    ) -> Tuple[Optional[List[str]], List[str]]:
        if not attributes:
            return None, []

        selected: List[str] = []
        unknown: List[str] = []

        for attr in attributes:
            attr = attr.strip()
            if not attr:
                continue
            prop = self.reader.get_property(attr)
            if prop is None:
                unknown.append(attr)
                continue
            selected.append(prop.name)

        if not selected:
            return None, unknown

        return selected, unknown
