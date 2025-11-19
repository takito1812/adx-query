"""
Binary snapshot reader for Sysinternals ADExplorer `.dat` files.

This implementation interprets the snapshot format directly using the Python
standard library.  It is inspired by the reverse-engineering work published in
https://github.com/c3c/ADExplorerSnapshot.py (MIT licensed) but avoids external
dependencies so the CLI can run on a plain Python installation.
"""

from __future__ import annotations

import datetime
import mmap
import os
import struct
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Sequence, Tuple

# ADSI attribute type constants (subset required for the reader)
ADSTYPE_INVALID = 0
ADSTYPE_DN_STRING = 1
ADSTYPE_CASE_EXACT_STRING = 2
ADSTYPE_CASE_IGNORE_STRING = 3
ADSTYPE_PRINTABLE_STRING = 4
ADSTYPE_NUMERIC_STRING = 5
ADSTYPE_BOOLEAN = 6
ADSTYPE_INTEGER = 7
ADSTYPE_OCTET_STRING = 8
ADSTYPE_UTC_TIME = 9
ADSTYPE_LARGE_INTEGER = 10
ADSTYPE_PROV_SPECIFIC = 11
ADSTYPE_OBJECT_CLASS = 12
ADSTYPE_CASEIGNORE_LIST = 13
ADSTYPE_OCTET_LIST = 14
ADSTYPE_PATH = 15
ADSTYPE_POSTALADDRESS = 16
ADSTYPE_TIMESTAMP = 17
ADSTYPE_BACKLINK = 18
ADSTYPE_TYPEDNAME = 19
ADSTYPE_HOLD = 20
ADSTYPE_NETADDRESS = 21
ADSTYPE_REPLICAPOINTER = 22
ADSTYPE_FAXNUMBER = 23
ADSTYPE_EMAIL = 24
ADSTYPE_NT_SECURITY_DESCRIPTOR = 25
ADSTYPE_UNKNOWN = 26
ADSTYPE_DN_WITH_BINARY = 27
ADSTYPE_DN_WITH_STRING = 28


@dataclass(frozen=True)
class SnapshotHeader:
    signature: str
    captured_at: datetime.datetime
    description: str
    server: str
    num_objects: int
    num_attributes: int
    mapping_offset: int
    file_size: int


@dataclass(frozen=True)
class PropertyDefinition:
    index: int
    name: str
    ads_type: int
    distinguished_name: str
    schema_id_guid: uuid.UUID
    attribute_security_guid: uuid.UUID


def _windows_filetime_to_datetime(value: int) -> datetime.datetime:
    """Convert a Windows FILETIME (100-ns intervals since 1601) to UTC datetime."""
    if value == 0:
        return datetime.datetime.fromtimestamp(0, tz=datetime.timezone.utc)
    epoch_start = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
    delta = datetime.timedelta(microseconds=value / 10)
    return epoch_start + delta


def _read_exact(fh, size: int) -> bytes:
    data = fh.read(size)
    if len(data) != size:
        raise EOFError(f"Expected {size} bytes, received {len(data)}")
    return data


def _read_uint32(fh) -> int:
    return struct.unpack("<I", _read_exact(fh, 4))[0]


def _read_int32(fh) -> int:
    return struct.unpack("<i", _read_exact(fh, 4))[0]


def _read_int64(fh) -> int:
    return struct.unpack("<q", _read_exact(fh, 8))[0]


def _read_uint16(fh) -> int:
    return struct.unpack("<H", _read_exact(fh, 2))[0]


def _read_utf16le_string(data: bytes) -> str:
    if not data:
        return ""
    return data.decode("utf-16-le", errors="ignore").rstrip("\x00")


def _read_wchar_string(fh) -> str:
    """Read a UTF-16LE NUL-terminated string from the current file position."""
    buf = bytearray()
    while True:
        ch = _read_exact(fh, 2)
        if ch == b"\x00\x00":
            break
        buf.extend(ch)
    if not buf:
        return ""
    return buf.decode("utf-16-le", errors="ignore")


def _parse_sid(data: bytes) -> str:
    """Convert a binary SID into the standard string representation."""
    if len(data) < 8:
        return data.hex()
    revision = data[0]
    sub_authority_count = data[1]
    identifier_authority = int.from_bytes(data[2:8], byteorder="big")
    sub_authorities = []
    for i in range(sub_authority_count):
        start = 8 + i * 4
        end = start + 4
        if end > len(data):
            break
        sub_authorities.append(str(struct.unpack("<I", data[start:end])[0]))
    return "S-{}-{}{}".format(
        revision,
        identifier_authority,
        "".join(f"-{s}" for s in sub_authorities),
    )


def _decode_octet_string(prop_name: str, blob: bytes, raw: bool) -> object:
    """Decode binary attributes to human readable types when possible."""
    if raw:
        return blob

    low_name = prop_name.lower()
    if len(blob) == 16 and (low_name.endswith("guid") or low_name == "objectguid"):
        return str(uuid.UUID(bytes_le=blob))
    if low_name == "objectsid":
        return _parse_sid(blob)
    return blob.hex()


def _represent_bytes(data: bytes, raw: bool) -> object:
    return data if raw else data.hex()


class SnapshotEntry:
    """Represents a single AD object extracted from the snapshot."""

    __slots__ = (
        "reader",
        "offset",
        "size",
        "_mapping",
        "_cache",
        "_raw_cache",
    )

    def __init__(self, reader: "SnapshotReader", offset: int):
        self.reader = reader

        self.offset = offset
        self.size = 0
        self._mapping: List[Tuple[int, int]] = []
        self._cache: Dict[int, List[object]] = {}
        self._raw_cache: Dict[int, List[object]] = {}
        self._read_object_header()

    def _read_object_header(self) -> None:
        fh = self.reader.fh
        fh.seek(self.offset)
        self.size = _read_uint32(fh)
        table_size = _read_uint32(fh)
        mapping: List[Tuple[int, int]] = []
        for _ in range(table_size):
            attr_index = _read_uint32(fh)
            attr_offset = _read_int32(fh)
            mapping.append((attr_index, attr_offset))
        self._mapping = mapping

    @property
    def mapping(self) -> Sequence[Tuple[int, int]]:
        return self._mapping

    def get_attribute_values(self, attr_name: str, raw: bool = False) -> List[object]:
        prop = self.reader.get_property(attr_name)
        if prop is None:
            raise KeyError(attr_name)

        cache = self._raw_cache if raw else self._cache
        if prop.index in cache:
            return cache[prop.index]

        attr_offset: Optional[int] = None
        for idx, offset in self._mapping:
            if idx == prop.index:
                attr_offset = offset
                break

        if attr_offset is None:
            raise KeyError(attr_name)

        values = self._read_values(prop, attr_offset, raw=raw)
        cache[prop.index] = values
        return values

    def iter_attributes(self) -> Iterator[Tuple[str, List[object]]]:
        for attr_index, _ in self._mapping:
            prop = self.reader.properties[attr_index]
            try:
                values = self.get_attribute_values(prop.name)
            except KeyError:
                continue
            yield prop.name, values

    def to_dict(self, attributes: Optional[Sequence[str]] = None) -> Dict[str, object]:
        if attributes:
            result: Dict[str, object] = {}
            for name in attributes:
                prop = self.reader.get_property(name)
                if prop is None:
                    continue
                try:
                    values = self.get_attribute_values(prop.name)
                except KeyError:
                    continue
                result[prop.name] = _collapse_values(values)
            return result

        result: Dict[str, object] = {}
        for name, values in self.iter_attributes():
            result[name] = _collapse_values(values)
        return result

    def _read_values(
        self,
        prop: PropertyDefinition,
        attr_offset: int,
        raw: bool = False,
    ) -> List[object]:
        fh = self.reader.fh
        file_attr_offset = self.offset + attr_offset
        fh.seek(file_attr_offset)
        num_values = _read_uint32(fh)
        if num_values == 0:
            return []

        attr_type = prop.ads_type
        values: List[object] = []

        if attr_type in (
            ADSTYPE_DN_STRING,
            ADSTYPE_CASE_EXACT_STRING,
            ADSTYPE_CASE_IGNORE_STRING,
            ADSTYPE_PRINTABLE_STRING,
            ADSTYPE_NUMERIC_STRING,
            ADSTYPE_OBJECT_CLASS,
        ):
            offsets = [_read_int32(fh) for _ in range(num_values)]
            for rel in offsets:
                absolute = file_attr_offset + rel
                fh.seek(absolute)
                values.append(_read_wchar_string(fh))

        elif attr_type == ADSTYPE_OCTET_STRING:
            lengths = [_read_uint32(fh) for _ in range(num_values)]
            for length in lengths:
                data = _read_exact(fh, length)
                values.append(_decode_octet_string(prop.name, data, raw))

        elif attr_type == ADSTYPE_BOOLEAN:
            for _ in range(num_values):
                values.append(bool(_read_uint32(fh)))

        elif attr_type == ADSTYPE_INTEGER:
            for _ in range(num_values):
                values.append(_read_uint32(fh))

        elif attr_type == ADSTYPE_LARGE_INTEGER:
            for _ in range(num_values):
                values.append(_read_int64(fh))

        elif attr_type == ADSTYPE_UTC_TIME:
            for _ in range(num_values):
                year = _read_uint16(fh)
                month = _read_uint16(fh)
                _ = _read_uint16(fh)  # day of week (unused)
                day = _read_uint16(fh)
                hour = _read_uint16(fh)
                minute = _read_uint16(fh)
                second = _read_uint16(fh)
                _ = _read_uint16(fh)  # milliseconds (unused)
                try:
                    dt = datetime.datetime(
                        year,
                        month,
                        day,
                        hour,
                        minute,
                        second,
                        tzinfo=datetime.timezone.utc,
                    )
                    values.append(int(dt.timestamp()))
                except ValueError:
                    values.append(0)

        elif attr_type == ADSTYPE_NT_SECURITY_DESCRIPTOR:
            for _ in range(num_values):
                length = _read_uint32(fh)
                values.append(_represent_bytes(_read_exact(fh, length), raw))

        else:
            for _ in range(num_values):
                length = _read_uint32(fh)
                values.append(_represent_bytes(_read_exact(fh, length), raw))

        return values


def _collapse_values(values: List[object]) -> object:
    if not values:
        return []
    if len(values) == 1:
        return values[0]
    return values


class SnapshotReader:
    """High-level access to an ADExplorer snapshot."""

    def __init__(self, path: os.PathLike[str] | str, use_mmap: bool = True):
        self.path = Path(path)
        if not self.path.is_file():
            raise FileNotFoundError(self.path)

        self._fh_raw = self.path.open("rb")
        self._mmap: Optional[mmap.mmap] = None
        if use_mmap:
            self._mmap = mmap.mmap(self._fh_raw.fileno(), 0, access=mmap.ACCESS_READ)
            self.fh = self._mmap
        else:
            self.fh = self._fh_raw

        self._header = self._parse_header()
        self._properties, self._property_by_name = self._parse_properties()
        self._object_offsets = self._parse_object_offsets()

    def __enter__(self) -> "SnapshotReader":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def close(self) -> None:
        if self._mmap is not None:
            self._mmap.close()
        self._fh_raw.close()

    @property
    def header(self) -> SnapshotHeader:
        return self._header

    @property
    def properties(self) -> Sequence[PropertyDefinition]:
        return self._properties

    def get_property(self, name: str) -> Optional[PropertyDefinition]:
        if name is None:
            return None
        idx = self._property_by_name.get(name.lower())
        if idx is None:
            return None
        return self._properties[idx]

    def iter_entries(self) -> Iterator[SnapshotEntry]:
        for offset in self._object_offsets:
            yield SnapshotEntry(self, offset)

    # -- internal parsing helpers -------------------------------------------------

    def _parse_header(self) -> SnapshotHeader:
        self.fh.seek(0)
        signature = _read_exact(self.fh, 10).decode("ascii", errors="ignore").rstrip(
            "\x00"
        )
        marker = _read_int32(self.fh)
        filetime = struct.unpack("<Q", _read_exact(self.fh, 8))[0]
        optional_description = _read_utf16le_string(_read_exact(self.fh, 260 * 2))
        server = _read_utf16le_string(_read_exact(self.fh, 260 * 2))
        num_objects = _read_uint32(self.fh)
        num_attributes = _read_uint32(self.fh)
        fileoffset_low = _read_uint32(self.fh)
        fileoffset_high = _read_uint32(self.fh)
        fileoffset_end = _read_uint32(self.fh)
        _ = _read_int32(self.fh)  # unk0x43a (unused)

        mapping_offset = (fileoffset_high << 32) | fileoffset_low
        captured_at = _windows_filetime_to_datetime(filetime)
        file_size = self.path.stat().st_size

        return SnapshotHeader(
            signature=signature,
            captured_at=captured_at,
            description=optional_description,
            server=server,
            num_objects=num_objects,
            num_attributes=num_attributes,
            mapping_offset=mapping_offset,
            file_size=file_size,
        )

    def _parse_properties(
        self,
    ) -> Tuple[List[PropertyDefinition], Dict[str, int]]:
        self.fh.seek(self._header.mapping_offset)
        num_properties = _read_uint32(self.fh)
        properties: List[PropertyDefinition] = []
        by_name: Dict[str, int] = {}

        for idx in range(num_properties):
            len_prop_name = _read_uint32(self.fh)
            prop_name = _read_utf16le_string(_read_exact(self.fh, len_prop_name))
            _ = _read_int32(self.fh)  # unk1
            ads_type = _read_uint32(self.fh)
            len_dn = _read_uint32(self.fh)
            distinguished_name = _read_utf16le_string(_read_exact(self.fh, len_dn))
            schema_guid = uuid.UUID(bytes_le=_read_exact(self.fh, 16))
            attribute_guid = uuid.UUID(bytes_le=_read_exact(self.fh, 16))
            _read_exact(self.fh, 4)  # blob, unused

            prop = PropertyDefinition(
                index=idx,
                name=prop_name,
                ads_type=ads_type,
                distinguished_name=distinguished_name,
                schema_id_guid=schema_guid,
                attribute_security_guid=attribute_guid,
            )
            properties.append(prop)
            by_name[prop_name.lower()] = idx

        return properties, by_name

    def _parse_object_offsets(self) -> List[int]:
        offsets: List[int] = []
        self.fh.seek(0x43E)
        for _ in range(self._header.num_objects):
            pos = self.fh.tell()
            size_data = self.fh.read(4)
            if len(size_data) != 4:
                break
            obj_size = struct.unpack("<I", size_data)[0]
            offsets.append(pos)
            self.fh.seek(pos + obj_size)
        return offsets
