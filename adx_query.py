#!/usr/bin/env python3
"""
Command line interface for querying ADExplorer snapshot files.
"""

from __future__ import annotations

import argparse
import copy
import os
import shlex
import sys
import textwrap
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence

from dat_reader import SnapshotReader
from filter_engine import FilterSyntaxError, parse_filter
from formatters import write_csv, write_excel, write_json, write_table
from query_engine import QueryEngine

@dataclass
class QueryRequest:
    ldap_filter: Optional[str]
    attributes: Optional[List[str]]
    output_format: str
    output_path: Optional[str]
    limit: Optional[int]
    ignore_case: bool
    benchmark: bool


class QueryConfigurationError(Exception):
    """Raised when query options are invalid."""


def parse_arguments(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Execute LDAP filters directly against ADExplorer .dat snapshots",
    )
    parser.add_argument(
        "--snapshot",
        help="Path to the ADExplorer .dat snapshot file",
    )
    parser.add_argument(
        "--filter",
        dest="ldap_filter",
        help="LDAP filter to evaluate (e.g. \"(objectClass=user)\")",
    )
    parser.add_argument(
        "--attributes",
        nargs="+",
        help="Attributes to return (space or comma separated).",
    )
    parser.add_argument(
        "--format",
        choices=("json", "csv", "table", "excel"),
        default="table",
        help="Output format (defaults to table).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Maximum number of results to return.",
    )
    parser.add_argument(
        "--ignore-case",
        action="store_true",
        help="Perform case-insensitive comparisons.",
    )
    parser.add_argument(
        "--benchmark",
        action="store_true",
        help="Print performance statistics after the query.",
    )
    parser.add_argument(
        "--dump-header",
        action="store_true",
        help="Display snapshot metadata before running the query.",
    )
    parser.add_argument(
        "--output",
        help="Write results to the specified output file.",
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Launch an interactive prompt to tweak filters iteratively.",
    )
    args = parser.parse_args(argv)
    if not args.snapshot and not args.interactive:
        parser.error("--snapshot is required unless --interactive is enabled.")
    if not args.interactive and not args.ldap_filter:
        parser.error("--filter is required unless --interactive is enabled.")
    return args


def _expand_attributes(values: Optional[Sequence[str]]) -> Optional[List[str]]:
    if not values:
        return None
    attrs: List[str] = []
    for item in values:
        for part in item.split(","):
            part = part.strip()
            if part:
                attrs.append(part)
    return attrs or None


@contextmanager
def _maybe_open_output(path: Optional[str]):
    if not path:
        yield sys.stdout
        return

    target = Path(path)
    with target.open("w", encoding="utf-8", newline="") as fh:
        yield fh


def _print_header(reader: SnapshotReader) -> None:
    header = reader.header
    print(f"File:         {reader.path}")
    print(f"Server:       {header.server or 'N/A'}")
    print(f"Description:  {header.description or 'N/A'}")
    captured = header.captured_at.astimezone()
    print(f"Captured:     {captured.isoformat()}")
    print(f"Objects:      {header.num_objects}")
    print(f"Attributes:   {header.num_attributes}")
    size_mb = header.file_size / (1024 * 1024)
    print(f"Size:         {size_mb:.2f} MB")
    print("-")


def run_query(
    reader: SnapshotReader,
    request: QueryRequest,
    ldap_filter_override: Optional[str] = None,
) -> QueryEngine:
    filter_text = (
        ldap_filter_override if ldap_filter_override is not None else request.ldap_filter
    )
    if not filter_text:
        raise QueryConfigurationError(
            "An LDAP filter is required to execute the query."
        )

    filter_node = parse_filter(filter_text)
    engine = QueryEngine(
        reader,
        filter_node,
        ignore_case=request.ignore_case,
        attributes=request.attributes,
        limit=request.limit,
    )

    if engine.unknown_attributes:
        missing = ", ".join(engine.unknown_attributes)
        print(
            f"Warning: the following attributes do not exist in the snapshot: {missing}",
            file=sys.stderr,
        )

    if request.output_format == "excel":
        if not request.output_path:
            raise QueryConfigurationError(
                "Excel output requires --output pointing to an .xlsx file."
            )
        rows = [engine.materialise(entry) for entry in engine.search()]
        write_excel(
            rows,
            request.output_path,
            fieldnames=engine.selected_attributes,
        )
    else:
        entries = engine.search()
        results = (engine.materialise(entry) for entry in entries)
        with _maybe_open_output(request.output_path) as output_stream:
            if request.output_format == "json":
                write_json(results, output_stream)
            elif request.output_format == "csv":
                write_csv(
                    results,
                    output_stream,
                    fieldnames=engine.selected_attributes,
                )
            else:
                table_rows = list(results)
                if table_rows:
                    write_table(
                        table_rows,
                        output_stream,
                        field_order=engine.selected_attributes,
                    )

    if request.benchmark:
        _print_benchmark(engine)

    return engine


def _print_benchmark(engine: QueryEngine) -> None:
    stats = engine.stats
    print("\nBenchmark:", file=sys.stderr)
    print(f"  Entries evaluated: {stats.entries_evaluated}", file=sys.stderr)
    print(f"  Matches:            {stats.matches}", file=sys.stderr)
    print(f"  Total time:         {stats.duration_seconds:.3f}s", file=sys.stderr)


def _clear_screen() -> None:
    command = "cls" if os.name == "nt" else "clear"
    os.system(command)


def _prompt_snapshot_path() -> str:
    while True:
        try:
            user_input = input("Ruta al snapshot (.dat): ").strip()
        except EOFError as exc:
            raise QueryConfigurationError("Se requiere una ruta valida al snapshot.") from exc
        if not user_input:
            print("La ruta no puede estar vacia. Intenta de nuevo.")
            continue
        candidate = Path(user_input).expanduser()
        if candidate.is_file():
            return str(candidate)
        print(f"No se encontro el archivo: {candidate}. Intenta nuevamente.")


def _load_prompt_toolkit():
    try:
        from prompt_toolkit import PromptSession
        from prompt_toolkit.completion import WordCompleter
        from prompt_toolkit.history import InMemoryHistory
    except ImportError as exc:
        raise RuntimeError(
            "Interactive mode requires 'prompt_toolkit'. "
            "Install it with `pip install prompt_toolkit`."
        ) from exc
    return PromptSession, WordCompleter, InMemoryHistory


class InteractiveShell:
    COMMANDS = (
        "help",
        "config",
        "attrs",
        "limit",
        "format",
        "output",
        "benchmark",
        "ignore-case",
        "dump-header",
        "reset",
        "clear",
        "run",
        "quit",
        "exit",
    )

    def __init__(self, reader: SnapshotReader, request: QueryRequest) -> None:
        self.reader = reader
        self.request = copy.deepcopy(request)
        self._initial_request = copy.deepcopy(request)
        PromptSession, WordCompleter, InMemoryHistory = _load_prompt_toolkit()
        self._session = PromptSession(
            history=InMemoryHistory(),
            completer=WordCompleter(
                [f":{cmd}" for cmd in self.COMMANDS], ignore_case=True
            ),
        )

    def run(self) -> None:
        print(
            "Interactive mode: escribe filtros LDAP directamente o usa comandos "
            "prefijados con ':' (ej. :help)."
        )
        if not self.request.ldap_filter:
            print("Tip: empieza con un filtro como (objectClass=user).")

        while True:
            try:
                text = self._session.prompt("adx> ")
            except EOFError:
                print("\nSaliendo del modo interactivo.")
                break
            except KeyboardInterrupt:
                print("^C")
                continue

            text = text.strip()
            if not text:
                self._execute_filter(self.request.ldap_filter, remember=False)
                continue

            lowered = text.lower()
            if lowered in {"exit", "quit"}:
                print("Saliendo del modo interactivo.")
                break
            if lowered == "clear":
                _clear_screen()
                continue

            if text.startswith(":"):
                should_exit = self._handle_command(text[1:].strip())
                if should_exit:
                    break
                continue

            self._execute_filter(text)

    def _handle_command(self, command_line: str) -> bool:
        try:
            parts = shlex.split(command_line)
        except ValueError as exc:
            print(f"Comando invalido: {exc}")
            return False

        if not parts:
            return False

        cmd = parts[0].lower()
        args = parts[1:]

        if cmd in {"quit", "exit"}:
            return True
        if cmd == "help":
            self._print_help()
        elif cmd == "config":
            self._print_config()
        elif cmd == "attrs":
            self._set_attributes(args)
        elif cmd == "limit":
            self._set_limit(args)
        elif cmd == "format":
            self._set_format(args)
        elif cmd == "output":
            self._set_output(args)
        elif cmd == "benchmark":
            self._toggle_flag("benchmark", args)
        elif cmd == "ignore-case":
            self._toggle_flag("ignore_case", args)
        elif cmd == "dump-header":
            _print_header(self.reader)
        elif cmd == "reset":
            self._reset()
        elif cmd == "clear":
            _clear_screen()
        elif cmd == "run":
            self._execute_filter(self.request.ldap_filter, remember=False)
        else:
            print(
                f"Comando desconocido: {cmd}. Usa :help para ver la lista disponible."
            )
        return False

    def _execute_filter(self, ldap_filter: Optional[str], remember: bool = True) -> None:
        if not ldap_filter:
            print("No hay filtro activo. Escribe uno o usa :help para ver opciones.")
            return
        if remember:
            self.request.ldap_filter = ldap_filter

        try:
            engine = run_query(
                self.reader,
                self.request,
                ldap_filter_override=ldap_filter,
            )
        except FilterSyntaxError as exc:
            print(f"Error de sintaxis en el filtro: {exc}")
            return
        except QueryConfigurationError as exc:
            print(exc)
            return

        stats = engine.stats
        destino = self.request.output_path or "stdout"
        print(
            f"✓ {stats.matches} objetos (evaluados {stats.entries_evaluated}) "
            f"en {stats.duration_seconds:.3f}s → destino: {destino}"
        )

    def _set_attributes(self, args: List[str]) -> None:
        if not args:
            self.request.attributes = None
            print("Se mostraran todas las propiedades disponibles.")
            return
        attrs = _expand_attributes(args)
        if not attrs:
            self.request.attributes = None
            print("Lista de atributos vacia; se usara el modo completo.")
            return
        self.request.attributes = attrs
        print(f"Atributos seleccionados: {', '.join(attrs)}")

    def _set_limit(self, args: List[str]) -> None:
        if not args:
            self.request.limit = None
            print("Sin limite de resultados.")
            return
        try:
            value = int(args[0])
            if value <= 0:
                raise ValueError
        except ValueError:
            print("El limite debe ser un entero positivo.")
            return
        self.request.limit = value
        print(f"Limite fijado en {value} entradas.")

    def _set_format(self, args: List[str]) -> None:
        if not args:
            print("Especifica un formato: table, json, csv o excel.")
            return
        choice = args[0].lower()
        if choice not in {"table", "json", "csv", "excel"}:
            print("Formato no valido. Usa table, json, csv o excel.")
            return
        self.request.output_format = choice
        print(f"Formato de salida: {choice}")

    def _set_output(self, args: List[str]) -> None:
        if not args:
            self.request.output_path = None
            print("Los resultados se enviaran a stdout.")
            return
        path = " ".join(args)
        self.request.output_path = path
        print(f"Destino configurado: {path}")

    def _toggle_flag(self, attr: str, args: List[str]) -> None:
        current = getattr(self.request, attr)
        if args:
            value = args[0].lower()
            if value in {"on", "true", "1"}:
                new_value = True
            elif value in {"off", "false", "0"}:
                new_value = False
            else:
                print("Usa 'on' o 'off'.")
                return
        else:
            new_value = not current
        setattr(self.request, attr, new_value)
        estado = "activado" if new_value else "desactivado"
        label = "Benchmark" if attr == "benchmark" else "Ignore-case"
        print(f"{label} {estado}.")

    def _print_config(self) -> None:
        print("Configuracion actual:")
        print(f"  Filtro:         {self.request.ldap_filter or '(no definido)'}")
        attrs = (
            ", ".join(self.request.attributes)
            if self.request.attributes
            else "Todos"
        )
        print(f"  Atributos:      {attrs}")
        print(f"  Formato:        {self.request.output_format}")
        print(f"  Destino:        {self.request.output_path or 'stdout'}")
        print(f"  Limite:         {self.request.limit or 'sin limite'}")
        print(f"  Ignore-case:    {'si' if self.request.ignore_case else 'no'}")
        print(f"  Benchmark:      {'si' if self.request.benchmark else 'no'}")

    def _reset(self) -> None:
        self.request = copy.deepcopy(self._initial_request)
        print("Parametros restaurados al estado inicial.")

    def _print_help(self) -> None:
        help_text = textwrap.dedent(
            """
            Comandos disponibles (usa ':' antes del comando):
              :help            Mostrar esta ayuda
              :config          Ver la configuracion actual
              :attrs attr ...  Limitar atributos (sin argumentos = todos)
              :limit N         Definir maximo de resultados
              :format tipo     table, json, csv o excel
              :output PATH     Guardar salida en archivo (sin args = stdout)
              :benchmark [on|off]  Alternar estadisticas
              :ignore-case [on|off] Activar comparaciones case-insensitive
              :dump-header     Mostrar metadatos del snapshot
              :reset           Restaurar configuracion inicial
              :run             Repetir el ultimo filtro
              :quit / :exit    Salir del modo interactivo
            """
        ).strip()
        print(help_text)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_arguments(argv)
    attributes = _expand_attributes(args.attributes)

    request = QueryRequest(
        ldap_filter=args.ldap_filter,
        attributes=attributes,
        output_format=args.format,
        output_path=args.output,
        limit=args.limit,
        ignore_case=args.ignore_case,
        benchmark=args.benchmark,
    )

    snapshot_path = args.snapshot
    if args.interactive and not snapshot_path:
        try:
            snapshot_path = _prompt_snapshot_path()
        except QueryConfigurationError as exc:
            print(exc, file=sys.stderr)
            return 1

    with SnapshotReader(snapshot_path) as reader:
        if args.dump_header:
            _print_header(reader)

        if args.interactive:
            try:
                shell = InteractiveShell(reader, request)
            except RuntimeError as exc:
                print(exc, file=sys.stderr)
                return 1
            shell.run()
            return 0

        try:
            run_query(reader, request)
        except FilterSyntaxError as exc:
            print(f"Filter syntax error: {exc}", file=sys.stderr)
            return 1
        except QueryConfigurationError as exc:
            print(exc, file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
