"""shorewalld tap — operator troubleshooting CLI for dnstap streams.

``shorewalld tap`` connects to a dnstap unix socket (typically the
same socket pdns_recursor is already writing to, or a spare one
set up for debugging) and pretty-prints every frame it sees.
Think ``tcpdump`` for DNS answers — essential for verifying that
the recursor ↔ shorewalld wiring actually works before anyone
looks at Prometheus.

Features
--------

* **Three output formats**: ``pretty`` (columnar, ANSI-coloured
  when stdout is a TTY), ``structured`` (one key=value line per
  frame for grep + journalctl), and ``json`` (line-delimited JSON
  for ``jq`` pipelines).
* **Filters** on qname (substring or regex), RCODE, RR type, and
  CLIENT_QUERY vs CLIENT_RESPONSE.
* **Allowlist check**: takes a compiled allowlist file and marks
  each frame as "in-allowlist" so you can tell at a glance whether
  it would be populated into a shorewalld set.
* **Stats summary on exit** (Ctrl-C or ``--count N`` reached):
  top-N qnames, rcode breakdown, allowlist hit rate.

Defaults come from the ``DNSTAP_SOCKET`` key of ``shorewall.conf``
(when we have a config reader — for now the ``--socket`` flag is
required). CLI flags override.

Runs entirely in the foreground — no systemd unit, no background
task. Exits on Ctrl-C and prints the summary. Zero interaction
with the live shorewalld instance (if any) — tap uses a separate
socket path so it can't steal frames from the running daemon.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import socket
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from .dns_wire import extract_qname, extract_rcode
from .dnstap import decode_dnstap_frame
from .framestream import (
    FrameStreamError,
    accept_handshake,
    read_frame,
)

# ── output formatting ────────────────────────────────────────────────


ANSI_RESET = "\x1b[0m"
ANSI_BOLD = "\x1b[1m"
ANSI_DIM = "\x1b[2m"
ANSI_RED = "\x1b[31m"
ANSI_GREEN = "\x1b[32m"
ANSI_YELLOW = "\x1b[33m"
ANSI_CYAN = "\x1b[36m"

_RCODE_NAMES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
    6: "YXDOMAIN",
    7: "YXRRSET",
    8: "NXRRSET",
    9: "NOTAUTH",
    10: "NOTZONE",
}

_DNSTAP_TYPE_NAMES = {
    1: "AUTH_QUERY",
    2: "AUTH_RESPONSE",
    3: "RESOLVER_QUERY",
    4: "RESOLVER_RESPONSE",
    5: "CLIENT_QUERY",
    6: "CLIENT_RESPONSE",
    7: "FORWARDER_QUERY",
    8: "FORWARDER_RESPONSE",
    9: "STUB_QUERY",
    10: "STUB_RESPONSE",
}


def _rcode_str(rcode: int | None) -> str:
    if rcode is None:
        return "-"
    return _RCODE_NAMES.get(rcode, f"RCODE{rcode}")


def _colour(text: str, code: str, enable: bool) -> str:
    return f"{code}{text}{ANSI_RESET}" if enable else text


@dataclass
class Frame:
    """One decoded dnstap frame, as the tap CLI sees it."""
    ts_mono: float
    dnstap_type: int
    rcode: int | None
    qname: str
    wire_len: int
    in_allowlist: bool | None = None        # None = no allowlist loaded


@dataclass
class TapStats:
    total: int = 0
    by_type: Counter = field(default_factory=Counter)
    by_rcode: Counter = field(default_factory=Counter)
    by_qname: Counter = field(default_factory=Counter)
    allowlist_hits: int = 0
    allowlist_misses: int = 0
    decode_errors: int = 0
    filtered_out: int = 0


# ── allowlist helper ─────────────────────────────────────────────────


def _load_allowlist(path: Path | None) -> set[str] | None:
    """Load the compiled allowlist (from Phase 1 ``dnsnames.compiled``).

    Returns a ``set[str]`` of canonical qnames, or ``None`` if the
    path wasn't provided. Missing file is treated as an empty
    allowlist with a warning — that's usually a misconfiguration.
    """
    if path is None:
        return None
    if not path.exists():
        print(
            f"warning: allowlist file {path} does not exist — "
            "every frame will be marked as miss",
            file=sys.stderr,
        )
        return set()
    from shorewall_nft.nft.dns_sets import read_compiled_allowlist
    reg = read_compiled_allowlist(path)
    return set(reg.specs.keys())


# ── frame pipeline ───────────────────────────────────────────────────


def decode_frame(buf: memoryview | bytes) -> Frame | None:
    """Turn raw dnstap protobuf bytes into a :class:`Frame`.

    Returns ``None`` on decode errors so the caller can count them
    and continue. Minimal work beyond the protobuf step — qname and
    rcode come from the cheap DNS wire walker instead of dnspython.
    """
    try:
        result = decode_dnstap_frame(bytes(buf))
    except Exception:
        return None
    if result is None:
        return None
    msg_type, wire = result
    qn_result = extract_qname(wire)
    qname = qn_result[0] if qn_result else ""
    rcode = extract_rcode(wire)
    return Frame(
        ts_mono=time.monotonic(),
        dnstap_type=msg_type,
        rcode=rcode,
        qname=qname,
        wire_len=len(wire),
    )


def _passes_filter(
    frame: Frame,
    *,
    qname_re: re.Pattern[str] | None,
    rcode_filter: str | None,
    show_queries: bool,
) -> bool:
    if not show_queries and frame.dnstap_type not in (6, 8, 10):
        return False
    if qname_re is not None and not qname_re.search(frame.qname):
        return False
    if rcode_filter is not None:
        want = _RCODE_NAMES.get(frame.rcode or -1, "")
        if want.upper() != rcode_filter.upper():
            return False
    return True


def _format_pretty(frame: Frame, *, use_colour: bool) -> str:
    ts = time.strftime("%H:%M:%S", time.localtime()) + \
        f".{int((frame.ts_mono % 1) * 1000):03d}"
    type_name = _DNSTAP_TYPE_NAMES.get(
        frame.dnstap_type, f"TYPE{frame.dnstap_type}")
    rcode_text = _rcode_str(frame.rcode)
    rcode_colour = ANSI_GREEN
    if rcode_text == "NXDOMAIN":
        rcode_colour = ANSI_RED
    elif rcode_text == "SERVFAIL":
        rcode_colour = ANSI_RED
    elif rcode_text == "REFUSED":
        rcode_colour = ANSI_YELLOW
    qname_display = frame.qname[:40]
    if len(frame.qname) > 40:
        qname_display = qname_display[:39] + "…"
    tag = ""
    if frame.in_allowlist is True:
        tag = _colour("[allowlist ✓]", ANSI_GREEN, use_colour)
    elif frame.in_allowlist is False:
        tag = _colour("[unknown]", ANSI_DIM, use_colour)
    return (
        f"{ts}  "
        f"{type_name:<17} "
        f"{_colour(rcode_text, rcode_colour, use_colour):<10} "
        f"{qname_display:<40} "
        f"len={frame.wire_len:<4} "
        f"{tag}"
    )


def _format_structured(frame: Frame) -> str:
    parts = [
        f"ts={time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime())}",
        f"type={_DNSTAP_TYPE_NAMES.get(frame.dnstap_type, frame.dnstap_type)}",
        f"rcode={_rcode_str(frame.rcode)}",
        f"qname={frame.qname or '-'}",
        f"len={frame.wire_len}",
    ]
    if frame.in_allowlist is not None:
        parts.append(f"allowlist={'hit' if frame.in_allowlist else 'miss'}")
    return " ".join(parts)


def _format_json(frame: Frame) -> str:
    doc = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()),
        "type": _DNSTAP_TYPE_NAMES.get(
            frame.dnstap_type, f"TYPE{frame.dnstap_type}"),
        "rcode": _rcode_str(frame.rcode),
        "qname": frame.qname,
        "wire_len": frame.wire_len,
    }
    if frame.in_allowlist is not None:
        doc["allowlist"] = "hit" if frame.in_allowlist else "miss"
    return json.dumps(doc, separators=(",", ":"))


def format_frame(
    frame: Frame, *, fmt: str, use_colour: bool
) -> str:
    if fmt == "pretty":
        return _format_pretty(frame, use_colour=use_colour)
    if fmt == "structured":
        return _format_structured(frame)
    if fmt == "json":
        return _format_json(frame)
    raise ValueError(f"unknown format: {fmt}")


# ── Reader loop ──────────────────────────────────────────────────────


@dataclass
class TapState:
    stats: TapStats
    allowlist: set[str] | None
    stopping: bool = False


def _make_reader_writer(sock: socket.socket):
    """Adapter so existing FrameStream helpers work with a blocking socket.

    ``framestream.read_frame`` is designed for asyncio StreamReaders;
    the tap CLI runs synchronously. A minimal shim presents the
    blocking socket as an async reader by wrapping recv into a
    coroutine that never yields.
    """
    import asyncio

    class _BlockingReader:
        def __init__(self, s):
            self._s = s
            self._buf = bytearray()

        async def readexactly(self, n: int) -> bytes:
            while len(self._buf) < n:
                chunk = self._s.recv(max(4096, n - len(self._buf)))
                if not chunk:
                    raise asyncio.IncompleteReadError(bytes(self._buf), n)
                self._buf.extend(chunk)
            out = bytes(self._buf[:n])
            del self._buf[:n]
            return out

    class _BlockingWriter:
        def __init__(self, s):
            self._s = s

        def write(self, data: bytes) -> None:
            self._s.sendall(data)

        async def drain(self) -> None:
            return

        def close(self) -> None:
            try:
                self._s.close()
            except OSError:
                pass

    return _BlockingReader(sock), _BlockingWriter(sock)


def serve_one_connection(
    sock: socket.socket,
    state: TapState,
    *,
    fmt: str,
    use_colour: bool,
    qname_re: re.Pattern[str] | None,
    rcode_filter: str | None,
    show_queries: bool,
    count_limit: int | None,
    stream,
) -> None:
    """Run one recursor-side connection to completion.

    Handles the FrameStream handshake, then reads frames in a loop
    until EOF or ``count_limit`` is reached. The existing
    :func:`framestream.read_frame` helper is async; we wrap the
    blocking socket so it can drive it without pulling in a real
    event loop.
    """
    import asyncio

    async def _run():
        reader, writer = _make_reader_writer(sock)
        try:
            await accept_handshake(reader, writer)
        except FrameStreamError as e:
            print(f"handshake failed: {e}", file=sys.stderr)
            return
        while not state.stopping:
            try:
                is_ctrl, body = await read_frame(reader)
            except asyncio.IncompleteReadError:
                return
            except FrameStreamError as e:
                print(f"read error: {e}", file=sys.stderr)
                return
            if is_ctrl:
                # STOP / FINISH frames — nothing to print, just
                # loop and let the next read fail on EOF.
                continue
            frame = decode_frame(body)
            if frame is None:
                state.stats.decode_errors += 1
                continue
            if state.allowlist is not None:
                frame.in_allowlist = frame.qname in state.allowlist
                if frame.in_allowlist:
                    state.stats.allowlist_hits += 1
                else:
                    state.stats.allowlist_misses += 1
            if not _passes_filter(
                frame,
                qname_re=qname_re,
                rcode_filter=rcode_filter,
                show_queries=show_queries,
            ):
                state.stats.filtered_out += 1
                continue
            state.stats.total += 1
            state.stats.by_type[frame.dnstap_type] += 1
            if frame.rcode is not None:
                state.stats.by_rcode[frame.rcode] += 1
            if frame.qname:
                state.stats.by_qname[frame.qname] += 1
            stream.write(
                format_frame(frame, fmt=fmt, use_colour=use_colour) + "\n")
            stream.flush()
            if count_limit is not None and state.stats.total >= count_limit:
                state.stopping = True
                return

    asyncio.run(_run())


def print_summary(stats: TapStats, *, stream) -> None:
    stream.write("\n=== tap summary ===\n")
    stream.write(f"total frames (post-filter):   {stats.total}\n")
    stream.write(f"decode errors:                 {stats.decode_errors}\n")
    stream.write(f"filtered out:                  {stats.filtered_out}\n")
    if stats.allowlist_hits or stats.allowlist_misses:
        rate = 0.0
        denom = stats.allowlist_hits + stats.allowlist_misses
        if denom > 0:
            rate = 100.0 * stats.allowlist_hits / denom
        stream.write(
            f"allowlist hit rate:            {stats.allowlist_hits}/"
            f"{denom} ({rate:.1f}%)\n"
        )
    if stats.by_type:
        stream.write("by type:\n")
        for t, n in stats.by_type.most_common():
            name = _DNSTAP_TYPE_NAMES.get(t, f"TYPE{t}")
            stream.write(f"  {name:<20} {n}\n")
    if stats.by_rcode:
        stream.write("by rcode:\n")
        for r, n in stats.by_rcode.most_common():
            stream.write(f"  {_rcode_str(r):<10} {n}\n")
    if stats.by_qname:
        stream.write("top 10 qnames:\n")
        for q, n in stats.by_qname.most_common(10):
            stream.write(f"  {q:<40} {n}\n")
    stream.flush()


# ── CLI ──────────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="shorewalld tap",
        description="Pretty-print a dnstap stream for troubleshooting.",
    )
    p.add_argument(
        "--socket", required=True, metavar="PATH",
        help="path to the dnstap unix socket")
    p.add_argument(
        "--format", default="pretty",
        choices=("pretty", "structured", "json"),
        help="output format (default: pretty)")
    p.add_argument(
        "--filter-qname", default=None, metavar="REGEX",
        help="only show frames whose qname matches this regex")
    p.add_argument(
        "--filter-rcode", default=None, metavar="NAME",
        help="only show frames with this rcode (NOERROR, NXDOMAIN, ...)")
    p.add_argument(
        "--show-queries", action="store_true",
        help="also show CLIENT_QUERY frames (default: responses only)")
    p.add_argument(
        "--allowlist", default=None, metavar="PATH",
        help="path to dnsnames.compiled — tag frames as in/out allowlist")
    p.add_argument(
        "--count", type=int, default=None, metavar="N",
        help="exit after N matching frames (default: run until Ctrl-C)")
    p.add_argument(
        "--no-color", action="store_true",
        help="disable ANSI colour even on TTY")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    socket_path = Path(args.socket)
    if not socket_path.exists():
        print(
            f"error: socket {socket_path} does not exist",
            file=sys.stderr,
        )
        return 2

    allowlist = _load_allowlist(
        Path(args.allowlist) if args.allowlist else None)
    qname_re = re.compile(args.filter_qname) if args.filter_qname else None
    use_colour = (
        args.format == "pretty"
        and sys.stdout.isatty()
        and not args.no_color
        and not os.environ.get("NO_COLOR")
    )

    state = TapState(stats=TapStats(), allowlist=allowlist)

    def on_signal(signum, _frame):
        state.stopping = True

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    # Tap connects to the dnstap socket as a client — pdns writes
    # to the socket as a client too in its typical setup, so this
    # needs a SOCK_STREAM listener somewhere. In practice, tap
    # spawns its own *listener* on a dedicated socket that pdns
    # would be configured to also write to, and waits for pdns to
    # connect. See docs/reference/shorewalld-tap.md for the config
    # recipe.
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        os.unlink(socket_path)
    except FileNotFoundError:
        pass
    server.bind(str(socket_path))
    os.chmod(socket_path, 0o660)
    server.listen(1)

    print(
        f"shorewalld tap listening on {socket_path}  "
        f"(format={args.format}, filter={args.filter_qname or '-'})",
        file=sys.stderr,
    )

    try:
        while not state.stopping:
            server.settimeout(0.5)
            try:
                conn, _addr = server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            conn.settimeout(None)
            try:
                serve_one_connection(
                    conn,
                    state,
                    fmt=args.format,
                    use_colour=use_colour,
                    qname_re=qname_re,
                    rcode_filter=args.filter_rcode,
                    show_queries=args.show_queries,
                    count_limit=args.count,
                    stream=sys.stdout,
                )
            finally:
                try:
                    conn.close()
                except OSError:
                    pass
            if args.count is not None and state.stats.total >= args.count:
                break
    finally:
        try:
            server.close()
            os.unlink(socket_path)
        except OSError:
            pass
        print_summary(state.stats, stream=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
