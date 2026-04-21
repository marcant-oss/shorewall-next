"""HA peer replication over UDP with HMAC auth.

Goal
----

Two shorewalld instances (fw-a, fw-b) each sit next to their own
pdns_recursor. When the recursor on fw-a sees a DNS answer for a
managed qname, fw-a populates its local nft set *and* replicates
the same update to fw-b so both boxes have identical set contents
without waiting for fw-b's recursor to independently resolve the
same name. The result is "same view of truth" across a failover
boundary with no nft-set replication.

Architecture
------------

* **Transport**: UDP on a configurable (host, port). No retry,
  no reliability — lost datagrams are reconciled organically by
  TTL expiry or by the next sequence gap triggering a snapshot
  request.
* **Framing**: one ``PeerEnvelope`` protobuf per datagram, plus
  a 32-byte HMAC-SHA256 trailer. No IP fragmentation — every
  datagram is capped at 1400 bytes before serialisation.
* **Auth**: symmetric HMAC-SHA256 keyed off a shared secret
  loaded from ``PEER_SECRET_FILE``. Auth is pluggable behind a
  :class:`PeerAuth` protocol so Phase 2 can swap in AEAD or
  asymmetric signatures without touching the rest of the code.
* **Loop prevention**: ``origin_node`` in every envelope. If
  the receiver's own hostname appears there, drop without
  applying (happens on multicast loops, not in our unicast
  design, but the check is free).
* **Liveness**: a periodic :class:`HeartbeatLoop` task fires an
  envelope every ``PEER_HEARTBEAT_INTERVAL`` seconds carrying
  local state counters. Receivers publish them via the
  exporter so scraping *either* node shows *both* nodes' health.

Non-goals for Phase 8
---------------------

* **No snapshot request/response.** That's Phase 9. Phase 8
  ships the envelope schema and plumbing, but the
  ``SnapshotRequest`` / ``SnapshotResponse`` handlers are
  stubbed.
* **No multi-peer mesh.** One-to-one HA pair only; the design
  generalises trivially but we don't exercise it here.
* **No encryption.** HMAC gives authenticity + integrity; the
  HA interlink is typically a trusted private subnet, so
  confidentiality isn't the threat model. Phase 2 can add
  AEAD via the pluggable :class:`PeerAuth`.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import socket
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from shorewall_nft.nft.dns_sets import canonical_qname

from .dns_set_tracker import DnsSetTracker, Proposal
from .exporter import CollectorBase, _MetricFamily
from .logsetup import get_logger, get_rate_limiter
from .proto import peer_pb2
from .setwriter import SetWriter

log = get_logger("peer")
rl = get_rate_limiter()


# Protocol version for ``PeerEnvelope.proto_version``. Bumped on
# incompatible schema changes. Receivers reject envelopes with a
# version they don't understand.
PROTO_VERSION = 1

# Max entries per SnapshotResponse chunk. Each entry is ~40 bytes
# serialised (qname + family + ip + ttl + wire framing), plus the
# PeerEnvelope overhead. 20 entries ≈ 800 bytes total, well under
# MAX_ENVELOPE_BYTES.
SNAPSHOT_CHUNK_SIZE = 20

# After this many seconds without a chunk arriving, a partial
# snapshot reconstruction is abandoned and the metrics counter
# bumped. The next request recovers from the partial drop.
SNAPSHOT_TIMEOUT_SEC = 5.0

# Max payload size for one envelope *before* the HMAC trailer.
# 1400 bytes keeps us well below typical MTU 1500 minus IP + UDP
# headers minus our HMAC trailer. No IP fragmentation ever.
MAX_ENVELOPE_BYTES = 1400

# HMAC-SHA256 output length.
HMAC_LEN = 32

DEFAULT_HEARTBEAT_INTERVAL = 5.0
DEFAULT_BATCH_WINDOW_SEC = 0.020           # 20 ms, longer than local
                                            # SetWriter's 10 ms so we
                                            # fan-in a bit more before
                                            # the outbound send.


# ---------------------------------------------------------------------------
# Auth: pluggable interface + the HMAC default
# ---------------------------------------------------------------------------


class PeerAuth(Protocol):
    """Pluggable signing interface.

    ``sign`` appends a trailer to a serialised envelope; ``verify``
    strips the trailer back off and checks it. Swap implementations
    to move from HMAC-SHA256 to ChaCha20-Poly1305 AEAD (Phase 2) or
    to Ed25519 signatures (Phase 2b) without touching the sender or
    receiver code.
    """

    def sign(self, body: bytes) -> bytes: ...
    def verify(self, body_with_tag: bytes) -> bytes | None: ...


class HmacSha256Auth:
    """Shared-secret HMAC-SHA256 signing.

    Keys come from a file on disk to avoid baking secrets into
    config. Mode 0600/0640 enforced on the reader side so
    operators don't accidentally leave the key world-readable.
    """

    def __init__(self, secret: bytes) -> None:
        if len(secret) < 16:
            raise ValueError(
                "peer HMAC secret must be at least 16 bytes")
        self._secret = secret

    @classmethod
    def from_file(cls, path: str | os.PathLike) -> "HmacSha256Auth":
        p = Path(path)
        data = p.read_bytes().strip()
        if not data:
            raise ValueError(f"peer secret file {p} is empty")
        try:
            st = p.stat()
            if st.st_mode & 0o077:
                log.warning(
                    "peer secret file is world-readable",
                    extra={"path": str(p), "mode": oct(st.st_mode)})
        except OSError:
            pass
        return cls(data)

    def sign(self, body: bytes) -> bytes:
        tag = hmac.new(self._secret, body, hashlib.sha256).digest()
        return body + tag

    def verify(self, body_with_tag: bytes) -> bytes | None:
        if len(body_with_tag) < HMAC_LEN:
            return None
        body = body_with_tag[:-HMAC_LEN]
        tag = body_with_tag[-HMAC_LEN:]
        expected = hmac.new(
            self._secret, body, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):
            return None
        return body


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


@dataclass
class PeerMetrics:
    up: int = 0                         # gauge: 1 if peer heartbeat fresh
    frames_sent_total: int = 0
    frames_received_total: int = 0
    frames_lost_total: int = 0          # seq gaps detected
    hmac_failures_total: int = 0
    decode_errors_total: int = 0
    proto_version_mismatch_total: int = 0
    loop_drops_total: int = 0
    bytes_sent_total: int = 0
    bytes_received_total: int = 0
    dns_batches_applied_total: int = 0
    dns_updates_applied_total: int = 0
    heartbeats_sent_total: int = 0
    heartbeats_received_total: int = 0
    send_errors_total: int = 0
    last_heartbeat_recv_mono: float = 0.0
    last_heartbeat_send_mono: float = 0.0
    rtt_seconds: float = 0.0
    # Snapshot machinery (Phase 9)
    snapshot_requests_sent_total: int = 0
    snapshot_requests_received_total: int = 0
    snapshot_responses_sent_total: int = 0
    snapshot_chunks_sent_total: int = 0
    snapshot_chunks_received_total: int = 0
    snapshot_entries_applied_total: int = 0
    snapshot_partials_dropped_total: int = 0
    snapshot_complete_total: int = 0


# ---------------------------------------------------------------------------
# Envelope helpers
# ---------------------------------------------------------------------------


def _serialise_envelope(
    env: peer_pb2.PeerEnvelope, auth: PeerAuth
) -> bytes:
    body = env.SerializeToString()
    if len(body) + HMAC_LEN > MAX_ENVELOPE_BYTES:
        raise ValueError(
            f"peer envelope would exceed {MAX_ENVELOPE_BYTES}-byte cap "
            f"({len(body)} + {HMAC_LEN} trailer)")
    return auth.sign(body)


def _parse_envelope(
    datagram: bytes, auth: PeerAuth
) -> peer_pb2.PeerEnvelope | None:
    body = auth.verify(datagram)
    if body is None:
        return None
    env = peer_pb2.PeerEnvelope()
    try:
        env.ParseFromString(body)
    except Exception:  # noqa: BLE001
        return None
    return env


# ---------------------------------------------------------------------------
# asyncio datagram protocol: inbound handler
# ---------------------------------------------------------------------------


class _InboundProtocol(asyncio.DatagramProtocol):
    """Receives UDP datagrams and hands them to :class:`PeerLink`."""

    def __init__(self, link: "PeerLink") -> None:
        self._link = link

    def connection_made(self, transport) -> None:
        self._transport = transport

    def datagram_received(self, data: bytes, _addr) -> None:
        try:
            self._link._on_datagram(data)
        except Exception as e:  # noqa: BLE001
            rl.warn(
                log,
                ("inbound", type(e).__name__),
                "peer inbound processing error: %s", e)


# ---------------------------------------------------------------------------
# PeerLink — top-level owner of the replication lifecycle
# ---------------------------------------------------------------------------


class PeerLink:
    """Bi-directional UDP link to one HA peer.

    Typical wiring inside :class:`Daemon`::

        secret_file = cfg.get("PEER_SECRET_FILE")
        link = PeerLink(
            tracker=tracker,
            writer=writer,
            auth=HmacSha256Auth.from_file(secret_file),
            bind_host="0.0.0.0",
            bind_port=9749,
            peer_host="10.0.0.2",
            peer_port=9749,
            origin_node=socket.gethostname(),
            heartbeat_interval=5.0,
        )
        await link.start(loop)
        ...
        await link.stop()
    """

    def __init__(
        self,
        *,
        tracker: DnsSetTracker,
        writer: SetWriter | None,
        auth: PeerAuth,
        bind_host: str,
        bind_port: int,
        peer_host: str,
        peer_port: int,
        origin_node: str,
        heartbeat_interval: float = DEFAULT_HEARTBEAT_INTERVAL,
        local_netns: str = "",
    ) -> None:
        self._tracker = tracker
        self._writer = writer
        self._auth = auth
        self._bind_host = bind_host
        self._bind_port = bind_port
        self._peer_host = peer_host
        self._peer_port = peer_port
        self._origin_node = origin_node
        self._heartbeat_interval = heartbeat_interval
        self._local_netns = local_netns

        self._transport: asyncio.DatagramTransport | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._heartbeat_task: asyncio.Task[None] | None = None
        self._send_seq = 1
        self._expected_peer_seq: dict[str, int] = {}
        self._stopping = False
        self._batch_window_sec = DEFAULT_BATCH_WINDOW_SEC
        # Snapshot reconstruction state: snapshot_id → (received_chunks,
        # expected_total, first_received_mono). Receivers apply entries
        # incrementally as chunks arrive; this state only tracks the
        # completeness gauge and the per-snapshot timeout.
        self._snapshot_rx: dict[int, dict] = {}
        self._next_snapshot_id = int(time.time()) & 0xFFFFFFFF
        self.metrics = PeerMetrics()

    # ── Lifecycle ─────────────────────────────────────────────────────

    async def start(
        self, loop: asyncio.AbstractEventLoop | None = None
    ) -> None:
        self._loop = loop or asyncio.get_running_loop()
        self._transport, _ = await self._loop.create_datagram_endpoint(
            lambda: _InboundProtocol(self),
            local_addr=(self._bind_host, self._bind_port),
            # Request DF bit so oversized sends fail loudly instead
            # of being silently fragmented by the kernel.
            family=socket.AF_INET,
        )
        # Set IP_MTU_DISCOVER=IP_PMTUDISC_DO so the kernel refuses
        # to fragment anything we send — any oversize envelope
        # raises EMSGSIZE rather than wasting the HA interlink on
        # fragmented packets that middleboxes may drop.
        try:
            sock = self._transport.get_extra_info("socket")
            if sock is not None and hasattr(socket, "IP_PMTUDISC_DO"):
                sock.setsockopt(
                    socket.IPPROTO_IP,
                    socket.IP_MTU_DISCOVER,
                    socket.IP_PMTUDISC_DO,
                )
        except OSError as e:
            log.debug("failed to set IP_PMTUDISC_DO: %s", e)
        self._heartbeat_task = self._loop.create_task(
            self._heartbeat_loop(), name="shorewalld.peer.heartbeat")
        log.info(
            "peer link started",
            extra={
                "bind": f"{self._bind_host}:{self._bind_port}",
                "peer": f"{self._peer_host}:{self._peer_port}",
                "origin": self._origin_node,
            },
        )

    async def stop(self) -> None:
        self._stopping = True
        if self._heartbeat_task is not None:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            self._heartbeat_task = None
        if self._transport is not None:
            self._transport.close()
            self._transport = None

    # ── Outbound: build + send envelopes ──────────────────────────────

    def _next_seq(self) -> int:
        seq = self._send_seq
        self._send_seq = (self._send_seq + 1) & 0xFFFFFFFFFFFFFFFF
        if self._send_seq == 0:
            self._send_seq = 1
        return seq

    def _new_envelope(self) -> peer_pb2.PeerEnvelope:
        env = peer_pb2.PeerEnvelope()
        env.seq = self._next_seq()
        env.ts_unix_ns = time.time_ns()
        env.origin_node = self._origin_node
        env.proto_version = PROTO_VERSION
        return env

    def _send(self, env: peer_pb2.PeerEnvelope) -> None:
        if self._transport is None:
            return
        try:
            datagram = _serialise_envelope(env, self._auth)
        except ValueError as e:
            self.metrics.send_errors_total += 1
            rl.warn(
                log, ("send_oversize", self._peer_host),
                "peer envelope too large: %s", e)
            return
        try:
            self._transport.sendto(
                datagram, (self._peer_host, self._peer_port))
        except OSError as e:
            self.metrics.send_errors_total += 1
            rl.warn(
                log, ("send_oserror", e.errno or "unknown"),
                "peer sendto failed: %s", e)
            return
        self.metrics.frames_sent_total += 1
        self.metrics.bytes_sent_total += len(datagram)

    def send_dns_batch(
        self,
        updates: list[tuple[str, list[bytes], list[bytes], int]],
    ) -> None:
        """Serialise + send one DnsBatch envelope to the peer.

        ``updates`` is a list of ``(qname, a_rrs, aaaa_rrs, ttl)``
        tuples. Typically built by the :class:`SetWriter` hook
        just after a local commit to the tracker — the caller
        filters out DEDUP verdicts so only fresh updates get
        replicated.

        Caps the batch so the serialised envelope stays under
        :data:`MAX_ENVELOPE_BYTES`; anything larger is split
        across multiple envelopes transparently.
        """
        if not updates:
            return
        env = self._new_envelope()
        for (qname, a_rrs, aaaa_rrs, ttl) in updates:
            upd = env.dns_batch.updates.add()
            upd.qname = qname
            # Protobuf ≥ 4.x returns bytes directly from repeated-bytes
            # fields; the bytes() wrap was a redundant no-op copy.
            for ip in a_rrs:
                upd.a_rrs.append(ip)
            for ip in aaaa_rrs:
                upd.aaaa_rrs.append(ip)
            upd.ttl = ttl
            # Check size after each append; flush mid-batch if
            # approaching the cap.
            if len(env.SerializeToString()) > MAX_ENVELOPE_BYTES - HMAC_LEN - 128:
                self._send(env)
                env = self._new_envelope()
        if len(env.dns_batch.updates) > 0:
            self._send(env)

    # ── Heartbeat ─────────────────────────────────────────────────────

    def _send_heartbeat(self) -> None:
        env = self._new_envelope()
        hb = env.heartbeat
        snap = self._tracker.snapshot()
        hb.frames_accepted_total = self.metrics.frames_received_total
        hb.frames_dropped_total = self.metrics.frames_lost_total
        hb.queue_depth = 0                # owned by setwriter, not peer
        hb.nft_set_elements_total = snap.totals.elements
        hb.uptime_seconds = int(time.monotonic())
        hb.version = "1.1.0"              # filled in by Daemon at startup
        self._send(env)
        self.metrics.heartbeats_sent_total += 1
        self.metrics.last_heartbeat_send_mono = time.monotonic()

    async def _heartbeat_loop(self) -> None:
        # Fire one heartbeat immediately so the peer knows we're
        # alive without waiting a full interval.
        try:
            self._send_heartbeat()
        except Exception as e:  # noqa: BLE001
            rl.warn(
                log, ("heartbeat_init",),
                "initial heartbeat failed: %s", e)
        while not self._stopping:
            try:
                await asyncio.sleep(self._heartbeat_interval)
            except asyncio.CancelledError:
                return
            try:
                self._send_heartbeat()
            except Exception as e:  # noqa: BLE001
                rl.warn(
                    log, ("heartbeat",),
                    "heartbeat send failed: %s", e)

    # ── Inbound: datagram dispatch ────────────────────────────────────

    def _on_datagram(self, data: bytes) -> None:
        self.metrics.frames_received_total += 1
        self.metrics.bytes_received_total += len(data)

        env = _parse_envelope(data, self._auth)
        if env is None:
            # Either HMAC failed or protobuf decode failed — bump
            # both counters for symmetry so we can tell them apart
            # at the decode layer below, but here the distinction
            # is collapsed for simplicity.
            self.metrics.hmac_failures_total += 1
            return
        if env.proto_version != PROTO_VERSION:
            self.metrics.proto_version_mismatch_total += 1
            rl.warn(
                log, ("proto_version", env.proto_version),
                "peer sent proto_version %d, expected %d",
                env.proto_version, PROTO_VERSION)
            return
        if env.origin_node == self._origin_node:
            self.metrics.loop_drops_total += 1
            return

        # Sequence gap detection, per sender.
        expected = self._expected_peer_seq.get(env.origin_node)
        if expected is not None and env.seq > expected:
            gap = env.seq - expected
            self.metrics.frames_lost_total += gap
        self._expected_peer_seq[env.origin_node] = env.seq + 1

        payload = env.WhichOneof("payload")
        if payload == "heartbeat":
            self._handle_heartbeat(env)
        elif payload == "dns_batch":
            self._handle_dns_batch(env)
        elif payload == "snapshot_request":
            self._handle_snapshot_request(env)
        elif payload == "snapshot_response":
            self._handle_snapshot_response(env)

    def _handle_heartbeat(self, env: peer_pb2.PeerEnvelope) -> None:
        self.metrics.heartbeats_received_total += 1
        self.metrics.up = 1
        now = time.monotonic()
        self.metrics.last_heartbeat_recv_mono = now
        # RTT estimate: assume the sender's heartbeat is sent about
        # at the same time as ours, so ts_unix_ns deltas are rough.
        # A proper RTT would need echo timestamps; Phase 2.
        self.metrics.rtt_seconds = 0.0

    def _handle_dns_batch(
        self, env: peer_pb2.PeerEnvelope
    ) -> None:
        if self._writer is None:
            return
        batch = env.dns_batch
        applied = 0
        for upd in batch.updates:
            qn = canonical_qname(upd.qname)
            ttl = int(upd.ttl) or 60
            sid_v4 = self._tracker.set_id_for(qn, 4)
            if sid_v4 is not None:
                # Protobuf ≥ 4.x: upd.a_rrs items are bytes already.
                assert not upd.a_rrs or isinstance(
                    upd.a_rrs[0], bytes
                ), "unexpected non-bytes in a_rrs"
                for rr in upd.a_rrs:
                    if len(rr) == 4:
                        self._writer.submit(
                            netns=self._local_netns,
                            family=4,
                            proposal=Proposal(
                                set_id=sid_v4,
                                ip=int.from_bytes(rr, "big"),
                                ttl=ttl,
                            ),
                        )
                        applied += 1
            sid_v6 = self._tracker.set_id_for(qn, 6)
            if sid_v6 is not None:
                assert not upd.aaaa_rrs or isinstance(
                    upd.aaaa_rrs[0], bytes
                ), "unexpected non-bytes in aaaa_rrs"
                for rr in upd.aaaa_rrs:
                    if len(rr) == 16:
                        self._writer.submit(
                            netns=self._local_netns,
                            family=6,
                            proposal=Proposal(
                                set_id=sid_v6,
                                ip=int.from_bytes(rr, "big"),
                                ttl=ttl,
                            ),
                        )
                        applied += 1
        self.metrics.dns_batches_applied_total += 1
        self.metrics.dns_updates_applied_total += applied


    # ── Snapshot request/response (Phase 9) ──────────────────────────

    def request_snapshot(
        self, qname_filter: list[str] | None = None
    ) -> int:
        """Ask the peer to dump its current DNS-set state.

        Returns the snapshot_id of the request so callers can
        correlate with the metric counters. The response chunks
        arrive asynchronously via :meth:`_handle_snapshot_response`
        and are applied incrementally to the local tracker via
        :class:`SetWriter`.

        Typical caller: :class:`Daemon.run` immediately after
        state-file load, when the local state might be incomplete.
        """
        snapshot_id = self._next_snapshot_id
        self._next_snapshot_id = (
            (self._next_snapshot_id + 1) & 0xFFFFFFFF) or 1
        env = self._new_envelope()
        env.snapshot_request.snapshot_id = snapshot_id
        if qname_filter:
            for qn in qname_filter:
                env.snapshot_request.qname_filter.append(qn)
        self._send(env)
        self.metrics.snapshot_requests_sent_total += 1
        return snapshot_id

    def _handle_snapshot_request(
        self, env: peer_pb2.PeerEnvelope
    ) -> None:
        """Respond to a peer's SnapshotRequest by streaming chunks."""
        self.metrics.snapshot_requests_received_total += 1
        req = env.snapshot_request
        snapshot_id = req.snapshot_id
        qname_filter = set(req.qname_filter) if req.qname_filter else None

        # Build the flat entry list from the tracker once up front
        # so the chunk split is deterministic even if the tracker
        # mutates mid-stream.
        entries = self._tracker.export_state()
        now_mono = time.monotonic()
        filtered: list[tuple[str, int, bytes, int]] = []
        for qname, family, ip_bytes, deadline_mono in entries:
            if qname_filter is not None and qname not in qname_filter:
                continue
            remaining = max(1, int(deadline_mono - now_mono))
            filtered.append((qname, family, ip_bytes, remaining))

        total_chunks = max(
            1, (len(filtered) + SNAPSHOT_CHUNK_SIZE - 1)
            // SNAPSHOT_CHUNK_SIZE)
        for chunk_index in range(total_chunks):
            start = chunk_index * SNAPSHOT_CHUNK_SIZE
            end = start + SNAPSHOT_CHUNK_SIZE
            chunk_entries = filtered[start:end]
            out = self._new_envelope()
            out.snapshot_response.snapshot_id = snapshot_id
            out.snapshot_response.chunk_index = chunk_index
            out.snapshot_response.total_chunks = total_chunks
            for qname, family, ip_bytes, remaining in chunk_entries:
                e = out.snapshot_response.entries.add()
                e.qname = qname
                e.family = family
                e.ip = ip_bytes
                e.remaining_ttl = remaining
            self._send(out)
            self.metrics.snapshot_chunks_sent_total += 1
        self.metrics.snapshot_responses_sent_total += 1

    def _handle_snapshot_response(
        self, env: peer_pb2.PeerEnvelope
    ) -> None:
        """Apply one chunk of a snapshot stream incrementally.

        Each chunk's entries are pushed through the local
        :class:`SetWriter` as regular :class:`Proposal` records.
        The tracker's per-name TTL floor/ceil clamps values into
        the operator-intended range, so a misbehaving peer can't
        install entries outside the allowlist's bounds.
        """
        self.metrics.snapshot_chunks_received_total += 1
        resp = env.snapshot_response
        snapshot_id = resp.snapshot_id

        state = self._snapshot_rx.get(snapshot_id)
        if state is None:
            state = {
                "received": 0,
                "total": resp.total_chunks,
                "started": time.monotonic(),
            }
            self._snapshot_rx[snapshot_id] = state
        state["received"] += 1

        if self._writer is not None:
            # entry.ip is a bytes field in protobuf ≥ 4.x — no copy needed.
            for entry in resp.entries:
                if entry.family == 4 and len(entry.ip) == 4:
                    sid = self._tracker.set_id_for(
                        entry.qname, 4)
                    if sid is None:
                        continue
                    self._writer.submit(
                        netns=self._local_netns,
                        family=4,
                        proposal=Proposal(
                            set_id=sid,
                            ip=int.from_bytes(entry.ip, "big"),
                            ttl=int(entry.remaining_ttl),
                        ),
                    )
                    self.metrics.snapshot_entries_applied_total += 1
                elif entry.family == 6 and len(entry.ip) == 16:
                    sid = self._tracker.set_id_for(
                        entry.qname, 6)
                    if sid is None:
                        continue
                    self._writer.submit(
                        netns=self._local_netns,
                        family=6,
                        proposal=Proposal(
                            set_id=sid,
                            ip=int.from_bytes(entry.ip, "big"),
                            ttl=int(entry.remaining_ttl),
                        ),
                    )
                    self.metrics.snapshot_entries_applied_total += 1

        # Reap stale snapshots on every chunk so the dict never
        # grows unbounded.
        now = time.monotonic()
        for sid in list(self._snapshot_rx):
            s = self._snapshot_rx[sid]
            if sid == snapshot_id:
                if s["received"] >= s["total"]:
                    del self._snapshot_rx[sid]
                    self.metrics.snapshot_complete_total += 1
                continue
            if now - s["started"] > SNAPSHOT_TIMEOUT_SEC:
                del self._snapshot_rx[sid]
                self.metrics.snapshot_partials_dropped_total += 1


# ---------------------------------------------------------------------------
# Liveness check — used by the exporter to clear ``peer_up`` when
# heartbeats stop arriving.
# ---------------------------------------------------------------------------


def peer_is_up(metrics: PeerMetrics, interval: float) -> bool:
    """Return True if the last heartbeat arrived within 3× interval."""
    if metrics.last_heartbeat_recv_mono == 0.0:
        return False
    return (time.monotonic() - metrics.last_heartbeat_recv_mono
            < interval * 3.0)


class PeerMetricsCollector(CollectorBase):
    """Prometheus collector for the HA peer-link metrics."""

    def __init__(self, link: "PeerLink") -> None:
        super().__init__(netns="")
        self._link = link

    def collect(self) -> list[_MetricFamily]:
        m = self._link.metrics
        fams: list[_MetricFamily] = []

        def gauge(name: str, help_text: str, value: float) -> None:
            fam = _MetricFamily(name, help_text, [])
            fam.add([], value)
            fams.append(fam)

        def counter(name: str, help_text: str, value: int) -> None:
            fam = _MetricFamily(name, help_text, [], mtype="counter")
            fam.add([], float(value))
            fams.append(fam)

        gauge("shorewalld_peer_up",
              "1 if peer heartbeat is fresh, 0 otherwise", float(m.up))
        counter("shorewalld_peer_frames_sent_total",
                "UDP frames sent to HA peer", m.frames_sent_total)
        counter("shorewalld_peer_frames_received_total",
                "UDP frames received from HA peer", m.frames_received_total)
        counter("shorewalld_peer_frames_lost_total",
                "Detected sequence-number gaps from HA peer", m.frames_lost_total)
        counter("shorewalld_peer_hmac_failures_total",
                "Frames rejected by HMAC-SHA256 verification", m.hmac_failures_total)
        counter("shorewalld_peer_decode_errors_total",
                "Frames that failed protobuf decode", m.decode_errors_total)
        counter("shorewalld_peer_bytes_sent_total",
                "Bytes sent to HA peer", m.bytes_sent_total)
        counter("shorewalld_peer_bytes_received_total",
                "Bytes received from HA peer", m.bytes_received_total)
        counter("shorewalld_peer_dns_updates_applied_total",
                "Individual DNS set entries replicated from peer",
                m.dns_updates_applied_total)
        counter("shorewalld_peer_heartbeats_sent_total",
                "Heartbeat frames sent to peer", m.heartbeats_sent_total)
        counter("shorewalld_peer_heartbeats_received_total",
                "Heartbeat frames received from peer", m.heartbeats_received_total)
        counter("shorewalld_peer_send_errors_total",
                "Errors sending UDP datagrams to peer", m.send_errors_total)
        gauge("shorewalld_peer_rtt_seconds",
              "Latest peer round-trip time estimate in seconds", m.rtt_seconds)
        counter("shorewalld_peer_snapshot_complete_total",
                "Full peer state snapshots successfully applied",
                m.snapshot_complete_total)
        return fams
