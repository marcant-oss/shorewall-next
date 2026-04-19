"""Generated protobuf modules for shorewalld.

# Inject a compatibility shim for protobuf < 3.20 (e.g. AlmaLinux 10 ships
# 3.19.6).  The generated *_pb2.py files do
#   ``from google.protobuf.internal import builder as _builder``
# which fails on 3.19 because the builder sub-module was added in 3.20.
# Setting sys.modules before any pb2 import makes Python's import machinery
# find our shim instead of raising ImportError.
import sys as _sys

try:
    from google.protobuf.internal import builder as _pb_builder  # noqa: F401
except ImportError:
    from . import _builder_compat as _pb_builder  # type: ignore[assignment]
    _sys.modules.setdefault("google.protobuf.internal.builder", _pb_builder)

del _sys, _pb_builder



Source schemas live alongside the generated ``*_pb2.py`` files so
the generator can be re-run from ``Makefile`` / CI if the upstream
schema changes. Do not hand-edit the ``*_pb2.py`` files.

Schemas
-------

* ``dnstap.proto`` — dnstap framestream payload. Upstream:
  https://github.com/dnstap/dnstap.pb/blob/master/dnstap.proto
* ``dnsmessage.proto`` — PowerDNS recursor's protobufServer output.
  Upstream: pdns source tree, ``pdns/dnsmessage.proto``. Added in
  Phase 5.
* ``worker.proto`` — parent↔nft-worker control messages. Added in
  Phase 2 if/when the binary BatchBuilder becomes inadequate.
* ``peer.proto`` — HA peer replication envelope. Added in Phase 8.

Regeneration
------------

From the repository root::

    protoc --proto_path=shorewall_nft/daemon/proto \\
           --python_out=shorewall_nft/daemon/proto \\
           shorewall_nft/daemon/proto/dnstap.proto

The generated files are checked in so the package ships without
needing protoc on the build host.
"""
