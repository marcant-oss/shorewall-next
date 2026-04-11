"""Generated protobuf modules for shorewalld.

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
