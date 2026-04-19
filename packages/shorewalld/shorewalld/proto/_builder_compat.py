"""Compatibility shim: google.protobuf.internal.builder for protobuf < 3.20.

protobuf ≥ 3.20 added google.protobuf.internal.builder with
BuildMessageAndEnumDescriptors / BuildTopDescriptorsAndMessages.
AlmaLinux 10 (AppStream) ships protobuf 3.19.6 which lacks it.
This module is injected into sys.modules under the canonical name
by proto/__init__.py when the real module is absent.
"""
from __future__ import annotations

from google.protobuf import message_factory as _message_factory
from google.protobuf import symbol_database as _sym_db_module


def BuildMessageAndEnumDescriptors(file_descriptor, module_dict):  # noqa: N802
    """Populate module_dict with _TYPENAME descriptor stubs.

    In modern protobuf this feeds the pure-Python descriptor backend
    (_USE_C_DESCRIPTORS == False).  With the C extension (the default
    for distro-packaged protobuf 3.x) the block that reads these is
    gated behind ``if _descriptor._USE_C_DESCRIPTORS == False`` and
    never executes.  We still add the keys so the NameError never fires.
    """
    def _walk(desc, prefix: str) -> None:
        key = "_" + (prefix + desc.name).upper()
        module_dict[key] = desc
        for nested in desc.nested_types:
            _walk(nested, prefix + desc.name + "_")
        for enum in desc.enum_types:
            module_dict["_" + (prefix + desc.name + "_" + enum.name).upper()] = enum

    for msg_desc in file_descriptor.message_types_by_name.values():
        _walk(msg_desc, "")
    for enum_desc in file_descriptor.enum_types_by_name.values():
        module_dict["_" + enum_desc.name.upper()] = enum_desc


def BuildTopDescriptorsAndMessages(file_descriptor, proto_module_name, module_dict):  # noqa: N802
    """Create message classes and register them in module_dict."""
    sym_db = _sym_db_module.Default()
    factory = _message_factory.MessageFactory()

    def _add(msg_desc) -> None:
        cls = factory.GetPrototype(msg_desc)
        module_dict[msg_desc.name] = cls
        try:
            sym_db.RegisterMessage(cls)
        except Exception:  # noqa: BLE001
            pass
        for nested in msg_desc.nested_types:
            _add(nested)

    for msg_desc in file_descriptor.message_types_by_name.values():
        _add(msg_desc)
