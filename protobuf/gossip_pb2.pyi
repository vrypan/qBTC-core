import blockchain_pb2 as _blockchain_pb2
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class GossipMessageType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    UNKNOWN: _ClassVar[GossipMessageType]
    BLOCK: _ClassVar[GossipMessageType]
UNKNOWN: GossipMessageType
BLOCK: GossipMessageType

class GossipMessage(_message.Message):
    __slots__ = ("type", "block")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    BLOCK_FIELD_NUMBER: _ClassVar[int]
    type: GossipMessageType
    block: _blockchain_pb2.Block
    def __init__(self, type: _Optional[_Union[GossipMessageType, str]] = ..., block: _Optional[_Union[_blockchain_pb2.Block, _Mapping]] = ...) -> None: ...
