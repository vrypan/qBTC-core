from . import blockchain_pb2 as _blockchain_pb2
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
    TRANSACTION: _ClassVar[GossipMessageType]
    STATUS: _ClassVar[GossipMessageType]
UNKNOWN: GossipMessageType
BLOCK: GossipMessageType
TRANSACTION: GossipMessageType
STATUS: GossipMessageType

class GossipMessage(_message.Message):
    __slots__ = ("type", "block", "transaction_data", "status_data")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    BLOCK_FIELD_NUMBER: _ClassVar[int]
    TRANSACTION_DATA_FIELD_NUMBER: _ClassVar[int]
    STATUS_DATA_FIELD_NUMBER: _ClassVar[int]
    type: GossipMessageType
    block: _blockchain_pb2.Block
    transaction_data: GossipTransactionData
    status_data: GossipStatusData
    def __init__(self, type: _Optional[_Union[GossipMessageType, str]] = ..., block: _Optional[_Union[_blockchain_pb2.Block, _Mapping]] = ..., transaction_data: _Optional[_Union[GossipTransactionData, _Mapping]] = ..., status_data: _Optional[_Union[GossipStatusData, _Mapping]] = ...) -> None: ...

class GossipStatusData(_message.Message):
    __slots__ = ("mempool_size", "tip_hash")
    MEMPOOL_SIZE_FIELD_NUMBER: _ClassVar[int]
    TIP_HASH_FIELD_NUMBER: _ClassVar[int]
    mempool_size: int
    tip_hash: bytes
    def __init__(self, mempool_size: _Optional[int] = ..., tip_hash: _Optional[bytes] = ...) -> None: ...

class GossipTransactionData(_message.Message):
    __slots__ = ("hash", "transaction")
    HASH_FIELD_NUMBER: _ClassVar[int]
    TRANSACTION_FIELD_NUMBER: _ClassVar[int]
    hash: bytes
    transaction: _blockchain_pb2.Transaction
    def __init__(self, hash: _Optional[bytes] = ..., transaction: _Optional[_Union[_blockchain_pb2.Transaction, _Mapping]] = ...) -> None: ...
