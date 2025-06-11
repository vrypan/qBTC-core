from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Block(_message.Message):
    __slots__ = ("size", "hash", "height", "header", "transaction_count", "tx")
    SIZE_FIELD_NUMBER: _ClassVar[int]
    HASH_FIELD_NUMBER: _ClassVar[int]
    HEIGHT_FIELD_NUMBER: _ClassVar[int]
    HEADER_FIELD_NUMBER: _ClassVar[int]
    TRANSACTION_COUNT_FIELD_NUMBER: _ClassVar[int]
    TX_FIELD_NUMBER: _ClassVar[int]
    size: int
    hash: bytes
    height: int
    header: BlockHeader
    transaction_count: int
    tx: _containers.RepeatedCompositeFieldContainer[Transaction]
    def __init__(self, size: _Optional[int] = ..., hash: _Optional[bytes] = ..., height: _Optional[int] = ..., header: _Optional[_Union[BlockHeader, _Mapping]] = ..., transaction_count: _Optional[int] = ..., tx: _Optional[_Iterable[_Union[Transaction, _Mapping]]] = ...) -> None: ...

class BlockHeader(_message.Message):
    __slots__ = ("version", "previous_hash", "merkle_root", "timestamp", "difficulty", "nonce")
    VERSION_FIELD_NUMBER: _ClassVar[int]
    PREVIOUS_HASH_FIELD_NUMBER: _ClassVar[int]
    MERKLE_ROOT_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    DIFFICULTY_FIELD_NUMBER: _ClassVar[int]
    NONCE_FIELD_NUMBER: _ClassVar[int]
    version: int
    previous_hash: bytes
    merkle_root: bytes
    timestamp: int
    difficulty: int
    nonce: int
    def __init__(self, version: _Optional[int] = ..., previous_hash: _Optional[bytes] = ..., merkle_root: _Optional[bytes] = ..., timestamp: _Optional[int] = ..., difficulty: _Optional[int] = ..., nonce: _Optional[int] = ...) -> None: ...

class Transaction(_message.Message):
    __slots__ = ("version", "inputs", "outputs", "locktime")
    VERSION_FIELD_NUMBER: _ClassVar[int]
    INPUTS_FIELD_NUMBER: _ClassVar[int]
    OUTPUTS_FIELD_NUMBER: _ClassVar[int]
    LOCKTIME_FIELD_NUMBER: _ClassVar[int]
    version: bytes
    inputs: _containers.RepeatedCompositeFieldContainer[TxInput]
    outputs: _containers.RepeatedCompositeFieldContainer[TxOutput]
    locktime: int
    def __init__(self, version: _Optional[bytes] = ..., inputs: _Optional[_Iterable[_Union[TxInput, _Mapping]]] = ..., outputs: _Optional[_Iterable[_Union[TxOutput, _Mapping]]] = ..., locktime: _Optional[int] = ...) -> None: ...

class TxInput(_message.Message):
    __slots__ = ("txid", "vout", "script_sig", "sequence")
    TXID_FIELD_NUMBER: _ClassVar[int]
    VOUT_FIELD_NUMBER: _ClassVar[int]
    SCRIPT_SIG_FIELD_NUMBER: _ClassVar[int]
    SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    txid: bytes
    vout: int
    script_sig: bytes
    sequence: int
    def __init__(self, txid: _Optional[bytes] = ..., vout: _Optional[int] = ..., script_sig: _Optional[bytes] = ..., sequence: _Optional[int] = ...) -> None: ...

class TxOutput(_message.Message):
    __slots__ = ("value", "script_pubkey")
    VALUE_FIELD_NUMBER: _ClassVar[int]
    SCRIPT_PUBKEY_FIELD_NUMBER: _ClassVar[int]
    value: int
    script_pubkey: bytes
    def __init__(self, value: _Optional[int] = ..., script_pubkey: _Optional[bytes] = ...) -> None: ...

class DbBlock(_message.Message):
    __slots__ = ("hash", "height", "header", "transaction_count", "txid")
    HASH_FIELD_NUMBER: _ClassVar[int]
    HEIGHT_FIELD_NUMBER: _ClassVar[int]
    HEADER_FIELD_NUMBER: _ClassVar[int]
    TRANSACTION_COUNT_FIELD_NUMBER: _ClassVar[int]
    TXID_FIELD_NUMBER: _ClassVar[int]
    hash: bytes
    height: int
    header: BlockHeader
    transaction_count: int
    txid: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, hash: _Optional[bytes] = ..., height: _Optional[int] = ..., header: _Optional[_Union[BlockHeader, _Mapping]] = ..., transaction_count: _Optional[int] = ..., txid: _Optional[_Iterable[bytes]] = ...) -> None: ...

class Utxo(_message.Message):
    __slots__ = ("txid", "vout", "output")
    TXID_FIELD_NUMBER: _ClassVar[int]
    VOUT_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_FIELD_NUMBER: _ClassVar[int]
    txid: bytes
    vout: int
    output: TxOutput
    def __init__(self, txid: _Optional[bytes] = ..., vout: _Optional[int] = ..., output: _Optional[_Union[TxOutput, _Mapping]] = ...) -> None: ...
