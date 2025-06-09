from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class GossipMessageType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    UNKNOWN: _ClassVar[GossipMessageType]
    BLOCK: _ClassVar[GossipMessageType]
UNKNOWN: GossipMessageType
BLOCK: GossipMessageType

class BlocksRequest(_message.Message):
    __slots__ = ("start_block_number", "stop_block_number")
    START_BLOCK_NUMBER_FIELD_NUMBER: _ClassVar[int]
    STOP_BLOCK_NUMBER_FIELD_NUMBER: _ClassVar[int]
    start_block_number: int
    stop_block_number: int
    def __init__(self, start_block_number: _Optional[int] = ..., stop_block_number: _Optional[int] = ...) -> None: ...

class HeightMessage(_message.Message):
    __slots__ = ("height",)
    HEIGHT_FIELD_NUMBER: _ClassVar[int]
    height: int
    def __init__(self, height: _Optional[int] = ...) -> None: ...

class PeersMessage(_message.Message):
    __slots__ = ("peers",)
    PEERS_FIELD_NUMBER: _ClassVar[int]
    peers: _containers.RepeatedCompositeFieldContainer[Peer]
    def __init__(self, peers: _Optional[_Iterable[_Union[Peer, _Mapping]]] = ...) -> None: ...

class Peer(_message.Message):
    __slots__ = ("address", "height", "last_seen")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    HEIGHT_FIELD_NUMBER: _ClassVar[int]
    LAST_SEEN_FIELD_NUMBER: _ClassVar[int]
    address: str
    height: int
    last_seen: int
    def __init__(self, address: _Optional[str] = ..., height: _Optional[int] = ..., last_seen: _Optional[int] = ...) -> None: ...

class Block(_message.Message):
    __slots__ = ("version", "previous_hash", "block_hash", "merkle_root", "timestamp", "bits", "nonce", "miner_address", "tx")
    VERSION_FIELD_NUMBER: _ClassVar[int]
    PREVIOUS_HASH_FIELD_NUMBER: _ClassVar[int]
    BLOCK_HASH_FIELD_NUMBER: _ClassVar[int]
    MERKLE_ROOT_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    BITS_FIELD_NUMBER: _ClassVar[int]
    NONCE_FIELD_NUMBER: _ClassVar[int]
    MINER_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    TX_FIELD_NUMBER: _ClassVar[int]
    version: int
    previous_hash: bytes
    block_hash: bytes
    merkle_root: bytes
    timestamp: int
    bits: int
    nonce: int
    miner_address: bytes
    tx: _containers.RepeatedCompositeFieldContainer[Transaction]
    def __init__(self, version: _Optional[int] = ..., previous_hash: _Optional[bytes] = ..., block_hash: _Optional[bytes] = ..., merkle_root: _Optional[bytes] = ..., timestamp: _Optional[int] = ..., bits: _Optional[int] = ..., nonce: _Optional[int] = ..., miner_address: _Optional[bytes] = ..., tx: _Optional[_Iterable[_Union[Transaction, _Mapping]]] = ...) -> None: ...

class Transaction(_message.Message):
    __slots__ = ("txid", "inputs", "outputs", "body", "timestamp")
    TXID_FIELD_NUMBER: _ClassVar[int]
    INPUTS_FIELD_NUMBER: _ClassVar[int]
    OUTPUTS_FIELD_NUMBER: _ClassVar[int]
    BODY_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    txid: bytes
    inputs: _containers.RepeatedCompositeFieldContainer[Input]
    outputs: _containers.RepeatedCompositeFieldContainer[Output]
    body: TransactionBody
    timestamp: int
    def __init__(self, txid: _Optional[bytes] = ..., inputs: _Optional[_Iterable[_Union[Input, _Mapping]]] = ..., outputs: _Optional[_Iterable[_Union[Output, _Mapping]]] = ..., body: _Optional[_Union[TransactionBody, _Mapping]] = ..., timestamp: _Optional[int] = ...) -> None: ...

class TransactionBody(_message.Message):
    __slots__ = ("msg_str", "pubkey", "signature")
    MSG_STR_FIELD_NUMBER: _ClassVar[int]
    PUBKEY_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    msg_str: bytes
    pubkey: bytes
    signature: bytes
    def __init__(self, msg_str: _Optional[bytes] = ..., pubkey: _Optional[bytes] = ..., signature: _Optional[bytes] = ...) -> None: ...

class Input(_message.Message):
    __slots__ = ("txid", "utxo_index", "sender", "receiver", "amount", "spent")
    TXID_FIELD_NUMBER: _ClassVar[int]
    UTXO_INDEX_FIELD_NUMBER: _ClassVar[int]
    SENDER_FIELD_NUMBER: _ClassVar[int]
    RECEIVER_FIELD_NUMBER: _ClassVar[int]
    AMOUNT_FIELD_NUMBER: _ClassVar[int]
    SPENT_FIELD_NUMBER: _ClassVar[int]
    txid: bytes
    utxo_index: int
    sender: bytes
    receiver: bytes
    amount: int
    spent: bool
    def __init__(self, txid: _Optional[bytes] = ..., utxo_index: _Optional[int] = ..., sender: _Optional[bytes] = ..., receiver: _Optional[bytes] = ..., amount: _Optional[int] = ..., spent: bool = ...) -> None: ...

class Output(_message.Message):
    __slots__ = ("txid", "utxo_index", "sender", "receiver", "amount", "spent")
    TXID_FIELD_NUMBER: _ClassVar[int]
    UTXO_INDEX_FIELD_NUMBER: _ClassVar[int]
    SENDER_FIELD_NUMBER: _ClassVar[int]
    RECEIVER_FIELD_NUMBER: _ClassVar[int]
    AMOUNT_FIELD_NUMBER: _ClassVar[int]
    SPENT_FIELD_NUMBER: _ClassVar[int]
    txid: bytes
    utxo_index: int
    sender: bytes
    receiver: bytes
    amount: int
    spent: bool
    def __init__(self, txid: _Optional[bytes] = ..., utxo_index: _Optional[int] = ..., sender: _Optional[bytes] = ..., receiver: _Optional[bytes] = ..., amount: _Optional[int] = ..., spent: bool = ...) -> None: ...

class GossipMessage(_message.Message):
    __slots__ = ("type", "block")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    BLOCK_FIELD_NUMBER: _ClassVar[int]
    type: GossipMessageType
    block: Block
    def __init__(self, type: _Optional[_Union[GossipMessageType, str]] = ..., block: _Optional[_Union[Block, _Mapping]] = ...) -> None: ...
