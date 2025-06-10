from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

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
