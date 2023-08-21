from typing import Self, Any
from dataclasses import dataclass
from abc import ABC, abstractmethod
from proto import veilid_capnp as proto

class WireSerDes(ABC):
	"""
	to and from types that are either capnproto objects themselves, or primitive field values
	"""

	@classmethod
	@abstractmethod
	def from_proto(cls, proto: Any) -> Self:
		pass

	@abstractmethod
	def to_proto(self) -> Any:
		pass


@dataclass(frozen=True)
class FourCC(WireSerDes):
	fourcc_bytes: bytes
	
	@classmethod
	def from_proto(cls, proto: int) -> Self:
		return cls(proto.to_bytes(4, "big"))
	
	def to_proto(self) -> int:
		return int.from_bytes(self.fourcc_bytes, "big")


@dataclass(frozen=True)
class CryptoKey(WireSerDes):
	key_bytes: bytes

	@classmethod
	def from_proto(cls, proto: proto.Key256) -> Self:
		return cls(
			proto.u0.to_bytes(8, "big") +
			proto.u1.to_bytes(8, "big") +
			proto.u2.to_bytes(8, "big") +
			proto.u3.to_bytes(8, "big")
		)

	def to_proto(self) -> proto.Key256:
		return proto.Key256(
			u0=int.from_bytes(self.key_bytes[0*8:1*8], "big"),
			u1=int.from_bytes(self.key_bytes[1*8:2*8], "big"),
			u2=int.from_bytes(self.key_bytes[2*8:3*8], "big"),
			u3=int.from_bytes(self.key_bytes[3*8:4*8], "big")
		)


@dataclass(frozen=True)
class TypedKey(WireSerDes):
	crypto_kind: bytes
	key: bytes

	@classmethod
	def from_proto(cls, proto: proto.TypedKey) -> Self:
		return cls(
			FourCC.from_proto(proto.kind).fourcc_bytes,
			CryptoKey.from_proto(proto.key).key_bytes
		)

	def to_proto(self) -> proto.TypedKey:
		return proto.TypedKey(
			kind=FourCC(self.crypto_kind).to_proto(),
			key=CryptoKey(self.key).to_proto()
		)


@dataclass(frozen=True)
class CryptoSignature(WireSerDes):
	signature_bytes: bytes

	@classmethod
	def from_proto(cls, proto: proto.Signature512) -> Self:
		return cls(
			proto.u0.to_bytes(8, "big") +
			proto.u1.to_bytes(8, "big") +
			proto.u2.to_bytes(8, "big") +
			proto.u3.to_bytes(8, "big") +
			proto.u4.to_bytes(8, "big") +
			proto.u5.to_bytes(8, "big") +
			proto.u6.to_bytes(8, "big") +
			proto.u7.to_bytes(8, "big")
		)
	
	def to_proto(self) -> proto.Signature512:
		return proto.Signature512(
			u0=int.from_bytes(self.signature_bytes[0*8:1*8], "big"),
			u1=int.from_bytes(self.signature_bytes[1*8:2*8], "big"),
			u2=int.from_bytes(self.signature_bytes[2*8:3*8], "big"),
			u3=int.from_bytes(self.signature_bytes[3*8:4*8], "big"),
			u4=int.from_bytes(self.signature_bytes[4*8:5*8], "big"),
			u5=int.from_bytes(self.signature_bytes[5*8:6*8], "big"),
			u6=int.from_bytes(self.signature_bytes[6*8:7*8], "big"),
			u7=int.from_bytes(self.signature_bytes[7*8:8*8], "big")
		)


@dataclass(frozen=True)
class CryptoNonce(WireSerDes):
	nonce_bytes: bytes

	@classmethod
	def from_proto(cls, proto: proto.Nonce24) -> Self:
		return cls(
			proto.u0.to_bytes(8, "big") +
			proto.u1.to_bytes(8, "big") +
			proto.u2.to_bytes(8, "big")
		)
	
	def to_proto(self) -> proto.Nonce24:
		return proto.Nonce24(
			u0=int.from_bytes(self.nonce_bytes[0*8:1*8], "big"),
			u1=int.from_bytes(self.nonce_bytes[1*8:2*8], "big"),
			u2=int.from_bytes(self.nonce_bytes[2*8:3*8], "big")
		)
