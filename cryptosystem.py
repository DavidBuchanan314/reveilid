from abc import ABC, abstractmethod
from typing import Dict, Tuple, Type, Self
import urlsafeb64nopad


class CryptoException(Exception):
	"""
	Generic cryptography error - might make this more specific
	"""
	pass


class CryptoSymmetric(ABC):
	@abstractmethod
	def __init__(self, key: bytes) -> None:
		pass

	@abstractmethod
	def unauthed_encrypt(self, message: bytes, nonce: bytes) -> bytes:
		pass

	@abstractmethod
	def unauthed_decrypt(self, message: bytes, nonce: bytes) -> bytes:
		pass

	@abstractmethod
	def aead_encrypt(self, plaintext: bytes) -> bytes:
		pass

	@abstractmethod
	def aead_decrypt(self, ciphertext: bytes) -> bytes:
		pass


class CryptoPublic(ABC):
	CRYPTO_KIND: bytes

	@abstractmethod
	def __init__(self, public_bytes: bytes) -> None:
		pass

	@abstractmethod
	def verify(self, message: bytes, signature: bytes) -> None:
		"""
		Raises an exception on verification failure
		"""
		pass

	@abstractmethod
	def __bytes__(self) -> bytes:
		pass

	def __str__(self) -> str:
		return self.CRYPTO_KIND.decode() + ":" + \
			urlsafeb64nopad.encode(bytes(self)).decode()

	def __repr__(self) -> str:
		return f"{self.__class__.__name__}({str(self)})"


class CryptoSecret(ABC):
	CRYPTO_KIND: bytes

	@abstractmethod
	def __init__(self, secret_bytes: bytes) -> None:
		pass

	@classmethod
	@abstractmethod
	def generate(cls) -> Self:
		pass

	@abstractmethod
	def public(self) -> CryptoPublic:
		pass

	@abstractmethod
	def sign(self, message: bytes) -> bytes:
		pass

	@abstractmethod
	def exchange(self, peer_public: CryptoPublic) -> CryptoSymmetric:
		"""
		Derive a shared secret, and use it to instantiate a symmetric cryptosystem object
		"""
		pass
	
	@abstractmethod
	def __bytes__(self) -> bytes:
		pass

	def __str__(self) -> str:
		return self.CRYPTO_KIND.decode() + ":" + \
			urlsafeb64nopad.encode(bytes(self)).decode()
	
	def __repr__(self) -> str:
		return f"{self.__class__.__name__}([REDACTED])"


class CryptosystemManager:
	cryptosystems_pub: Dict[bytes, Type[CryptoPublic]] = {}
	cryptosystems_sec: Dict[bytes, Type[CryptoSecret]] = {}

	def register(self, public_impl: Type[CryptoPublic], secret_impl: Type[CryptoSecret]) -> None:
		if public_impl.CRYPTO_KIND != secret_impl.CRYPTO_KIND:
			raise ValueError("CRYPTO_KIND mismatch")
		self.cryptosystems_pub[public_impl.CRYPTO_KIND] = public_impl
		self.cryptosystems_sec[secret_impl.CRYPTO_KIND] = secret_impl

	def get_public_cryptosystem(self, kind: bytes) -> Type[CryptoPublic]:
		return self.cryptosystems_pub[kind]
	
	def get_secret_cryptosystem(self, kind: bytes) -> Type[CryptoSecret]:
		return self.cryptosystems_sec[kind]
	
	def _parse_typed_string(self, data: str) -> Tuple[bytes, bytes]:
		if data[4] != ":":
			raise CryptoException("bad encoded key format")
		fourcc = data[:4].encode()
		body = urlsafeb64nopad.decode(data[5:].encode())
		return fourcc, body

	def parse_public_string(self, data: str) -> CryptoPublic:
		fourcc, body = self._parse_typed_string(data)
		return self.get_public_cryptosystem(fourcc)(body)
	
	def parse_secret_string(self, data: str) -> CryptoSecret:
		fourcc, body = self._parse_typed_string(data)
		return self.get_secret_cryptosystem(fourcc)(body)


cryptosystems = CryptosystemManager()
