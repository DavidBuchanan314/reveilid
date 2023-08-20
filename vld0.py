from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import ChaCha20
import ed25519_dalek # https://github.com/DavidBuchanan314/py-ed25519-bindings
from cryptosystem import CryptoPublic, CryptoSecret, CryptoSymmetric, CryptoException
from typing import Self
from blake3 import blake3

VLD0_KIND = b"VLD0"

VLD0_DOMAIN_SIGN = b"VLD0_SIGN"
VLD0_DOMAIN_CRYPT = b"VLD0_CRYPT"


class VLD0Symmetric(CryptoSymmetric):
	def __init__(self, key: bytes) -> None:
		if len(key) != 32:
			raise ValueError("incorrect key length")
		self.key = key

	def unauthed_encrypt(self, message: bytes, nonce: bytes) -> bytes:
		if len(nonce) != 24:
			raise ValueError("incorrect nonce length")
		# when a 24-byte nonce is passed, pycryptodome uses xchacha20 according to https://datatracker.ietf.org/doc/html/draft-arciszewski-xchacha-03
		# annoyingly, cryptography.io doesn't seem to offer a way to use xchacha20.
		return ChaCha20.new(key=self.key, nonce=nonce).encrypt(message)
	
	def unauthed_decrypt(self, message: bytes, nonce: bytes) -> bytes:
		if len(nonce) != 24:
			raise ValueError("incorrect nonce length")
		return ChaCha20.new(key=self.key, nonce=nonce).decrypt(message)

	def aead_encrypt(self, plaintext: bytes) -> bytes:
		raise Exception("todo")
	
	def aead_decrypt(self, ciphertext: bytes) -> bytes:
		raise Exception("todo")

class VLD0Public(CryptoPublic):
	CRYPTO_KIND = VLD0_KIND

	def __init__(self, public_bytes: bytes) -> None:
		if len(public_bytes) != 32:
			raise ValueError("incorrect public_bytes length")
		self.pubkey_ed = Ed25519PublicKey.from_public_bytes(public_bytes)
		self.pubkey_x = vld0_ed25519_to_x25519_pub(self.pubkey_ed)

	def verify(self, message: bytes, signature: bytes) -> None:
		if not ed25519_dalek.ed_verify_sha512_ph_ctx(signature, message, VLD0_DOMAIN_SIGN, self.pubkey_ed.public_bytes_raw()):
			raise CryptoException("invalid signature")
	
	def __bytes__(self) -> bytes:
		return self.pubkey_ed.public_bytes_raw()


class VLD0Secret(CryptoSecret):
	CRYPTO_KIND = VLD0_KIND

	def __init__(self, secret_bytes: bytes) -> None:
		if len(secret_bytes) != 32:
			raise ValueError("incorrect secret_bytes length")
		self.privkey_ed = Ed25519PrivateKey.from_private_bytes(secret_bytes)
		self.privkey_x = vld0_ed25519_to_x25519_priv(self.privkey_ed)
	
	@classmethod
	def generate(cls) -> Self:
		return cls(Ed25519PrivateKey.generate().private_bytes_raw())

	def public(self) -> CryptoPublic:
		return VLD0Public(self.privkey_ed.public_key().public_bytes_raw())
	
	def sign(self, message: bytes) -> bytes:
		dalek_priv, dalek_pub = ed25519_dalek.ed_from_seed(self.privkey_ed.private_bytes_raw())
		return ed25519_dalek.ed_sign_sha512_ph_ctx(dalek_pub, dalek_priv, VLD0_DOMAIN_SIGN, message)
	
	def exchange(self, peer_public: VLD0Public) -> CryptoSymmetric:
		shared_secret = self.privkey_x.exchange(peer_public.pubkey_x)
		derived = blake3(VLD0_DOMAIN_CRYPT + shared_secret).digest()
		return VLD0Symmetric(derived)
	
	def __bytes__(self) -> bytes:
		return self.privkey_ed.private_bytes_raw()


def vld0_ed25519_to_x25519_priv(edkey: Ed25519PrivateKey) -> X25519PrivateKey:
	hasher = hashes.Hash(hashes.SHA512())
	hasher.update(edkey.private_bytes_raw())
	h = hasher.finalize()
	# X25519PrivateKey.from_private_bytes will handle clamping for us
	return X25519PrivateKey.from_private_bytes(h[:32])


def vld0_ed25519_to_x25519_pub(edkey: Ed25519PublicKey) -> X25519PublicKey:
	"""
	DANGER DANGER DANGER THIS FUNCTION IS CRYPTOGRAPHICALLY UNSAFE
	IT DOES NOT HAVE THE REQUIRED CHECKS

	see https://github.com/pyca/cryptography/issues/5557#issuecomment-1202986332
	for something better but with nonzero dependencies
	"""

	ed_y = int.from_bytes(edkey.public_bytes_raw(), "little")
	ed_y &= (2**255 - 1) # mask off high bit (TODO: can we use this for malleability?)
	q = 2**255 - 19
	x = ((ed_y + 1) * pow(1 - ed_y, -1, q)) % q
	x_bytes = x.to_bytes(32, "little")
	return X25519PublicKey.from_public_bytes(x_bytes)
