import os
import cryptosystem
import lz4.block
from util import time_now_micros


def pack(sender_priv: cryptosystem.CryptoSecret, recip_pub: cryptosystem.CryptoPublic, payload: bytes) -> bytes:
	if sender_priv.CRYPTO_KIND != recip_pub.CRYPTO_KIND:
		raise ValueError("crypto kind mismatch")

	# todo: check max lengths

	compressed_with_length = lz4.block.compress(payload, store_size=True)

	nonce = os.urandom(24)
	encrypted_payload = sender_priv.exchange(recip_pub).unauthed_encrypt(compressed_with_length, nonce)

	msg = b""
	msg += b"VLD" # magic
	msg += b"\x00" # version
	msg += sender_priv.CRYPTO_KIND
	msg += (0x6a + 0x40 + len(encrypted_payload)).to_bytes(2, "little") # size (of whole packet)
	msg += time_now_micros().to_bytes(8, "little") # time (epoch micros)
	msg += nonce # 24 bytes
	msg += bytes(sender_priv.public()) # sender id 32 bytes
	msg += bytes(recip_pub) # 32 bytes
	msg += encrypted_payload

	sig = sender_priv.sign(msg)
	
	msg += sig
	return msg


def unpack(recip_priv: cryptosystem.CryptoSecret, sender_pub: cryptosystem.CryptoPublic, envelope: bytes) -> bytes:
	if recip_priv.CRYPTO_KIND != sender_pub.CRYPTO_KIND:
		raise ValueError("crypto kind mismatch")

	if envelope[:3] != b"VLD":
		raise Exception("bad envelope magic")

	if envelope[3] != 0:
		raise Exception("bad version")
	
	if envelope[4:8] != recip_priv.CRYPTO_KIND:
		raise Exception("bad crypto_kind")
	
	# TODO: also check for max
	if int.from_bytes(envelope[8:10], "little") != len(envelope):
		raise Exception("bad envelope length")
	
	# TODO: care about timestamps
	timestamp = int.from_bytes(envelope[10:18], "little")

	nonce = envelope[18:42]

	if envelope[42:74] != bytes(sender_pub):
		raise Exception("unexpected sender pubkey value")
	
	if envelope[74:106] != bytes(recip_priv.public()):
		raise Exception("unexpected recipient pubkey value")
	
	signature = envelope[-64:]

	sender_pub.verify(envelope[:-64], signature) # throws on bad sig

	plaintext = recip_priv.exchange(sender_pub).unauthed_decrypt(envelope[106:-64], nonce)

	decompressed_len = int.from_bytes(plaintext[:4], "little")
	if decompressed_len > 0x10000:  # XXX pick correct limit!!!
		raise Exception("payload too big")
	
	return lz4.block.decompress(plaintext[4:], decompressed_len)
