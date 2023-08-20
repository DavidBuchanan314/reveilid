import base64


def encode(data: bytes) -> bytes:
	return base64.urlsafe_b64encode(data).rstrip(b"=")


def decode(data: bytes) -> bytes:
	decoded = base64.urlsafe_b64decode(data + b"==")  # python doesn't mind too much padding
	roundtrip = encode(decoded)  # this is kinda inefficient but it doesn't happen in any hot paths
	if roundtrip != data:
		raise Exception("non-canonical base64 encoding")
	return decoded
