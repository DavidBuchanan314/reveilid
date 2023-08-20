import envelope
from cryptosystem import cryptosystems as cryptos
import vld0
cryptos.register(vld0.VLD0Public, vld0.VLD0Secret)

privkey = cryptos.parse_secret_string("VLD0:THmGEpj0Jdt5GjYO-FcbEp-YigWoAeF70eonnP-IleU")
#privkey = cryptos.get_secret_cryptosystem(b"VLD0").generate()
pubkey = privkey.public()
print("secret:", privkey)
print("public:", pubkey)

pubkey2 = cryptos.parse_public_string(str(pubkey))
print("public2:", pubkey2)

symmetric = privkey.exchange(pubkey)
print(symmetric.unauthed_encrypt(b"hello", b"A"*24))

env = envelope.pack(privkey, pubkey, b"hello")
print(env)

res = envelope.unpack(privkey, pubkey, env)
print(res)
