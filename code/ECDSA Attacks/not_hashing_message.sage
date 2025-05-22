from ecdsa import SigningKey, NIST256p

signing_key = SigningKey.generate(NIST256p)
verifying_key = signing_key.verifying_key

class MyHash:
    def __init__(self, data):
        self.data = data

    def digest(self):
        return self.data

message = "Please authorize a payment of $500 to Alice for consulting services."
signature = signing_key.sign(message.encode(), hashfunc=MyHash)
assert verifying_key.verify(signature, message.encode(), hashfunc=MyHash)

evil_message = "Please authorize a payment of $500 to Alice and $100,000 to Mallory's offshore account."
assert verifying_key.verify(signature, evil_message.encode(), hashfunc=MyHash)
print("success!")
