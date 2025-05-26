from ecdsa.ecdsa import curve_256, generator_256, Public_key, Private_key
from Crypto.Util.number import bytes_to_long,  long_to_bytes
from hashlib import sha256
import random
curve = curve_256
generator = generator_256
n = generator.order()
secret_key = 31793792271036091618790298616438342191207668866324683874629673835
public_key = Public_key(generator, generator * secret_key)
private_key = Private_key(public_key, secret_key)
k = random.randrange(curve.p())
message1 = "Putin met with world leaders to discuss regional stability."
message2 = "Trump announced a new campaign strategy during the rally."
z1 = bytes_to_long(sha256(message1.encode()).digest())
z2 = bytes_to_long(sha256(message2.encode()).digest())
signature1 = private_key.sign(z1, k)
signature2 = private_key.sign(z2, k)
found_k = (z1 - z2) * inverse_mod(signature1.s - signature2.s, n) % n
assert k == found_k
found_key = inverse_mod(signature1.r, n) * (found_k * signature1.s - z1) % n
assert found_key == secret_key
print("success!")
print("The secret is:", long_to_bytes(found_key).decode())
