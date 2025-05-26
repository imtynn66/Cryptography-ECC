from ecdsa.ecdsa import generator_128r1, curve_128r1
from Crypto.Util.number import long_to_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
import random

curve = curve_128r1
G = generator_128r1
n = G.order()
p = curve.p()
a = curve.a()

private_key = random.randrange(n)


def encrypt_data(shared_point, message):
    if shared_point.is_zero():
        x, y = 0, 0
    else:
        x, y = shared_point.xy()
    key = long_to_bytes(int(x)).rjust(16, b"\x00")
    iv = long_to_bytes(int(y)).rjust(16, b"\x00")
    cipher = AES.new(key, AES.MODE_CBC, iv)

    message = pad(message.encode(), 16)
    return cipher.encrypt(message)


def decrypt_data(shared_point, enc_message):
    if shared_point.is_zero():
        x, y = 0, 0
    else:
        x, y = shared_point.xy()
    key = long_to_bytes(int(x)).rjust(16, b"\x00")
    iv = long_to_bytes(int(y)).rjust(16, b"\x00")
    cipher = AES.new(key, AES.MODE_CBC, iv)

    decrypted = cipher.decrypt(enc_message)
    return unpad(decrypted, 16)


def ECDH(A):

    shared_point = private_key * A
    message = "Inconceivable!"
    return encrypt_data(shared_point, message)


def brute_force_encrypted_message(A, encrypted_message, max_order):
    for i in range(1, max_order):
        shared_point = i * A
        try:
            decrypted = decrypt_data(shared_point, encrypted_message)
            decrypted = decrypted.decode()
            return i
        except:
            continue
    raise Exception("Did not find a value for one of the encrypted messages")


def find_curves_with_small_subgroup(p, a, max_order):
    orders_found = set()
    b = 0
    while True:
        b += 1
        if b == p:
            # Ran out of b values
            break
        if (4*a^3 + 27*b^2) % p == 0:
            # Curve is singular
            continue

        E = EllipticCurve(GF(p), [a, b])
        for _ in range(100):
            R = E.random_point()
            n = R.order()
            for f, e in n.factor():
                if f in orders_found:
                    continue
                if f > max_order:
                    break

                # Create a point with order f
                orders_found.add(f)
                P = (n // f) * R
                assert P.order() == f
                yield (f, P)


subsolutions = []
subgroup = []
max_order = 10000
upto = 1
for order, A in find_curves_with_small_subgroup(p, a, max_order):
    upto *= order
    print("Found point with order", order, "so now can find keys of size up to", upto)

    encrypted_message = ECDH(A)

    key_mod_order = brute_force_encrypted_message(A, encrypted_message, max_order)

    subsolutions.append(key_mod_order)
    subgroup.append(order)

    if upto >= n:
        break

found_key = crt(subsolutions, subgroup)
print("Found private key", found_key)
assert private_key == found_key
print("success!")