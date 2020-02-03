from Cryptodome.Util import *  # noqa
import math
import random
from typing import List, Tuple


def rsa(length: int = 1024) -> Tuple[Tuple, Tuple]:
    """Generates the public and private for RSA encryption."""
    p, q = number.getPrime(length), number.getPrime(length)  # noqa
    n = p * q
    phi = (p - 1) * (q - 1)

    while True:
        e = number.getRandomRange(a=1, b=phi)  # noqa
        if coprime(e, phi):
            break
    d = modinv(e, phi)
    return (n, e), (n, d)


def cipher_RSA(
    text_message: str, public_key: Tuple, block_len=None
) -> List[int]:  # noqa
    """Ciphers a message using RSA."""
    if not block_len:
        block_len = int(math.log(len_, 2) - 1)
    n = public_key[0]
    e = public_key[1]
    number_message = "".join([to_number(char) for char in text_message])
    blocks, padding = to_blocks(number_message, block_len, return_type=int)
    return [pow(block, e, n) for block in blocks], padding


def decipher_RSA(
    ciphers: List[int], private_key: Tuple, padding, block_len=None
) -> str:
    """Deciphers a message using RSA."""
    if not block_len:
        block_len = int(math.log(len_, 2) - 1)
    n = private_key[0]
    d = private_key[1]
    deciphered = [pow(cipher, d, n) for cipher in ciphers]
    deciphered = pad_with_zeros(deciphered, block_len)
    return to_text("".join(deciphered), padding)


def to_number(char: str) -> str:
    n = ord(char)
    if n < 10:
        return "00" + str(n)
    if 10 < n < 100:
        return "0" + str(n)
    if 100 <= n < 1000:
        return str(n)
    if 1000 <= n:
        raise ValueError("Use standard characters to encrypt your message.")


def pad_with_zeros(numbers: List[int], block_len: int) -> List[str]:
    return [str(number).zfill(block_len) for number in numbers]


def to_text(message: str, padding):
    characters = [
        chr(int(message[i : i + 3]))  # noqa
        for i in range(0, len(message) - padding, 3)  # noqa
    ]  # noqa
    return "".join(characters)


def to_blocks(message: str, block_len, return_type=str):
    blocks = math.ceil(len(message) / block_len)
    padding = blocks * block_len - len(message)
    padded_message = "".join(
        [message, *[str(random.randint(0, 9)) for i in range(padding)]]
    )
    return (
        [
            return_type(padded_message[block_len * i : block_len * (i + 1)])  # noqa
            for i in range(blocks)  # noqa
        ],
        padding,
    )


def xgcd(a: int, b: int) -> Tuple[int]:
    """Returns (g, x, y) such that a*x + b*y = g = gcd(a, b)."""
    x0, x1, y0, y1 = 0, 1, 1, 0
    while a != 0:
        (q, a), b = divmod(b, a), a
        y0, y1 = y1, y0 - q * y1
        x0, x1 = x1, x0 - q * x1
    return b, x0, y0


def coprime(a: int, b: int) -> bool:
    """Returns True if a and b are coprime."""
    return xgcd(a, b)[0] == 1


def modinv(a: int, b: int) -> int:
    """Returns x such that (x * a) % b == 1."""
    g, x, _ = xgcd(a, b)
    if g != 1:
        raise Exception("gcd(a, b) != 1")
    return x % b


if __name__ == "__main__":

    len_ = 512
    block_len = 5
    text_message = "This is my message :)"

    public_key, private_key = rsa(len_)

    ciphers, padding = cipher_RSA(text_message, public_key)
    deciphered = decipher_RSA(ciphers, private_key, padding)

    print(deciphered)
