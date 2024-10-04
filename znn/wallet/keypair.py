from nacl.encoding import Base64Encoder
from nacl.encoding import HexEncoder
from nacl.signing import SigningKey
from nacl.signing import VerifyKey

from znn.model.primitives.address import Address
from znn.wallet.utils import from_ascii


def verify_signature(
    public_key_hex: str,
    signature: str,
    unsigned_message: str,
    encoding=Base64Encoder,
):
    verifying_key = VerifyKey(public_key_hex.encode(), encoder=HexEncoder)
    verifying_key.verify(
        Base64Encoder.encode(unsigned_message.encode()),
        from_ascii(signature.encode(), "", "base64"),
        encoder=encoding,
    )


class KeyPair:
    def __init__(self, private_key: str):
        self.private_key = private_key
        self.signing_key = SigningKey(private_key.encode(), encoder=HexEncoder)
        self.public_key = self.signing_key.verify_key.encode(
            encoder=HexEncoder
        ).decode()
        self.address = Address.from_public_key_hex(self.public_key)

    def sign(self, message: str, encoding=Base64Encoder):
        return self.signing_key.sign(message.encode(), encoder=encoding).signature
