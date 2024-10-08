from znn.model.primitives.hash import EMPTY_HASH
from znn.model.primitives.hash import Hash


class HashHeight:
    def __init__(self, hash_instance, height: int):
        self.height = height
        self.hash = hash_instance

    def __str__(self):
        return str(self.hash.to_bytes(8, "big"))
        # return self.core.hex()

    @staticmethod
    def from_json(json_data):
        return HashHeight(Hash.parse(json_data["hash"]), json_data["height"])

    def to_json(self):
        return {"hash": str(self.hash), "height": self.height}


EMPTY_HASH_HEIGHT = HashHeight(EMPTY_HASH, 0)
