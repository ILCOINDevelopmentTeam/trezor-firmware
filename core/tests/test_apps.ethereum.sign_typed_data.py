from common import *

if not utils.BITCOIN_ONLY:
    from apps.ethereum.sign_typed_data import (
        hash_struct,
        encode_data,
        encode_type,
        hash_type,
        encode_field,
        find_typed_dependencies,
        keccak256,
    )

TYPED_DATA = {
    "types": {
        "EIP712Domain": [
            {"name": "name", "type": "string"},
            {"name": "version", "type": "string"},
            {"name": "chainId", "type": "uint256"},
            {"name": "verifyingContract", "type": "address"},
        ],
        "Person": [
            {"name": "name", "type": "string"},
            {"name": "wallet", "type": "address"},
        ],
        "Mail": [
            {"name": "from", "type": "Person"},
            {"name": "to", "type": "Person"},
            {"name": "contents", "type": "string"},
        ],
    },
    "primaryType": "Mail",
    "domain": {
        "name": "Ether Mail",
        "version": "1",
        "chainId": "1",
        "verifyingContract": "0x1e0Ae8205e9726E6F296ab8869160A6423E2337E",
    },
    "message": {
        "from": {"name": "Cow", "wallet": "0xc0004B62C5A39a728e4Af5bee0c6B4a4E54b15ad"},
        "to": {"name": "Bob", "wallet": "0x54B0Fa66A065748C40dCA2C7Fe125A2028CF9982"},
        "contents": "Hello, Bob!",
    },
}


@unittest.skipUnless(not utils.BITCOIN_ONLY, "altcoin")
class TestEthereumSignTypedData(unittest.TestCase):
    def test_hash_struct(self):
        primary_type = "EIP712Domain"
        use_v4 = True
        data = {
            "verifyingContract": b"\x1e\n\xe8 ^\x97&\xe6\xf2\x96\xab\x88i\x16\nd#\xe23~",
            "chainId": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
            "name": b"Ether Mail",
            "version": b"1",
        }

        res = hash_struct(
            primary_type=primary_type,
            data=data,
            types=TYPED_DATA["types"],
            use_v4=use_v4,
        )
        expected = b"\xe5\xc3?\xd0n\xbaa\xacE\x18\xdc\x02d\x07\xd2\x8d\x1a\xbdH\xfcK\x07\xe0~#\x10\xaf\xb2[GV\xf4"
        self.assertEqual(res, expected)

    def test_encode_data(self):
        primary_type = "EIP712Domain"
        use_v4 = True
        data = {
            "verifyingContract": b"\x1e\n\xe8 ^\x97&\xe6\xf2\x96\xab\x88i\x16\nd#\xe23~",
            "chainId": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
            "name": b"Ether Mail",
            "version": b"1",
        }

        res = encode_data(
            primary_type=primary_type,
            data=data,
            types=TYPED_DATA["types"],
            use_v4=use_v4,
        )
        expected = bytearray(
            b"\x8bs\xc3\xc6\x9b\xb8\xfe=Q.\xccL\xf7Y\xccy#\x9f{\x17\x9b\x0f\xfa\xca\xa9\xa7]R+9@\x0f\xc7\x0e\xf0f8S[H\x81\xfa\xfc\xac\x82\x87\xe2\x10\xe3v\x9f\xf1\xa8\xe9\x1f\x1b\x95\xd6$na\xe4\xd3\xc6\xc8\x9e\xfd\xaaT\xc0\xf2\x0cz\xdfa(\x82\xdf\tP\xf5\xa9Qc~\x03\x07\xcd\xcbLg/)\x8b\x8b\xc6\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x1e\n\xe8 ^\x97&\xe6\xf2\x96\xab\x88i\x16\nd#\xe23~\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        )
        self.assertEqual(res, expected)

    def test_encode_type(self):
        VECTORS = (
            (
                "EIP712Domain",
                b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
            ),
            (
                "Person",
                b"Person(string name,address wallet)",
            ),
            (
                "Mail",
                b"Mail(Person from,Person to,string contents)Person(string name,address wallet)",
            ),
        )

        for primary_type, expected in VECTORS:
            res = encode_type(primary_type=primary_type, types=TYPED_DATA["types"])
            self.assertEqual(res, expected)

        with self.assertRaises(ValueError):
            encode_type(primary_type="UnexistingType", types=TYPED_DATA["types"])

    def test_hash_type(self):
        VECTORS = (
            (
                "EIP712Domain",
                keccak256(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
            ),
            (
                "Person",
                keccak256(b"Person(string name,address wallet)")
            ),
            (
                "Mail",
                keccak256(b"Mail(Person from,Person to,string contents)Person(string name,address wallet)")
            ),
        )

        for primary_type, expected in VECTORS:
            res = hash_type(primary_type=primary_type, types=TYPED_DATA["types"])
            self.assertEqual(res, expected)

    def test_find_typed_dependencies(self):
        VECTORS = (
            (
                "EIP712Domain",
                ["EIP712Domain"],
            ),
            (
                "Person",
                ["Person"],
            ),
            (
                "Mail",
                ["Mail", "Person"],
            ),
            (
                "Mail[]",
                ["Mail", "Person"],
            ),
            (
                "UnexistingType",
                [],
            ),
        )

        for primary_type, expected in VECTORS:
            res = find_typed_dependencies(primary_type=primary_type, types=TYPED_DATA["types"])
            self.assertEqual(res, expected)

    def test_encode_field(self):
        use_v4 = True

        VECTORS = (
            (
                {"type": "string", "name": "name"},
                b"Ether Mail",
                keccak256(b"Ether Mail"),
            ),
            (
                {"type": "string", "name": "version"},
                b"1",
                keccak256(b"1"),
            ),
            (
                {"type": "uint256", "name": "chainId"},
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
            ),
            (
                {"type": "address", "name": "verifyingContracts"},
                b"\x1e\n\xe8 ^\x97&\xe6\xf2\x96\xab\x88i\x16\nd#\xe23~",
                b"\x1e\n\xe8 ^\x97&\xe6\xf2\x96\xab\x88i\x16\nd#\xe23~",
            ),
        )

        for field, value, expected in VECTORS:
            _, res = encode_field(
                use_v4=use_v4,
                in_array=False,
                types=TYPED_DATA["types"],
                name=field["name"],
                type_name=field["type"],
                value=value,
            )
            self.assertEqual(res, expected)


if __name__ == "__main__":
    unittest.main()
