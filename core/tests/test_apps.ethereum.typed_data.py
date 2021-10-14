from common import *

from trezor import wire
from trezor.messages import EthereumTypedDataStructAck as ETDSA
from trezor.messages import EthereumStructMember as ESM
from trezor.messages import EthereumFieldType as EFT
from trezor.enums import EthereumDataType as EDT


if not utils.BITCOIN_ONLY:
    from apps.ethereum.typed_data import (
        encode_type,
        hash_type,
        encode_field,
        validate_field,
        validate_field_type,
        find_typed_dependencies,
        keccak256,
        get_type_name,
        decode_data,
    )

TYPES_BASIC = {
    "EIP712Domain": ETDSA(
        members=[
            ESM(
                name="name",
                type=EFT(
                    data_type=EDT.STRING,
                ),
            ),
            ESM(
                name="version",
                type=EFT(
                    data_type=EDT.STRING,
                ),
            ),
            ESM(
                name="chainId",
                type=EFT(
                    size=32,
                    data_type=EDT.UINT,
                ),
            ),
            ESM(
                name="verifyingContract",
                type=EFT(
                    data_type=EDT.ADDRESS,
                ),
            ),
        ]
    ),
    "Mail": ETDSA(
        members=[
            ESM(
                name="from",
                type=EFT(
                    size=2,
                    data_type=EDT.STRUCT,
                    struct_name="Person",
                ),
            ),
            ESM(
                name="to",
                type=EFT(
                    size=2,
                    data_type=EDT.STRUCT,
                    struct_name="Person",
                ),
            ),
            ESM(
                name="contents",
                type=EFT(
                    data_type=EDT.STRING,
                ),
            ),
        ]
    ),
    "Person": ETDSA(
        members=[
            ESM(
                name="name",
                type=EFT(
                    data_type=EDT.STRING,
                ),
            ),
            ESM(
                name="wallet",
                type=EFT(
                    data_type=EDT.ADDRESS,
                ),
            ),
        ]
    ),
}

# TODO: these are currently not used, because of deleted hash_struct and encode_data unit tests
# Try to mock the request_member_value(), load it with these dicts and make it return the correct value
DOMAIN_VALUES = {
    # 0x1e0Ae8205e9726E6F296ab8869160A6423E2337E
    "verifyingContract": b"\x1e\n\xe8 ^\x97&\xe6\xf2\x96\xab\x88i\x16\nd#\xe23~",
    # 1
    "chainId": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
    "name": b"Ether Mail",
    "version": b"1",
}
MESSAGE_VALUES_BASIC = {
    "contents": b"Hello, Bob!",
    "to": {
        "name": b"Bob",
        # 0x54B0Fa66A065748C40dCA2C7Fe125A2028CF9982
        "wallet": b"T\xb0\xfaf\xa0et\x8c@\xdc\xa2\xc7\xfe\x12Z (\xcf\x99\x82",
    },
    "from": {
        "name": b"Cow",
        # 0xc0004B62C5A39a728e4Af5bee0c6B4a4E54b15ad
        "wallet": b"\xc0\x00Kb\xc5\xa3\x9ar\x8eJ\xf5\xbe\xe0\xc6\xb4\xa4\xe5K\x15\xad",
    },
}

TYPES_LIST = {
    "EIP712Domain": ETDSA(
        members=[
            ESM(
                name="name",
                type=EFT(
                    data_type=EDT.STRING,
                ),
            ),
            ESM(
                name="version",
                type=EFT(
                    data_type=EDT.STRING,
                ),
            ),
            ESM(
                name="chainId",
                type=EFT(
                    size=32,
                    data_type=EDT.UINT,
                ),
            ),
            ESM(
                name="verifyingContract",
                type=EFT(
                    data_type=EDT.ADDRESS,
                ),
            ),
        ]
    ),
    "Mail": ETDSA(
        members=[
            ESM(
                name="from",
                type=EFT(
                    size=6,
                    data_type=EDT.STRUCT,
                    struct_name="Person",
                ),
            ),
            ESM(
                name="to",
                type=EFT(
                    size=6,
                    data_type=EDT.STRUCT,
                    struct_name="Person",
                ),
            ),
            ESM(
                name="messages",
                type=EFT(
                    data_type=EDT.ARRAY,
                    entry_type=EFT(
                        data_type=EDT.STRING,
                    ),
                ),
            ),
        ]
    ),
    "Person": ETDSA(
        members=[
            ESM(
                name="name",
                type=EFT(
                    size=None,
                    data_type=EDT.STRING,
                ),
            ),
            ESM(
                name="wallet",
                type=EFT(
                    data_type=EDT.ADDRESS,
                ),
            ),
            ESM(
                name="married",
                type=EFT(
                    data_type=EDT.BOOL,
                ),
            ),
            ESM(
                name="kids",
                type=EFT(
                    size=1,
                    data_type=EDT.UINT,
                ),
            ),
            ESM(
                name="karma",
                type=EFT(
                    size=2,
                    data_type=EDT.INT,
                ),
            ),
            ESM(
                name="pets",
                type=EFT(
                    data_type=EDT.ARRAY,
                    entry_type=EFT(
                        data_type=EDT.STRING,
                    ),
                ),
            ),
        ]
    ),
}

MESSAGE_VALUES_LIST = {
    "messages": [b"Hello, Bob!", b"How are you?", b"Hope you're fine"],
    "to": {
        "name": b"Bob",
        "karma": b"\xff\xfc",  # -4
        "kids": b"\x00",
        "pets": [b"dog", b"cat"],
        # 0x54B0Fa66A065748C40dCA2C7Fe125A2028CF9982
        "wallet": b"T\xb0\xfaf\xa0et\x8c@\xdc\xa2\xc7\xfe\x12Z (\xcf\x99\x82",
        "married": b"\x00",
    },
    "from": {
        "name": b"Amy",
        "karma": b"\x00\x04",
        "kids": b"\x02",
        "pets": [b"parrot"],
        # 0xc0004B62C5A39a728e4Af5bee0c6B4a4E54b15ad
        "wallet": b"\xc0\x00Kb\xc5\xa3\x9ar\x8eJ\xf5\xbe\xe0\xc6\xb4\xa4\xe5K\x15\xad",
        "married": b"\x01",
    },
}

# TODO: validate all by some third party app, like signing data by Metamask
# ??? How to approach the testing ???
# - we could copy the most important test cases testing important functionality
# Testcases are at:
# https://github.com/MetaMask/eth-sig-util/blob/73ace3309bf4b97d901fb66cd61db15eede7afe9/src/sign-typed-data.test.ts
# Worth testing/implementing:
# should encode data with a recursive data type
# should ignore extra unspecified message properties
# should throw an error when an atomic property is set to null
# Missing custom type properties are omitted in V3, but encoded as 0 (bytes32) in V4

@unittest.skipUnless(not utils.BITCOIN_ONLY, "altcoin")
class TestEthereumSignTypedData(unittest.TestCase):
    def test_encode_type(self):
        VECTORS = (  # primary_type, types, expected
            (
                "EIP712Domain",
                TYPES_BASIC,
                b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
            ),
            ("Person", TYPES_BASIC, b"Person(string name,address wallet)"),
            (
                "Mail",
                TYPES_BASIC,
                b"Mail(Person from,Person to,string contents)Person(string name,address wallet)",
            ),
            (
                "Person",
                TYPES_LIST,
                b"Person(string name,address wallet,bool married,uint8 kids,int16 karma,string[] pets)",
            ),
            (
                "Mail",
                TYPES_LIST,
                b"Mail(Person from,Person to,string[] messages)Person(string name,address wallet,bool married,uint8 kids,int16 karma,string[] pets)",
            ),
        )

        for primary_type, types, expected in VECTORS:
            res = encode_type(primary_type=primary_type, types=types)
            self.assertEqual(res, expected)

    def test_hash_type(self):
        VECTORS = (  # primary_type, expected
            (
                "EIP712Domain",
                keccak256(
                    b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
            ),
            ("Person", keccak256(b"Person(string name,address wallet)")),
            (
                "Mail",
                keccak256(
                    b"Mail(Person from,Person to,string contents)Person(string name,address wallet)"
                ),
            ),
        )

        for primary_type, expected in VECTORS:
            w = bytearray()
            hash_type(w=w, primary_type=primary_type, types=TYPES_BASIC)
            self.assertEqual(w, expected)

    def test_find_typed_dependencies(self):
        VECTORS = (  # primary_type, expected
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
            res = []
            find_typed_dependencies(primary_type=primary_type, types=TYPES_BASIC, results=res)
            self.assertEqual(res, expected)

    def test_encode_field(self):
        VECTORS = (  # field, value, expected
            (
                EFT(data_type=EDT.STRING, size=None),
                b"Ether Mail",
                keccak256(b"Ether Mail"),
            ),
            (
                EFT(data_type=EDT.STRING, size=None),
                b"1",
                keccak256(b"1"),
            ),
            (
                EFT(data_type=EDT.UINT, size=32),
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
            ),
            (
                EFT(data_type=EDT.UINT, size=4),
                b"\x00\x00\x00\xde",
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xde",
            ),
            (
                EFT(data_type=EDT.INT, size=1),
                b"\x05",
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05",
            ),
            (
                EFT(data_type=EDT.ADDRESS, size=None),
                b"\x1e\n\xe8 ^\x97&\xe6\xf2\x96\xab\x88i\x16\nd#\xe23~",
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1e\n\xe8 ^\x97&\xe6\xf2\x96\xab\x88i\x16\nd#\xe23~",
            ),
            (
                EFT(data_type=EDT.BOOL, size=None),
                b"\x01",
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
            ),
            (
                EFT(data_type=EDT.BOOL, size=None),
                b"\x00",
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            ),
        )

        for field, value, expected in VECTORS:
            # metamask_v4_compat should not have any effect on the
            # result for items outside of arrays
            for metamask_v4_compat in [True, False]:
                w = bytearray()
                encode_field(
                    w=w,
                    field=field,
                    value=value,
                )
                self.assertEqual(w, expected)

    def test_validate_field(self):
        VECTORS_VALID_INVALID = (  # field, valid_values, invalid_values
            (
                EFT(data_type=EDT.UINT, size=1),
                [b"\xff"],
                [b"\xff\xee"],
            ),
            (
                EFT(data_type=EDT.BYTES, size=8),
                [b"\xff" * 8],
                [b"\xff" * 7, b"\xff" * 9],
            ),
            (
                EFT(data_type=EDT.BOOL, size=None),
                [b"\x00", b"\x01"],
                [b"0", b"\x00\x01"],
            ),
            (
                EFT(data_type=EDT.STRING, size=None),
                [b"\x7f", b"a" * 1024],
                [b"\x80", b"a" * 1025],
            ),
            (
                EFT(data_type=EDT.ADDRESS, size=None),
                [b"T\xb0\xfaf\xa0et\x8c@\xdc\xa2\xc7\xfe\x12Z (\xcf\x99\x82"],
                [b"T\xb0\xfaf\xa0et\x8c@\xdc\xa2\xc7\xfe\x12Z (\xcf\x99"],
            ),
        )

        for field, valid_values, invalid_values in VECTORS_VALID_INVALID:
            for valid_value in valid_values:
                validate_field(field=field, field_name="test", value=valid_value)
            for invalid_value in invalid_values:
                with self.assertRaises(wire.DataError):
                    validate_field(field=field, field_name="test", value=invalid_value)

    def test_validate_field_type(self):
        ET = EFT(data_type=EDT.BYTES, size=8)
        VECTORS_VALID = (  # valid_field
            (EFT(data_type=EDT.STRUCT, struct_name="Person", size=3)),
            (EFT(data_type=EDT.ARRAY, entry_type=ET, size=None)),
            (EFT(data_type=EDT.ARRAY, entry_type=ET, size=6)),
            (EFT(data_type=EDT.BYTES, size=32)),
            (EFT(data_type=EDT.BYTES, size=None)),
            (EFT(data_type=EDT.UINT, size=8)),
            (EFT(data_type=EDT.INT, size=16)),
            (EFT(data_type=EDT.STRING)),
            (EFT(data_type=EDT.BOOL)),
            (EFT(data_type=EDT.ADDRESS)),
        )
        for valid_field in VECTORS_VALID:
            validate_field_type(field=valid_field)

        ET = EFT(data_type=EDT.BYTES, size=8)
        ET_INVALID = EFT(data_type=EDT.BYTES, size=33)
        VECTORS_INVALID = (  # invalid_field
            (EFT(data_type=EDT.STRUCT, size=None)),
            (EFT(data_type=EDT.STRUCT, struct_name=None)),
            (EFT(data_type=EDT.STRUCT, entry_type=ET)),
            (EFT(data_type=EDT.ARRAY, struct_name="Person")),
            (EFT(data_type=EDT.ARRAY, entry_type=None)),
            (EFT(data_type=EDT.ARRAY, entry_type=ET_INVALID)),
            (EFT(data_type=EDT.BYTES, struct_name="Person")),
            (EFT(data_type=EDT.BYTES, size=0)),
            (EFT(data_type=EDT.BYTES, size=33)),
            (EFT(data_type=EDT.BYTES, entry_type=ET)),
            (EFT(data_type=EDT.UINT, struct_name="Person")),
            (EFT(data_type=EDT.UINT, size=None)),
            (EFT(data_type=EDT.UINT, size=0)),
            (EFT(data_type=EDT.UINT, size=33)),
            (EFT(data_type=EDT.UINT, entry_type=ET)),
            (EFT(data_type=EDT.INT, struct_name="Person")),
            (EFT(data_type=EDT.INT, size=None)),
            (EFT(data_type=EDT.INT, size=0)),
            (EFT(data_type=EDT.INT, size=33)),
            (EFT(data_type=EDT.INT, entry_type=ET)),
            (EFT(data_type=EDT.STRING, struct_name="Person")),
            (EFT(data_type=EDT.STRING, size=3)),
            (EFT(data_type=EDT.STRING, entry_type=ET)),
            (EFT(data_type=EDT.BOOL, struct_name="Person")),
            (EFT(data_type=EDT.BOOL, size=3)),
            (EFT(data_type=EDT.BOOL, entry_type=ET)),
            (EFT(data_type=EDT.ADDRESS, struct_name="Person")),
            (EFT(data_type=EDT.ADDRESS, size=3)),
            (EFT(data_type=EDT.ADDRESS, entry_type=ET)),
        )
        for invalid_field in VECTORS_INVALID:
            with self.assertRaises(wire.DataError):
                validate_field_type(field=invalid_field)

    def test_get_type_name(self):
        VECTORS = (  # field, expected
            (
                EFT(
                    data_type=EDT.ARRAY,
                    size=None,
                    entry_type=EFT(data_type=EDT.UINT, size=32),
                ),
                "uint256[]",
            ),
            (
                EFT(
                    data_type=EDT.ARRAY,
                    size=4,
                    entry_type=EFT(data_type=EDT.STRING, size=None),
                ),
                "string[4]",
            ),
            (
                EFT(data_type=EDT.STRUCT, size=2, struct_name="Person"),
                "Person",
            ),
            (
                EFT(data_type=EDT.STRING, size=None),
                "string",
            ),
            (
                EFT(data_type=EDT.ADDRESS, size=None),
                "address",
            ),
            (
                EFT(data_type=EDT.BOOL, size=None),
                "bool",
            ),
            (
                EFT(data_type=EDT.UINT, size=20),
                "uint160",
            ),
            (
                EFT(data_type=EDT.INT, size=8),
                "int64",
            ),
            (
                EFT(data_type=EDT.BYTES, size=8),
                "bytes8",
            ),
            (
                EFT(data_type=EDT.BYTES, size=None),
                "bytes",
            ),
        )

        for field, expected in VECTORS:
            res = get_type_name(field)
            self.assertEqual(res, expected)

    def test_decode_data(self):
        VECTORS = (  # data, type_name, expected
            (b"\x4a\x56", "bytes", "4a56"),
            (b"Hello, Bob!", "string", "Hello, Bob!"),
            (
                b"\x1e\n\xe8 ^\x97&\xe6\xf2\x96\xab\x88i\x16\nd#\xe23~",
                "address",
                "0x1e0Ae8205e9726E6F296ab8869160A6423E2337E",
            ),
            (b"\x01", "bool", "true"),
            (b"\x00", "bool", "false"),
            (b"\x3f\x46\xaa", "uint", "4146858"),
            (b"\x3f\x46\xaa", "int", "4146858"),
            (b"\xff\xf1", "uint", "65521"),
            (b"\xff\xf1", "int", "-15"),
        )

        for data, type_name, expected in VECTORS:
            res = decode_data(data, type_name)
            self.assertEqual(res, expected)


if __name__ == "__main__":
    unittest.main()
