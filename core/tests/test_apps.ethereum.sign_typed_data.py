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
        EthereumDataType,
    )

DOMAIN_TYPES = {
    "EIP712Domain": [
        {
            "size": None,
            "data_type": EthereumDataType.STRING,
            "name": "name",
            "type_name": "string",
            "entry_type": None,
        },
        {
            "size": None,
            "data_type": EthereumDataType.STRING,
            "name": "version",
            "type_name": "string",
            "entry_type": None,
        },
        {
            "size": 32,
            "data_type": EthereumDataType.UINT,
            "name": "chainId",
            "type_name": "uint256",
            "entry_type": None,
        },
        {
            "size": None,
            "data_type": EthereumDataType.ADDRESS,
            "name": "verifyingContract",
            "type_name": "address",
            "entry_type": None,
        },
    ]
}
MESSAGE_TYPES_BASIC = {
    "Mail": [
        {
            "size": 2,
            "data_type": EthereumDataType.STRUCT,
            "name": "from",
            "type_name": "Person",
            "entry_type": None,
        },
        {
            "size": 2,
            "data_type": EthereumDataType.STRUCT,
            "name": "to",
            "type_name": "Person",
            "entry_type": None,
        },
        {
            "size": None,
            "data_type": EthereumDataType.STRING,
            "name": "contents",
            "type_name": "string",
            "entry_type": None,
        },
    ],
    "Person": [
        {
            "size": None,
            "data_type": EthereumDataType.STRING,
            "name": "name",
            "type_name": "string",
            "entry_type": None,
        },
        {
            "size": None,
            "data_type": EthereumDataType.ADDRESS,
            "name": "wallet",
            "type_name": "address",
            "entry_type": None,
        },
    ],
}
# Micropython does not allow for some easy dict merge, being python3.4
ALL_TYPES_BASIC = {
    "EIP712Domain": DOMAIN_TYPES["EIP712Domain"],
    "Mail": MESSAGE_TYPES_BASIC["Mail"],
    "Person": MESSAGE_TYPES_BASIC["Person"],
}

DOMAIN_VALUES = {
    "verifyingContract": b"\x1e\n\xe8 ^\x97&\xe6\xf2\x96\xab\x88i\x16\nd#\xe23~",
    "chainId": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
    "name": b"Ether Mail",
    "version": b"1",
}
MESSAGE_VALUES_BASIC = {
    "contents": b"Hello, Bob!",
    "to": {
        "name": b"Bob",
        "wallet": b"T\xb0\xfaf\xa0et\x8c@\xdc\xa2\xc7\xfe\x12Z (\xcf\x99\x82",
    },
    "from": {
        "name": b"Cow",
        "wallet": b"\xc0\x00Kb\xc5\xa3\x9ar\x8eJ\xf5\xbe\xe0\xc6\xb4\xa4\xe5K\x15\xad",
    },
}

MESSAGE_TYPES_LIST = {
    "Mail": [
        {
            "entry_type": None,
            "name": "from",
            "size": 6,
            "data_type": 8,
            "type_name": "Person",
        },
        {
            "entry_type": None,
            "name": "to",
            "size": 6,
            "data_type": 8,
            "type_name": "Person",
        },
        {
            "entry_type": {
                "size": None,
                "type_name": "string",
                "data_type": 4,
                "entry_type": None,
            },
            "name": "messages",
            "size": None,
            "data_type": 7,
            "type_name": "string[]",
        },
    ],
    "Person": [
        {
            "entry_type": None,
            "name": "name",
            "size": None,
            "data_type": 4,
            "type_name": "string",
        },
        {
            "entry_type": None,
            "name": "wallet",
            "size": None,
            "data_type": 6,
            "type_name": "address",
        },
        {
            "entry_type": None,
            "name": "married",
            "size": None,
            "data_type": 5,
            "type_name": "bool",
        },
        {
            "entry_type": None,
            "name": "kids",
            "size": 1,
            "data_type": 1,
            "type_name": "uint8",
        },
        {
            "entry_type": None,
            "name": "karma",
            "size": 2,
            "data_type": 2,
            "type_name": "int16",
        },
        {
            "entry_type": {
                "size": None,
                "type_name": "string",
                "data_type": 4,
                "entry_type": None,
            },
            "name": "pets",
            "size": None,
            "data_type": 7,
            "type_name": "string[]",
        },
    ],
}
ALL_TYPES_LIST = {
    "EIP712Domain": DOMAIN_TYPES["EIP712Domain"],
    "Mail": MESSAGE_TYPES_LIST["Mail"],
    "Person": MESSAGE_TYPES_LIST["Person"],
}

MESSAGE_VALUES_LIST = {
    "messages": [b"Hello, Bob!", b"How are you?", b"Hope you're fine"],
    "to": {
        "name": b"Bob",
        "karma": b"\xff\xfc",
        "kids": b"\x00",
        "pets": [b"dog", b"cat"],
        "wallet": b"T\xb0\xfaf\xa0et\x8c@\xdc\xa2\xc7\xfe\x12Z (\xcf\x99\x82",
        "married": b"\x00",
    },
    "from": {
        "name": b"Amy",
        "karma": b"\x00\x04",
        "kids": b"\x02",
        "pets": [b"parrot"],
        "wallet": b"\xc0\x00Kb\xc5\xa3\x9ar\x8eJ\xf5\xbe\xe0\xc6\xb4\xa4\xe5K\x15\xad",
        "married": b"\x01",
    },
}


@unittest.skipUnless(not utils.BITCOIN_ONLY, "altcoin")
class TestEthereumSignTypedData(unittest.TestCase):
    def test_hash_struct(self):
        """These final expected results generated with the use of eth_account library"""
        res = hash_struct(
            primary_type="EIP712Domain",
            data=DOMAIN_VALUES,
            types=DOMAIN_TYPES,
            use_v4=True,
        )
        expected = b"\x97\xd6\xf57t\xb8\x10\xfb\xda'\xe0\x91\xc0<jmh\x15\xdd\x12p\xc2\xe6.\x82\xc6\x91|\x1e\xffwK"
        self.assertEqual(res, expected)

        res = hash_struct(
            primary_type="Mail",
            data=MESSAGE_VALUES_BASIC,
            types=MESSAGE_TYPES_BASIC,
            use_v4=True,
        )
        expected = b"\xeae)\xf0\xee\x9e\xb0\xb2\x07\xb5\xa8\xb0\xeb\xfag=9\x8djx&(\x18\xda\x1d'\x0b\xd18\xf8\x1f\x03"
        self.assertEqual(res, expected)

    def test_encode_data(self):
        res = encode_data(
            primary_type="EIP712Domain",
            data=DOMAIN_VALUES,
            types=DOMAIN_TYPES,
            use_v4=True,
        )
        expected = b"\xc7\x0e\xf0f8S[H\x81\xfa\xfc\xac\x82\x87\xe2\x10\xe3v\x9f\xf1\xa8\xe9\x1f\x1b\x95\xd6$na\xe4\xd3\xc6\xc8\x9e\xfd\xaaT\xc0\xf2\x0cz\xdfa(\x82\xdf\tP\xf5\xa9Qc~\x03\x07\xcd\xcbLg/)\x8b\x8b\xc6\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1e\n\xe8 ^\x97&\xe6\xf2\x96\xab\x88i\x16\nd#\xe23~"
        self.assertEqual(res, expected)

        res = encode_data(
            primary_type="Mail",
            data=MESSAGE_VALUES_BASIC,
            types=MESSAGE_TYPES_BASIC,
            use_v4=True,
        )
        expected = b"${\xf6.\x89\xe8\xab\xc6g\x02\x1e\xa5\xe4hf\xad\xbe\xf8\x0f\xb0\x01\xc2\x17-\xf9#\n0A/\x13\xa15'H\x1b_\xa5a5\x06\x04\xa6\rsOI\xee\x90\x7f\x17O[\xa6\xbby\x1a\xabAun\xce~\xd1\xb5\xaa\xdf1T\xa2a\xab\xdd\x90\x86\xfcb{a\xef\xca&\xaeW\x02p\x1d\x05\xcd#\x05\xf7\xc5*/\xc8"
        self.assertEqual(res, expected)

    def test_encode_type(self):
        VECTORS = (
            (
                "EIP712Domain",
                b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
                ALL_TYPES_BASIC,
            ),
            ("Person", b"Person(string name,address wallet)", ALL_TYPES_BASIC),
            (
                "Mail",
                b"Mail(Person from,Person to,string contents)Person(string name,address wallet)",
                ALL_TYPES_BASIC,
            ),
            (
                "Person",
                b"Person(string name,address wallet,bool married,uint8 kids,int16 karma,string[] pets)",
                ALL_TYPES_LIST,
            ),
            (
                "Mail",
                b"Mail(Person from,Person to,string[] messages)Person(string name,address wallet,bool married,uint8 kids,int16 karma,string[] pets)",
                ALL_TYPES_LIST,
            ),
        )

        for primary_type, expected, types in VECTORS:
            res = encode_type(primary_type=primary_type, types=types)
            self.assertEqual(res, expected)

    def test_hash_type(self):
        VECTORS = (
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
            res = hash_type(primary_type=primary_type, types=ALL_TYPES_BASIC)
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
            res = find_typed_dependencies(
                primary_type=primary_type, types=ALL_TYPES_BASIC
            )
            self.assertEqual(res, expected)

    def test_encode_field(self):
        VECTORS = (
            (
                {"data_type": EthereumDataType.STRING, "size": None},
                b"Ether Mail",
                keccak256(b"Ether Mail"),
            ),
            (
                {"data_type": EthereumDataType.STRING, "size": None},
                b"1",
                keccak256(b"1"),
            ),
            (
                {"data_type": EthereumDataType.UINT, "size": 32},
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
            ),
            (
                {"data_type": EthereumDataType.UINT, "size": 4},
                b"\x00\x00\x00\xde",
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xde",
            ),
            (
                {"data_type": EthereumDataType.INT, "size": 1},
                b"\x05",
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05",
            ),
            (
                {"data_type": EthereumDataType.ADDRESS, "size": None},
                b"\x1e\n\xe8 ^\x97&\xe6\xf2\x96\xab\x88i\x16\nd#\xe23~",
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1e\n\xe8 ^\x97&\xe6\xf2\x96\xab\x88i\x16\nd#\xe23~",
            ),
            (
                {"data_type": EthereumDataType.BOOL, "size": None},
                b"\x01",
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
            ),
            (
                {"data_type": EthereumDataType.BOOL, "size": None},
                b"\x00",
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            ),
        )

        for field, value, expected in VECTORS:
            res = encode_field(
                field=field,
                value=value,
            )
            self.assertEqual(res, expected)


if __name__ == "__main__":
    unittest.main()
