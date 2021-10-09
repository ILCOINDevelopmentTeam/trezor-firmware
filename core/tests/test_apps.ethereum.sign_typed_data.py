from common import *

from trezor import wire
from trezor.messages import (
    EthereumTypedDataStructAck,
    EthereumStructMember,
    EthereumFieldType,
)
from trezor.enums import EthereumDataType


if not utils.BITCOIN_ONLY:
    from apps.ethereum.sign_typed_data import (
        hash_struct,
        encode_data,
        encode_type,
        hash_type,
        encode_field,
        validate_field,
        find_typed_dependencies,
        keccak256,
    )
    from apps.ethereum.typed_data import get_type_name

DOMAIN_TYPES = {
    "EIP712Domain": EthereumTypedDataStructAck(
        members=[
            EthereumStructMember(
                name="name",
                type=EthereumFieldType(
                    size=None,
                    data_type=EthereumDataType.STRING,
                    struct_name=None,
                    entry_type=None,
                )
            ),
            EthereumStructMember(
                name="version",
                type=EthereumFieldType(
                    size=None,
                    data_type=EthereumDataType.STRING,
                    struct_name=None,
                    entry_type=None,
                )
            ),
            EthereumStructMember(
                name="chainId",
                type=EthereumFieldType(
                    size=32,
                    data_type=EthereumDataType.UINT,
                    struct_name=None,
                    entry_type=None,
                )
            ),
            EthereumStructMember(
                name="verifyingContract",
                type=EthereumFieldType(
                    size=None,
                    data_type=EthereumDataType.ADDRESS,
                    struct_name=None,
                    entry_type=None,
                )
            ),
        ]
    )
}
MESSAGE_TYPES_BASIC = {
    "Mail": EthereumTypedDataStructAck(
        members=[
            EthereumStructMember(
                name="from",
                type=EthereumFieldType(
                    size=2,
                    data_type=EthereumDataType.STRUCT,
                    struct_name="Person",
                    entry_type=None,
                )
            ),
            EthereumStructMember(
                name="to",
                type=EthereumFieldType(
                    size=2,
                    data_type=EthereumDataType.STRUCT,
                    struct_name="Person",
                    entry_type=None,
                )
            ),
            EthereumStructMember(
                name="contents",
                type=EthereumFieldType(
                    size=None,
                    data_type=EthereumDataType.STRING,
                    struct_name=None,
                    entry_type=None,
                )
            ),
        ]
    ),
    "Person": EthereumTypedDataStructAck(
        members=[
            EthereumStructMember(
                name="name",
                type=EthereumFieldType(
                    size=None,
                    data_type=EthereumDataType.STRING,
                    struct_name=None,
                    entry_type=None,
                )
            ),
            EthereumStructMember(
                name="wallet",
                type=EthereumFieldType(
                    size=None,
                    data_type=EthereumDataType.ADDRESS,
                    struct_name=None,
                    entry_type=None,
                )
            ),
        ]
    ),
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
    "Mail": EthereumTypedDataStructAck(
        members=[
            EthereumStructMember(
                name="from",
                type=EthereumFieldType(
                    size=6,
                    data_type=EthereumDataType.STRUCT,
                    struct_name="Person",
                    entry_type=None,
                )
            ),
            EthereumStructMember(
                name="to",
                type=EthereumFieldType(
                    size=6,
                    data_type=EthereumDataType.STRUCT,
                    struct_name="Person",
                    entry_type=None,
                )
            ),
            EthereumStructMember(
                name="messages",
                type=EthereumFieldType(
                    size=None,
                    data_type=EthereumDataType.ARRAY,
                    struct_name=None,
                    entry_type=EthereumFieldType(
                        size=None,
                        data_type=EthereumDataType.STRING,
                        struct_name=None,
                        entry_type=None,
                    ),
                )
            ),
        ]
    ),
    "Person": EthereumTypedDataStructAck(
        members=[
            EthereumStructMember(
                name="name",
                type=EthereumFieldType(
                    size=None,
                    data_type=EthereumDataType.STRING,
                    struct_name=None,
                    entry_type=None,
                )
            ),
            EthereumStructMember(
                name="wallet",
                type=EthereumFieldType(
                    size=None,
                    data_type=EthereumDataType.ADDRESS,
                    struct_name=None,
                    entry_type=None,
                )
            ),
            EthereumStructMember(
                name="married",
                type=EthereumFieldType(
                    size=None,
                    data_type=EthereumDataType.BOOL,
                    struct_name=None,
                    entry_type=None,
                )
            ),
            EthereumStructMember(
                name="kids",
                type=EthereumFieldType(
                    size=1,
                    data_type=EthereumDataType.UINT,
                    struct_name=None,
                    entry_type=None,
                )
            ),
            EthereumStructMember(
                name="karma",
                type=EthereumFieldType(
                    size=2,
                    data_type=EthereumDataType.INT,
                    struct_name=None,
                    entry_type=None,
                )
            ),
            EthereumStructMember(
                name="pets",
                type=EthereumFieldType(
                    size=None,
                    data_type=EthereumDataType.ARRAY,
                    struct_name=None,
                    entry_type=EthereumFieldType(
                        size=None,
                        data_type=EthereumDataType.STRING,
                        struct_name=None,
                        entry_type=None,
                    ),
                )
            ),
        ]
    ),
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

# TODO: validate all by some third party app, like signing data by Metamask


@unittest.skipUnless(not utils.BITCOIN_ONLY, "altcoin")
class TestEthereumSignTypedData(unittest.TestCase):
    def test_hash_struct(self):
        """These final expected results generated with the use of eth_account library"""
        VECTORS = (  # primary_type, data, types, expected
            (
                "EIP712Domain",
                DOMAIN_VALUES,
                DOMAIN_TYPES,
                b"\x97\xd6\xf57t\xb8\x10\xfb\xda'\xe0\x91\xc0<jmh\x15\xdd\x12p\xc2\xe6.\x82\xc6\x91|\x1e\xffwK",
            ),
            (
                "Mail",
                MESSAGE_VALUES_BASIC,
                MESSAGE_TYPES_BASIC,
                b"\xeae)\xf0\xee\x9e\xb0\xb2\x07\xb5\xa8\xb0\xeb\xfag=9\x8djx&(\x18\xda\x1d'\x0b\xd18\xf8\x1f\x03",
            ),
            (
                "Mail",
                MESSAGE_VALUES_LIST,
                MESSAGE_TYPES_LIST,
                b"\x8a\xb8fR\xa3\xafR]\xf8\x9e\x82M\x1c\xbcE\x0c\xdb@\x84dF\xbc\xa3\xcb\xdc\xec\x12H\xc8xt\xd4",
            ),
        )
        for primary_type, data, types, expected in VECTORS:
            res = hash_struct(
                primary_type=primary_type,
                data=data,
                types=types,
                use_v4=True,
            )
            self.assertEqual(res, expected)

    def test_encode_data(self):
        VECTORS = (  # primary_type, data, types, expected
            (
                "EIP712Domain",
                DOMAIN_VALUES,
                DOMAIN_TYPES,
                b"\xc7\x0e\xf0f8S[H\x81\xfa\xfc\xac\x82\x87\xe2\x10\xe3v\x9f\xf1\xa8\xe9\x1f\x1b\x95\xd6$na\xe4\xd3\xc6\xc8\x9e\xfd\xaaT\xc0\xf2\x0cz\xdfa(\x82\xdf\tP\xf5\xa9Qc~\x03\x07\xcd\xcbLg/)\x8b\x8b\xc6\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1e\n\xe8 ^\x97&\xe6\xf2\x96\xab\x88i\x16\nd#\xe23~",
            ),
            (
                "Mail",
                MESSAGE_VALUES_BASIC,
                MESSAGE_TYPES_BASIC,
                b"${\xf6.\x89\xe8\xab\xc6g\x02\x1e\xa5\xe4hf\xad\xbe\xf8\x0f\xb0\x01\xc2\x17-\xf9#\n0A/\x13\xa15'H\x1b_\xa5a5\x06\x04\xa6\rsOI\xee\x90\x7f\x17O[\xa6\xbby\x1a\xabAun\xce~\xd1\xb5\xaa\xdf1T\xa2a\xab\xdd\x90\x86\xfcb{a\xef\xca&\xaeW\x02p\x1d\x05\xcd#\x05\xf7\xc5*/\xc8",
            ),
            (
                "Mail",
                MESSAGE_VALUES_LIST,
                MESSAGE_TYPES_LIST,
                b's\xe6\x01\x83\xf0X55!\x81\x15\xd99\x8c\x9cQ\xaeX\xa0\xc3\x04\x05\x16\x84\xf3N\x9bq\xb08\xe2\xd4\x19\x04\xce\t\x0c\xe8\xbe\xfe\x0bY"\x94\xa7\xe2\xea\x18W\xa7\xd8\x0f\xe0\xb4\x9bI=\x81\xf1\xf3g\xf8\xe7Y.\xf5\xf3=3t\xf4\xb6%\xfd\x1bu\xba\xae\xb1\xfa\xbd\xa5%\x8a\xc2\xa3\x19\x0bbu\xf2\xadzkg\x93',
            ),
        )
        for primary_type, data, types, expected in VECTORS:
            res = encode_data(
                primary_type=primary_type,
                data=data,
                types=types,
                use_v4=True,
            )
            self.assertEqual(res, expected)

    def test_encode_type(self):
        VECTORS = (  # primary_type, types, expected
            (
                "EIP712Domain",
                ALL_TYPES_BASIC,
                b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
            ),
            ("Person", ALL_TYPES_BASIC, b"Person(string name,address wallet)"),
            (
                "Mail",
                ALL_TYPES_BASIC,
                b"Mail(Person from,Person to,string contents)Person(string name,address wallet)",
            ),
            (
                "Person",
                ALL_TYPES_LIST,
                b"Person(string name,address wallet,bool married,uint8 kids,int16 karma,string[] pets)",
            ),
            (
                "Mail",
                ALL_TYPES_LIST,
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
            res = hash_type(primary_type=primary_type, types=ALL_TYPES_BASIC)
            self.assertEqual(res, expected)

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
            res = find_typed_dependencies(
                primary_type=primary_type, types=ALL_TYPES_BASIC
            )
            self.assertEqual(res, expected)

    def test_encode_field(self):
        # TODO: need to add a fake writer and check it really got written
        VECTORS = (  # field, value, expected
            (
                EthereumFieldType(data_type=EthereumDataType.STRING, size=None),
                b"Ether Mail",
                keccak256(b"Ether Mail"),
            ),
            (
                EthereumFieldType(data_type=EthereumDataType.STRING, size=None),
                b"1",
                keccak256(b"1"),
            ),
            (
                EthereumFieldType(data_type=EthereumDataType.UINT, size=32),
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
            ),
            (
                EthereumFieldType(data_type=EthereumDataType.UINT, size=4),
                b"\x00\x00\x00\xde",
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xde",
            ),
            (
                EthereumFieldType(data_type=EthereumDataType.INT, size=1),
                b"\x05",
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05",
            ),
            (
                EthereumFieldType(data_type=EthereumDataType.ADDRESS, size=None),
                b"\x1e\n\xe8 ^\x97&\xe6\xf2\x96\xab\x88i\x16\nd#\xe23~",
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1e\n\xe8 ^\x97&\xe6\xf2\x96\xab\x88i\x16\nd#\xe23~",
            ),
            (
                EthereumFieldType(data_type=EthereumDataType.BOOL, size=None),
                b"\x01",
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
            ),
            (
                EthereumFieldType(data_type=EthereumDataType.BOOL, size=None),
                b"\x00",
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            ),
            (
                EthereumFieldType(data_type=EthereumDataType.ARRAY, size=None, entry_type=EthereumFieldType(data_type=EthereumDataType.STRING)),
                [b"String A", b"Second string", b"another Text"],
                b"h\x0cn<\xe4\xc0}\x0by\xfa\x18\xa292\xd6@\x82\xd5\x82\x18\x9e;S\xe0\x1f\x19\xa9X3u\xbb\x8e",
            ),
            (
                EthereumFieldType(data_type=EthereumDataType.STRUCT, size=2, struct_name="Person"),
                {
                    "name": b"Bob",
                    "wallet": b"T\xb0\xfaf\xa0et\x8c@\xdc\xa2\xc7\xfe\x12Z (\xcf\x99\x82",
                },
                b"5'H\x1b_\xa5a5\x06\x04\xa6\rsOI\xee\x90\x7f\x17O[\xa6\xbby\x1a\xabAun\xce~\xd1",
            ),
        )

        for field, value, expected in VECTORS:
            res = encode_field(
                field=field, value=value, types=MESSAGE_TYPES_BASIC, use_v4=True
            )
            self.assertEqual(res, expected)

    def test_validate_field(self):
        VECTORS_VALID_INVALID = (  # field, valid_values, invalid_values
            (
                EthereumFieldType(data_type=EthereumDataType.UINT, size=1),
                [b"\xff"],
                [b"\xff\xee"],
            ),
            (
                EthereumFieldType(data_type=EthereumDataType.BYTES, size=8),
                [b"\xff" * 8],
                [b"\xff" * 7, b"\xff" * 9],
            ),
            (
                EthereumFieldType(data_type=EthereumDataType.BOOL, size=None),
                [b"\x00", b"\x01"],
                [b"0", b"\x00\x01"],
            ),
            (
                EthereumFieldType(data_type=EthereumDataType.STRING, size=None),
                [b"\x7f", b"a" * 1024],
                [b"\x80", b"a" * 1025],
            ),
            (
                EthereumFieldType(data_type=EthereumDataType.ADDRESS, size=None),
                [b"T\xb0\xfaf\xa0et\x8c@\xdc\xa2\xc7\xfe\x12Z (\xcf\x99\x82"],
                [b"T\xb0\xfaf\xa0et\x8c@\xdc\xa2\xc7\xfe\x12Z (\xcf\x99"],
            ),
        )

        for field, valid_values, invalid_values in VECTORS_VALID_INVALID:
            for valid_value in valid_values:
                validate_field(
                    field=field,
                    field_name="test",
                    value=valid_value
                )
            for invalid_value in invalid_values:
                with self.assertRaises(wire.DataError):
                    validate_field(
                        field=field,
                        field_name="test",
                        value=invalid_value
                    )

    def test_get_type_name(self):
        VECTORS = (  # field, expected
            (
                EthereumFieldType(data_type=EthereumDataType.ARRAY, size=None, entry_type=EthereumFieldType(data_type=EthereumDataType.UINT, size=32)),
                "uint256[]",
            ),
            (
                EthereumFieldType(data_type=EthereumDataType.STRUCT, size=2, struct_name="Person"),
                "Person",
            ),
            (
                EthereumFieldType(data_type=EthereumDataType.STRING, size=None),
                "string",
            ),
            (
                EthereumFieldType(data_type=EthereumDataType.ADDRESS, size=None),
                "address",
            ),
            (
                EthereumFieldType(data_type=EthereumDataType.BOOL, size=None),
                "bool",
            ),
            (
                EthereumFieldType(data_type=EthereumDataType.UINT, size=20),
                "uint160",
            ),
            (
                EthereumFieldType(data_type=EthereumDataType.INT, size=8),
                "int64",
            ),
            (
                EthereumFieldType(data_type=EthereumDataType.BYTES, size=8),
                "bytes8",
            ),
            (
                EthereumFieldType(data_type=EthereumDataType.BYTES, size=None),
                "bytes",
            ),
        )

        for field, expected in VECTORS:
            res = get_type_name(field)
            self.assertEqual(res, expected)


if __name__ == "__main__":
    unittest.main()
