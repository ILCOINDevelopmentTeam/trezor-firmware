# This file is part of the Trezor project.
#
# Copyright (C) 2012-2019 SatoshiLabs and contributors
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.

import pytest

from trezorlib import ethereum
from trezorlib.tools import parse_path

MNEMONIC = " ".join(["all"] * 12)
PATH = "m/44'/60'/0'/0/0"

EXPECTED_ADDRESS = "0x73d0385F4d8E00C5e6504C6030F47BF6212736A8"

# Verified by Metamask's eth_signTypedData_v4
EXPECTED_SIG_BASIC = "0x2c2d8c7c1facf5bdcd997b5435bb42f3f4170a111ce079c94b5d1e34414f76560c4600d2167568e052ab846555bd590de93bb230987766c636613262eaeb8bdc1c"
CONTENT_BASIC = """
{
    "types": {
        "EIP712Domain": [
            {
                "name": "name",
                "type": "string"
            },
            {
                "name": "version",
                "type": "string"
            },
            {
                "name": "chainId",
                "type": "uint256"
            },
            {
                "name": "verifyingContract",
                "type": "address"
            }
        ],
        "Person": [
            {
                "name": "name",
                "type": "string"
            },
            {
                "name": "wallet",
                "type": "address"
            }
        ],
        "Mail": [
            {
                "name": "from",
                "type": "Person"
            },
            {
                "name": "to",
                "type": "Person"
            },
            {
                "name": "contents",
                "type": "string"
            }
        ]
    },
    "primaryType": "Mail",
    "domain": {
        "name": "Ether Mail",
        "version": "1",
        "chainId": 1,
        "verifyingContract": "0x1e0Ae8205e9726E6F296ab8869160A6423E2337E"
    },
    "message": {
        "from": {
            "name": "Cow",
            "wallet": "0xc0004B62C5A39a728e4Af5bee0c6B4a4E54b15ad"
        },
        "to": {
            "name": "Bob",
            "wallet": "0x54B0Fa66A065748C40dCA2C7Fe125A2028CF9982"
        },
        "contents": "Hello, Bob!"
    }
}
"""

# Verified by Metamask's eth_signTypedData_v4
EXPECTED_SIG_COMPLEX = "0xf0a187388b33f17885c915173f38bd613d2ce4346acadfc390b2bae4c6def03667ceac155b5398bd8be326386e841e8820c5254f389a09d6d95ac72e2f6e19e61c"
CONTENT_COMPLEX = """
{
    "types": {
        "EIP712Domain": [
            {
                "name": "name",
                "type": "string"
            },
            {
                "name": "version",
                "type": "string"
            },
            {
                "name": "chainId",
                "type": "uint256"
            },
            {
                "name": "verifyingContract",
                "type": "address"
            },
            {
                "name": "salt",
                "type": "bytes32"
            }
        ],
        "Person": [
            {
                "name": "name",
                "type": "string"
            },
            {
                "name": "wallet",
                "type": "address"
            },
            {
                "name": "married",
                "type": "bool"
            },
            {
                "name": "kids",
                "type": "uint8"
            },
            {
                "name": "karma",
                "type": "int16"
            },
            {
                "name": "secret",
                "type": "bytes"
            },
            {
                "name": "small_secret",
                "type": "bytes16"
            },
            {
                "name": "pets",
                "type": "string[]"
            },
            {
                "name": "two_best_friends",
                "type": "string[2]"
            }
        ],
        "Mail": [
            {
                "name": "from",
                "type": "Person"
            },
            {
                "name": "to",
                "type": "Person"
            },
            {
                "name": "messages",
                "type": "string[]"
            }
        ]
    },
    "primaryType": "Mail",
    "domain": {
        "name": "Ether Mail",
        "version": "1",
        "chainId": 1,
        "verifyingContract": "0x1e0Ae8205e9726E6F296ab8869160A6423E2337E",
        "salt": "0xca92da1a6e91d9358328d2f2155af143a7cb74b81a3a4e3e57e2191823dbb56c"
    },
    "message": {
        "from": {
            "name": "Amy",
            "wallet": "0xc0004B62C5A39a728e4Af5bee0c6B4a4E54b15ad",
            "married": true,
            "kids": 2,
            "karma": 4,
            "secret": "0x62c5a39a728e4af5bee0c6b462c5a39a728e4af5bee0c6b462c5a39a728e4af5bee0c6b462c5a39a728e4af5bee0c6b4",
            "small_secret": "0x5ccf0e54367104795a47bc0481645d9e",
            "pets": [
                "parrot"
            ],
            "two_best_friends": [
                "Carl",
                "Denis"
            ]
        },
        "to": {
            "name": "Bob",
            "wallet": "0x54B0Fa66A065748C40dCA2C7Fe125A2028CF9982",
            "married": false,
            "kids": 0,
            "karma": -4,
            "secret": "0x7fe125a2028cf97fe125a2028cf97fe125a2028cf97fe125a2028cf97fe125a2028cf97fe125a2028cf97fe125a2028cf9",
            "small_secret": "0xa5e5c47b64775abc476d2962403258de",
            "pets": [
                "dog",
                "cat"
            ],
            "two_best_friends": [
                "Emil",
                "Franz"
            ]
        },
        "messages": [
            "Hello, Bob!",
            "How are you?",
            "Hope you're fine"
        ]
    }
}
"""

# Verified by Metamask's eth_signTypedData_v4
EXPECTED_SIG_STRUCT_LIST = "0x61d4a929f8513b6327c5eae227d65c394c3857904de483a2191095e2ec35a9ea2ecaf1a461332a6f4847679018848612b35c94150d9be8870ffad01fcbe72cf71c"
EXPECTED_SIG_STRUCT_LIST_NON_V4 = "0xba6658fd95d8f6048150c8ac64a596d974184522d1069237a57d0e170835fff661ff6f10c5049906a8a508c18d58145dcff91508e70e7e3c186193e3e3bb7dd61b"
CONTENT_STRUCT_LIST = """
{
    "types": {
        "EIP712Domain": [
            {
                "name": "name",
                "type": "string"
            },
            {
                "name": "version",
                "type": "string"
            },
            {
                "name": "chainId",
                "type": "uint256"
            },
            {
                "name": "verifyingContract",
                "type": "address"
            }
        ],
        "Person": [
            {
                "name": "name",
                "type": "string"
            },
            {
                "name": "wallet",
                "type": "address"
            }
        ],
        "Mail": [
            {
                "name": "from",
                "type": "Person"
            },
            {
                "name": "to",
                "type": "Person[]"
            },
            {
                "name": "contents",
                "type": "string"
            }
        ]
    },
    "primaryType": "Mail",
    "domain": {
        "name": "Ether Mail",
        "version": "1",
        "chainId": 1,
        "verifyingContract": "0x1e0Ae8205e9726E6F296ab8869160A6423E2337E"
    },
    "message": {
        "from": {
            "name": "Cow",
            "wallet": "0xc0004B62C5A39a728e4Af5bee0c6B4a4E54b15ad"
        },
        "to": [
            {
                "name": "Bob",
                "wallet": "0x54B0Fa66A065748C40dCA2C7Fe125A2028CF9982"
            },
            {
                "name": "Dave",
                "wallet": "0x73d0385F4d8E00C5e6504C6030F47BF6212736A8"
            }
        ],
        "contents": "Hello, guys!"
    }
}
"""

# TODO: could create JSON fixtures from it
VECTORS = (  # data_to_sign, expected_sig, metamask_v4_compat
    (CONTENT_BASIC, EXPECTED_SIG_BASIC, True),
    (CONTENT_COMPLEX, EXPECTED_SIG_COMPLEX, True),
    (CONTENT_STRUCT_LIST, EXPECTED_SIG_STRUCT_LIST, True),
    (CONTENT_STRUCT_LIST, EXPECTED_SIG_STRUCT_LIST_NON_V4, False),
)


@pytest.mark.setup_client(mnemonic=MNEMONIC)
def test_ethereum_sign_typed_data(client):
    for data_to_sign, expected_sig, metamask_v4_compat in VECTORS:
        with client:
            address_n = parse_path(PATH)
            ret = ethereum.sign_typed_data(client, address_n, metamask_v4_compat, data_to_sign)
            assert ret.address == EXPECTED_ADDRESS
            assert f"0x{ret.signature.hex()}" == expected_sig
