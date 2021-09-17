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
USE_V4 = True

EXPECTED_ADDRESS = "0x73d0385F4d8E00C5e6504C6030F47BF6212736A8"
EXPECTED_SIG = "0x74f1fb05738dfd1bf80d034099b2e5630697e41b3da74fd10168330ec0a592f1381ba191bfc122f530b82d5e8b03bb7ddc239ab21f1bc71f018438b2f9655cd01c"

CONTENT = '''
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
        "chainId": "1",
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
'''

@pytest.mark.setup_client(mnemonic=MNEMONIC)
def test_ethereum_sign_typed_data(client):
    with client:
        address_n = parse_path(PATH)
        ret = ethereum.sign_typed_data(client, address_n, USE_V4, CONTENT)
        assert ret.address == EXPECTED_ADDRESS
        assert f"0x{ret.signature.hex()}" == EXPECTED_SIG
