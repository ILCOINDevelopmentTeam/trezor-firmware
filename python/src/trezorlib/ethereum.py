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

import json
import re
from typing import Dict, Tuple, Union, List

from eth_abi.packed import encode_single_packed

from . import exceptions, messages
from .tools import expect, normalize_nfc, session


def int_to_big_endian(value) -> bytes:
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def find_typed_dependencies(
    primary_type: str, types: dict, results: list = None
) -> list:
    """
    Finds all types within a type definition object

    primary_type - Root type
    types - Type definitions
    results - Current set of accumulated types
    """
    if results is None:
        results = []

    m = re.compile(r"^\w+").match(primary_type)
    if m:
        primary_type = m.group(0)
    else:
        raise ValueError(f"cannot parse primary type: {primary_type}")

    if (primary_type in results) or (types.get(primary_type) is None):
        return results

    results.append(primary_type)
    for field in types[primary_type]:
        deps = find_typed_dependencies(field["type"], types, results)
        for dep in deps:
            if dep not in results:
                results.append(dep)

    return results


def encode_type(primary_type: str, types: dict) -> Tuple[str, Dict]:
    """
    Encodes the type of an object by encoding a comma delimited list of its members

    primary_type - Root type to encode
    types - Type definitions
    """
    result = ""
    result_indexed = {}

    all_deps = find_typed_dependencies(primary_type, types)
    non_primary_deps = [dep for dep in all_deps if dep != primary_type]
    deps_primary_first = [primary_type] + sorted(non_primary_deps)

    for type_name in deps_primary_first:
        children = types.get(type_name)
        if children is None:
            raise ValueError(f"no type definition specified: {type_name}")
        fields = ",".join([f"{c['type']} {c['name']}" for c in children])
        result += f"{type_name}({fields})"
        result_indexed[type_name] = children

    return result, result_indexed


REQUIRED_TYPED_DATA_PROPERTIES = ("types", "primaryType", "domain", "message")


def sanitize_typed_data(data: dict) -> dict:
    """
    Removes properties from a message object that are not defined per EIP-712

    data - typed message object
    """
    sanitized_data = {key: data[key] for key in REQUIRED_TYPED_DATA_PROPERTIES}
    sanitized_data["types"].setdefault("EIP712Domain", [])
    return sanitized_data


def is_array(type_name: str) -> bool:
    if type_name:
        return type_name[-1] == "]"

    return False


def typeof_array(type_name: str) -> str:
    return type_name[: type_name.rindex("[")]


def parse_number(arg: Union[int, str]) -> int:
    if isinstance(arg, str):
        return int(arg, 16)
    elif isinstance(arg, int):
        return arg

    raise ValueError("arg is not a number")


def parse_type_n(type_name: str) -> int:
    """Parse N from type<N>.

    Example: "uint256" -> 256
    """
    # TODO: we could use regex for this to take number from the end
    accum = []
    for c in type_name:
        if c.isdigit():
            accum.append(c)
        else:
            accum = []

    # join collected digits into a number
    return int("".join(accum))


def parse_array_n(type_name: str) -> Union[int, str]:
    """Parse N in type[<N>] where "type" can itself be an array type."""
    if type_name.endswith("[]"):
        return "dynamic"

    start_idx = type_name.rindex("[") + 1
    return int(type_name[start_idx:-1])


def encode_value(type_name: str, value) -> bytes:
    for int_type in ["int", "uint"]:
        if type_name.startswith(int_type):
            size = parse_type_n(type_name)

            if (size % 8 != 0) or (size not in range(8, 257)):
                raise ValueError(f"invalid {int_type}<N> width: {size}")

            value = parse_number(value)
            if value.bit_length() > size:
                raise ValueError(
                    f"supplied {int_type} exceeds width: {value.bit_length()} > {size}"
                )
            if int_type == "uint":
                if value < 0:
                    raise ValueError("supplied uint is negative")

    return encode_single_packed(type_name, value)


# ====== Client functions ====== #


@expect(messages.EthereumAddress, field="address")
def get_address(client, n, show_display=False, multisig=None):
    return client.call(
        messages.EthereumGetAddress(address_n=n, show_display=show_display)
    )


@expect(messages.EthereumPublicKey)
def get_public_node(client, n, show_display=False):
    return client.call(
        messages.EthereumGetPublicKey(address_n=n, show_display=show_display)
    )


@session
def sign_tx(
    client,
    n,
    nonce,
    gas_price,
    gas_limit,
    to,
    value,
    data=None,
    chain_id=None,
    tx_type=None,
):
    msg = messages.EthereumSignTx(
        address_n=n,
        nonce=int_to_big_endian(nonce),
        gas_price=int_to_big_endian(gas_price),
        gas_limit=int_to_big_endian(gas_limit),
        value=int_to_big_endian(value),
        to=to,
        chain_id=chain_id,
        tx_type=tx_type,
    )

    if data:
        msg.data_length = len(data)
        data, chunk = data[1024:], data[:1024]
        msg.data_initial_chunk = chunk

    response = client.call(msg)

    while response.data_length is not None:
        data_length = response.data_length
        data, chunk = data[data_length:], data[:data_length]
        response = client.call(messages.EthereumTxAck(data_chunk=chunk))

    # https://github.com/trezor/trezor-core/pull/311
    # only signature bit returned. recalculate signature_v
    if response.signature_v <= 1:
        response.signature_v += 2 * chain_id + 35

    return response.signature_v, response.signature_r, response.signature_s


@session
def sign_tx_eip1559(
    client,
    n,
    *,
    nonce,
    gas_limit,
    to,
    value,
    data=b"",
    chain_id,
    max_gas_fee,
    max_priority_fee,
    access_list=()
):
    length = len(data)
    data, chunk = data[1024:], data[:1024]
    msg = messages.EthereumSignTxEIP1559(
        address_n=n,
        nonce=int_to_big_endian(nonce),
        gas_limit=int_to_big_endian(gas_limit),
        value=int_to_big_endian(value),
        to=to,
        chain_id=chain_id,
        max_gas_fee=int_to_big_endian(max_gas_fee),
        max_priority_fee=int_to_big_endian(max_priority_fee),
        access_list=access_list,
        data_length=length,
        data_initial_chunk=chunk,
    )

    response = client.call(msg)

    while response.data_length is not None:
        data_length = response.data_length
        data, chunk = data[data_length:], data[:data_length]
        response = client.call(messages.EthereumTxAck(data_chunk=chunk))

    return response.signature_v, response.signature_r, response.signature_s


@expect(messages.EthereumMessageSignature)
def sign_message(client, n, message):
    message = normalize_nfc(message)
    return client.call(messages.EthereumSignMessage(address_n=n, message=message))


@expect(messages.EthereumTypedDataRequest)
def sign_typed_data(client, n: List[int], use_v4: bool, data_string: str):
    data = json.loads(data_string)
    data = sanitize_typed_data(data)

    _, domain_types = encode_type("EIP712Domain", data["types"])
    _, message_types = encode_type(data["primaryType"], data["types"])

    request = messages.EthereumSignTypedData(address_n=n, use_v4=use_v4)
    response = client.call(request)

    message_types_keys = list(message_types.keys())
    while len(response.member_path) > 0:
        root_index = response.member_path[0]
        type_index = response.member_path[1] if len(response.member_path) > 1 else None
        if root_index == 0:
            if response.expect_type and (type_index > 0):
                client.cancel()
                raise ValueError("unexpected type_index when requesting domain type")

            member_typename = "EIP712Domain"
            member_types = domain_types
            member_data = data["domain"]
        elif root_index == 1:
            if response.expect_type:
                # when device expects type, the path [1, x] points to element x in types linear layout
                member_typename = (
                    message_types_keys[type_index]
                    if type_index < len(message_types_keys)
                    else None
                )
            else:
                # when device expects value, the path [1, x] points to field x inside primaryType.
                member_typename = data["primaryType"]
            member_types = message_types
            member_data = data["message"]
        else:
            client.cancel()
            raise ValueError("unknown root")

        if response.expect_type:
            member_name = None
            for index in response.member_path[2:]:
                member_def = member_types[member_typename][index]
                member_name = member_def["name"]
                member_typename = member_def["type"]

            request = messages.EthereumTypedDataAck(
                member_name=member_name,
                member_type=member_typename,
                member_value=None,
            )

            if is_array(member_typename):
                array_type = typeof_array(member_typename)
                is_struct = array_type in member_types
                if is_struct:
                    array_size = parse_array_n(member_typename)
                    if array_size == "dynamic":
                        request.member_array_n = 0
                    else:
                        request.member_array_n = array_size
            else:
                is_struct = member_typename in member_types
                if is_struct:
                    request.member_children = len(member_types[member_typename])

            response = client.call(request)

        else:
            array_size = None
            for index in response.member_path[1:]:
                if array_size is None:
                    member_def = member_types[member_typename][index]
                    member_data = member_data[member_def["name"]]
                    member_typename = member_def["type"]

                    if is_array(member_typename):
                        array_size = parse_array_n(member_typename)
                        member_typename = typeof_array(member_typename)
                else:
                    if array_size != "dynamic":
                        if index > array_size - 1:
                            raise ValueError("array offset out of bounds")

                    # in array index offsets the array data, not type
                    member_data = member_data[index]

                    # in array, there is an array
                    if is_array(member_typename):
                        array_size = parse_array_n(member_typename)
                        member_typename = typeof_array(member_typename)
                    else:
                        # looking at a plain type now
                        array_size = None

            request = messages.EthereumTypedDataAck(
                member_type=member_typename,
            )

            if array_size:
                # strip arrays from type to see if it's a struct
                base_type = member_typename
                while is_array(base_type):
                    base_type = typeof_array(base_type)

                # is it?
                is_struct = base_type in member_types
                if is_struct:
                    request.member_type = base_type

                    if array_size == "dynamic":
                        request.member_array_n = len(member_data)
                    else:
                        request.member_array_n = array_size
                else:
                    # primitive type, pass it as-is
                    request.member_type = member_typename
                    request.member_value = encode_value(member_typename, member_data)
            else:
                # not in array
                is_struct = member_typename in member_types
                request.member_type = member_typename
                if not is_struct:
                    request.member_value = encode_value(member_typename, member_data)

            response = client.call(request)

    return response


def verify_message(client, address, signature, message):
    message = normalize_nfc(message)
    try:
        resp = client.call(
            messages.EthereumVerifyMessage(
                address=address, signature=signature, message=message
            )
        )
    except exceptions.TrezorFailure:
        return False
    return isinstance(resp, messages.Success)
