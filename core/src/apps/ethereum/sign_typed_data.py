from trezor.crypto.curve import secp256k1
from trezor.crypto.hashlib import sha3_256
from trezor.messages import EthereumTypedDataValueAck
from trezor.messages import EthereumTypedDataValueRequest
from trezor.messages import EthereumTypedDataSignature
from trezor.messages import EthereumTypedDataStructAck
from trezor.messages import EthereumTypedDataStructRequest
from trezor.enums import EthereumDataType
from trezor.utils import HashWriter

from apps.common import paths

from . import address
from .keychain import PATTERNS_ADDRESS, with_keychain_from_path
from .layout import (
    confirm_typed_data_brief,
    confirm_typed_domain_brief,
    require_confirm_typed_data,
    require_confirm_typed_data_hash,
    require_confirm_typed_domain,
)


def keccak256(message: bytes) -> bytes:
    h = HashWriter(sha3_256(keccak=True))
    h.extend(message)
    return h.get_digest()


@with_keychain_from_path(*PATTERNS_ADDRESS)
async def sign_typed_data(ctx, msg, keychain):
    data_hash = await generate_typed_data_hash(
        ctx, msg.primary_type, msg.metamask_v4_compat
    )

    await paths.validate_path(ctx, keychain, msg.address_n)

    node = keychain.derive(msg.address_n)
    signature = secp256k1.sign(
        node.private_key(), data_hash, False, secp256k1.CANONICAL_SIG_ETHEREUM
    )

    return EthereumTypedDataSignature(
        address=address.address_from_bytes(node.ethereum_pubkeyhash()),
        signature=signature[1:] + bytearray([signature[0]]),
    )


async def generate_typed_data_hash(
    ctx, primary_type: str, use_v4: bool = True
) -> bytes:
    """
    Generates typed data hash according to EIP-712 specification
    https://eips.ethereum.org/EIPS/eip-712#specification

    use_v4 - a flag that enables compatibility with MetaMask's signTypedData_v4 method
    """
    domain_types = await collect_types(ctx, "EIP712Domain")
    message_types = await collect_types(ctx, primary_type)
    domain_values = await collect_values(ctx, "EIP712Domain", domain_types, [0])
    message_values = await collect_values(ctx, primary_type, message_types)

    show_domain = await confirm_typed_domain_brief(ctx, domain_values)
    if show_domain:
        await require_confirm_typed_domain(
            ctx, domain_types["EIP712Domain"], domain_values
        )

    show_message = await confirm_typed_data_brief(
        ctx, primary_type, message_types[primary_type]
    )
    if show_message:
        await require_confirm_typed_data(
            ctx, primary_type, message_types, message_values
        )

    domain_separator = hash_struct("EIP712Domain", domain_values, domain_types, use_v4)
    message_hash = hash_struct(primary_type, message_values, message_types, use_v4)

    if not show_message:
        await require_confirm_typed_data_hash(ctx, primary_type, message_hash)

    return keccak256(b"\x19" + b"\x01" + domain_separator + message_hash)


async def collect_types(ctx, type_name: str, types: dict = None) -> dict:
    """
    Recursively collects types from the client
    """
    if types is None:
        types = {}

    # We already have that type
    if type_name in types:
        return types

    req = EthereumTypedDataStructRequest(name=type_name)
    res = await ctx.call(req, EthereumTypedDataStructAck)

    new_types = set()
    children = []
    for member in res.members:
        if member.type.data_type == EthereumDataType.STRUCT:
            new_types.add(member.type.type_name)
        children.append(
            {
                "data_type": member.type.data_type,
                "name": member.name,
                "size": member.type.size,
                "type_name": member.type.type_name,
                "entry_type": member.type.entry_type,
            }
        )

    types[type_name] = children

    # Recursively accounting for all the new types
    if len(new_types) > 0:
        for new_type in new_types:
            types = await collect_types(ctx, new_type, types)

    return types


def hash_struct(
    primary_type: str, data: dict, types: dict, use_v4: bool = True
) -> bytes:
    """
    Encodes and hashes an object using Keccak256
    """
    type_hash = hash_type(primary_type, types)
    encoded_data = encode_data(primary_type, data, types, use_v4)
    return keccak256(type_hash + encoded_data)


def encode_data(
    primary_type: str, data: dict, types: dict, use_v4: bool = True
) -> bytearray:
    """
    Encodes an object by encoding and concatenating each of its members

    SPEC:
    The encoding of a struct instance is enc(value₁) ‖ enc(value₂) ‖ … ‖ enc(valueₙ),
    i.e. the concatenation of the encoded member values in the order that they appear in the type.
    Each encoded member value is exactly 32-byte long.

    primary_type - Root type
    data - Object to encode
    types - Type definitions
    """
    result = b""

    for field in types[primary_type]:
        # Structs are handled on their own, arrays are also special
        if field["data_type"] == EthereumDataType.STRUCT:
            # SPEC: The struct values are encoded recursively as hashStruct(value)
            encoded_value = hash_struct(
                field["type_name"], data[field["name"]], types, use_v4
            )
        elif field["data_type"] == EthereumDataType.ARRAY:
            # SPEC:
            # The array values are encoded as the keccak256 hash of the concatenated
            # encodeData of their contents
            # TODO: To be implemented. We need to account for possible structs in array
            pass
        else:
            encoded_value = encode_field(
                field=field,
                value=data[field["name"]],
            )
        result += encoded_value

    return result


def encode_field(field: dict, value) -> bytes:
    """
    SPEC:
    The atomic values are encoded as follows:
    Boolean false and true are encoded as uint256 values 0 and 1 respectively.
    Addresses are encoded as uint160. Integer values are sign-extended to 256-bit and
    encoded in big endian order. bytes1 to bytes31 are arrays with a beginning (index 0)
    and an end (index length - 1), they are zero-padded at the end to bytes32 and encoded
    in beginning to end order.
    The dynamic values bytes and string are encoded as a keccak256 hash of their contents.
    """
    data_type = field["data_type"]
    size = field["size"]
    if data_type == EthereumDataType.UINT:
        num = int(value)
        return num.to_bytes(32, "big")
    elif data_type == EthereumDataType.INT:
        num = int(value)
        return num.to_bytes(32, "big", signed=True)
    elif data_type == EthereumDataType.BYTES:
        if size is None:
            return keccak256(value)
        else:
            return set_length_right(value, 32)
    elif data_type == EthereumDataType.STRING:
        return keccak256(value.encode())
    elif data_type == EthereumDataType.BOOL:
        num = 1 if value is True else 0
        return num.to_bytes(32, "big")
    elif data_type == EthereumDataType.ADDRESS:
        num = int(value, 16)
        return num.to_bytes(32, "big")

    # Structs and arrays should not be encoded directly by this function
    raise ValueError  # Unsupported data type for encoding


def set_length_right(msg: bytes, length: int) -> bytes:
    """
    Pads a `msg` with zeros till it has `length` bytes.
    Truncates the end of input if its length exceeds `length`.
    """
    # TODO: the SPEC may say something different: (test it on bytes16 for example)
    # SPEC:
    # bytes1 to bytes31 are arrays with a beginning (index 0) and an end (index length - 1),
    # they are zero-padded at the end to bytes32 and encoded in beginning to end order
    if len(msg) < length:
        buf = bytearray(length)
        buf[: len(msg)] = msg
        return buf

    return msg[:length]


async def collect_values(
    ctx, primary_type: str, types: dict, member_path: list = None
) -> dict:
    """
    Collects data values from the client
    """
    # Member path starting with [0] means getting domain values, [1] is for message values
    if member_path is None:
        member_path = [1]

    values = {}
    struct = types[primary_type]

    for fieldIdx in range(len(struct)):
        field = struct[fieldIdx]
        field_name = field["name"]
        field_type = field["data_type"]
        member_value_path = member_path + [fieldIdx]

        # Structs need to be handled recursively
        if field_type == EthereumDataType.STRUCT:
            struct_name = field["type_name"]
            values[field_name] = await collect_values(
                ctx, struct_name, types, member_value_path
            )
        else:
            res = await request_member_value(ctx, member_value_path)
            # TODO: here we could potentially check if the size corresponds to what is defined in types,
            # and also if the size does not exceed 1024 bytes
            values[field_name] = res.value

    return values


def hash_type(primary_type: str, types: dict) -> bytes:
    """
    Encodes and hashes a type using Keccak256
    """
    return keccak256(encode_type(primary_type, types))


def encode_type(primary_type: str, types: dict) -> bytes:
    """
    Encodes the type of an object by encoding a comma delimited list of its members

    SPEC:
    The type of a struct is encoded as name ‖ "(" ‖ member₁ ‖ "," ‖ member₂ ‖ "," ‖ … ‖ memberₙ ")"
    where each member is written as type ‖ " " ‖ name
    If the struct type references other struct types (and these in turn reference even more struct types),
    then the set of referenced struct types is collected, sorted by name and appended to the encoding.

    primary_type - Root type to encode
    types - Type definitions
    """
    result = b""

    deps = find_typed_dependencies(primary_type, types)
    non_primary_deps = [dep for dep in deps if dep != primary_type]
    primary_first_sorted_deps = [primary_type] + sorted(non_primary_deps)

    for type_name in primary_first_sorted_deps:
        children = types[type_name]
        fields = ",".join(["%s %s" % (c["type_name"], c["name"]) for c in children])
        result += b"%s(%s)" % (type_name, fields)

    return result


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

    if primary_type[-1] == "]":
        primary_type = primary_type[: primary_type.rindex("[")]

    # We already have this type or it is not even a defined type
    if (primary_type in results) or (primary_type not in types):
        return results

    results.append(primary_type)
    # Recursively adding all the children struct types
    for field in types[primary_type]:
        if field["data_type"] == EthereumDataType.STRUCT:
            deps = find_typed_dependencies(field["type_name"], types, results)
            for dep in deps:
                if dep not in results:
                    results.append(dep)

    return results


async def request_member_value(ctx, member_path: list) -> EthereumTypedDataValueAck:
    """
    Requests a value of member at `member_path` from the client
    """
    req = EthereumTypedDataValueRequest(
        member_path=member_path,
    )
    return await ctx.call(req, EthereumTypedDataValueAck)
