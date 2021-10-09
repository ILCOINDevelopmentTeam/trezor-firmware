if False:
    from typing import Dict

from trezor import wire
from trezor.crypto.curve import secp256k1
from trezor.crypto.hashlib import sha3_256
from trezor.messages import EthereumTypedDataValueAck
from trezor.messages import EthereumTypedDataValueRequest
from trezor.messages import EthereumTypedDataSignature
from trezor.messages import EthereumTypedDataStructAck
from trezor.messages import EthereumTypedDataStructRequest
from trezor.messages import EthereumFieldType
from trezor.enums import EthereumDataType
from trezor.utils import HashWriter

from apps.common import paths

from . import address
from .typed_data import get_type_name
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
        ctx, primary_type, message_types[primary_type].members
    )
    if show_message:
        await require_confirm_typed_data(
            ctx, primary_type, message_types, message_values
        )

    # TODO: the use_v4 variable is not used at all now, implement it
    domain_separator = hash_struct("EIP712Domain", domain_values, domain_types, use_v4)
    message_hash = hash_struct(primary_type, message_values, message_types, use_v4)

    if not show_message:
        await require_confirm_typed_data_hash(ctx, primary_type, message_hash)

    return keccak256(b"\x19" + b"\x01" + domain_separator + message_hash)


async def collect_types(
    ctx, type_name: str, types: Dict[str, EthereumTypedDataStructAck] = None
) -> Dict[str, EthereumTypedDataStructAck]:
    """
    Recursively collects types from the client
    """
    if types is None:
        types = {}

    req = EthereumTypedDataStructRequest(name=type_name)
    current_type = await ctx.call(req, EthereumTypedDataStructAck)
    types[type_name] = current_type
    for member in current_type.members:
        if (
            member.type.data_type == EthereumDataType.STRUCT
            and member.type.struct_name not in types
        ):
            types = await collect_types(ctx, member.type.struct_name, types)

    return types


def hash_struct(
    primary_type: str,
    data: dict,
    types: Dict[str, EthereumTypedDataStructAck],
    use_v4: bool = True,
) -> bytes:
    """
    Encodes and hashes an object using Keccak256
    """
    # TODO: create hashwriter object and pass it through other functions
    # w: Writer
    # w.append, w.extend methods
    # return w.digest()
    type_hash = hash_type(primary_type, types)
    encoded_data = encode_data(primary_type, data, types, use_v4)
    return keccak256(type_hash + encoded_data)


def encode_data(
    primary_type: str,
    data: dict,
    types: Dict[str, EthereumTypedDataStructAck],
    use_v4: bool = True,
) -> bytes:
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

    type_members = types[primary_type].members
    for member in type_members:
        encoded_value = encode_field(
            field=member.type,
            value=data[member.name],
            types=types,
            use_v4=use_v4,
        )
        result += encoded_value

    return result


def encode_field(
    field: EthereumFieldType,
    value: bytes,
    types: Dict[str, EthereumTypedDataStructAck],
    use_v4: bool = True,
) -> bytes:
    """
    SPEC:
    Atomic types:
    - Boolean false and true are encoded as uint256 values 0 and 1 respectively
    - Addresses are encoded as uint160
    - Integer values are sign-extended to 256-bit and encoded in big endian order
    - Bytes1 to bytes31 are arrays with a beginning (index 0)
      and an end (index length - 1), they are zero-padded at the end to bytes32 and encoded
      in beginning to end order
    Dynamic types:
    - Bytes and string are encoded as a keccak256 hash of their contents
    Reference types:
    - Array values are encoded as the keccak256 hash of the concatenated
      encodeData of their contents
    - Struct values are encoded recursively as hashStruct(value)
    """
    data_type = field.data_type

    # Arrays and structs need special recursive handling
    if data_type == EthereumDataType.ARRAY:
        buf = b""
        for element in value:
            buf += encode_field(
                field=field.entry_type,
                value=element,
                types=types,
                use_v4=use_v4,
            )
        return keccak256(buf)
    elif data_type == EthereumDataType.STRUCT:
        return hash_struct(
            primary_type=field.struct_name,
            data=value,
            types=types,
            use_v4=use_v4,
        )
    elif data_type == EthereumDataType.BYTES:
        if field["size"] is None:
            return keccak256(value)
        else:
            return rightpad32(value, 32)
    elif data_type == EthereumDataType.STRING:
        return keccak256(value)
    elif data_type in [
        EthereumDataType.UINT,
        EthereumDataType.INT,
        EthereumDataType.BOOL,
        EthereumDataType.ADDRESS,
    ]:
        return leftpad32(value)

    raise ValueError  # Unsupported data type for field encoding


def leftpad32(value: bytes) -> bytes:
    if len(value) > 32:
        raise ValueError  # Number is bigger than 32 bytes

    missing_bytes = 32 - len(value)
    return missing_bytes * b"\x00" + value


def rightpad32(value: bytes) -> bytes:
    if len(value) > 32:
        raise ValueError  # Number is bigger than 32 bytes

    missing_bytes = 32 - len(value)
    return value + missing_bytes * b"\x00"


async def collect_values(
    ctx,
    primary_type: str,
    types: Dict[str, EthereumTypedDataStructAck],
    member_path: list = None,
) -> dict:
    """
    Collects data values from the client
    """
    # Member path starting with [0] means getting domain values, [1] is for message values
    if member_path is None:
        member_path = [1]

    values = {}

    type_members = types[primary_type].members
    for member_index, member in enumerate(type_members):
        field_name = member.name
        field_type = member.type.data_type
        member_value_path = member_path + [member_index]

        # Structs need to be handled recursively, arrays are also special
        if field_type == EthereumDataType.STRUCT:
            struct_name = member.type.struct_name
            values[field_name] = await collect_values(
                ctx, struct_name, types, member_value_path
            )
        elif field_type == EthereumDataType.ARRAY:
            # TODO: account for array of structs (and array of arrays)
            res = await request_member_value(ctx, member_value_path)
            array_size = int.from_bytes(res.value, "big")
            arr = []
            for i in range(array_size):
                res = await request_member_value(ctx, member_value_path + [i])
                validate_field(member.type.entry_type, field_name, res.value)
                arr.append(res.value)
            values[field_name] = arr
        else:
            res = await request_member_value(ctx, member_value_path)
            validate_field(member.type, field_name, res.value)
            values[field_name] = res.value

    return values


def validate_field(field: EthereumFieldType, field_name: str, value: bytes) -> None:
    """
    Makes sure the byte data we receive are not corrupted or incorrect

    Raises wire.DataError if it encounters a problem, so clients are notified
    """
    field_size = field.size
    field_type = field.data_type

    # Checking if the size corresponds to what is defined in types,
    # and also setting our maximum supported size in bytes
    if field_size is not None:
        if len(value) != field_size:
            raise wire.DataError("{}: invalid length".format(field_name))
    else:
        max_byte_size = 1024
        if len(value) > max_byte_size:
            raise wire.DataError(
                "{}: invalid length, bigger than {}".format(field_name, max_byte_size)
            )

    # Specific tests for some data types
    if field_type == EthereumDataType.BOOL:
        if value not in [b"\x00", b"\x01"]:
            raise wire.DataError("{}: invalid boolean value".format(field_name))
    elif field_type == EthereumDataType.ADDRESS:
        if len(value) != 20:
            raise wire.DataError("{}: invalid address".format(field_name))
    elif field_type == EthereumDataType.STRING:
        try:
            value.decode()
        except UnicodeError:
            raise wire.DataError("{}: invalid UTF-8".format(field_name))


def hash_type(primary_type: str, types: Dict[str, EthereumTypedDataStructAck]) -> bytes:
    """
    Encodes and hashes a type using Keccak256
    """
    return keccak256(encode_type(primary_type, types))


def encode_type(
    primary_type: str, types: Dict[str, EthereumTypedDataStructAck]
) -> bytes:
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
        members = types[type_name].members
        fields = ",".join(["%s %s" % (get_type_name(m.type), m.name) for m in members])
        result += b"%s(%s)" % (type_name, fields)

    return result


def find_typed_dependencies(
    primary_type: str,
    types: Dict[str, EthereumTypedDataStructAck],
    results: list = None,
) -> list:
    """
    Finds all types within a type definition object

    primary_type - Root type
    types - Type definitions
    results - Current set of accumulated types
    """
    if results is None:
        results = []

    # When being an array, getting the part before the square brackets
    if primary_type[-1] == "]":
        primary_type = primary_type[: primary_type.index("[")]

    # We already have this type or it is not even a defined type
    if (primary_type in results) or (primary_type not in types):
        return results

    results.append(primary_type)

    # Recursively adding all the children struct types
    type_members = types[primary_type].members
    for member in type_members:
        if member.type.data_type == EthereumDataType.STRUCT:
            results = find_typed_dependencies(member.type.struct_name, types, results)

    return results


async def request_member_value(ctx, member_path: list) -> EthereumTypedDataValueAck:
    """
    Requests a value of member at `member_path` from the client
    """
    req = EthereumTypedDataValueRequest(
        member_path=member_path,
    )
    return await ctx.call(req, EthereumTypedDataValueAck)
