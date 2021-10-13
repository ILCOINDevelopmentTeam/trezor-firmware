if False:
    from typing import Dict
    from trezor.wire import Context

from ubinascii import hexlify

from trezor import wire
from trezor.enums import EthereumDataType, ButtonRequestType
from trezor.messages import EthereumFieldType
from trezor.messages import EthereumTypedDataStructAck
from trezor.messages import EthereumTypedDataValueAck
from trezor.messages import EthereumTypedDataValueRequest
from trezor.messages import EthereumStructMember

from trezor.ui.layouts import (
    confirm_properties
)


from trezor.utils import HashWriter
from trezor.crypto.hashlib import sha3_256

from .address import address_from_bytes


def get_hash_writer() -> HashWriter:
    return HashWriter(sha3_256(keccak=True))


def keccak256(message: bytes) -> bytes:
    h = get_hash_writer()
    h.extend(message)
    return h.get_digest()


async def hash_struct(
    ctx: Context,
    primary_type: str,
    types: Dict[str, EthereumTypedDataStructAck],
    member_path: list,
    show_data: bool,
    parent_objects: list,
    metamask_v4_compat: bool = True,
) -> bytes:
    """
    Encodes and hashes an object using Keccak256
    """
    w = get_hash_writer()
    hash_type(w, primary_type, types)
    await get_and_encode_data(
        ctx=ctx,
        w=w,
        primary_type=primary_type,
        types=types,
        member_path=member_path,
        show_data=show_data,
        parent_objects=parent_objects,
        metamask_v4_compat=metamask_v4_compat,
    )
    return w.get_digest()


async def get_and_encode_data(
    ctx: Context,
    w: HashWriter,
    primary_type: str,
    types: Dict[str, EthereumTypedDataStructAck],
    member_path: list,
    show_data: bool,
    parent_objects: list,
    metamask_v4_compat: bool = True,
) -> None:
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
    type_members = types[primary_type].members
    for member_index, member in enumerate(type_members):
        member_value_path = member_path + [member_index]
        data_type = member.type.data_type

        # Arrays and structs need special recursive handling
        if data_type == EthereumDataType.STRUCT:
            struct_name = member.type.struct_name
            res = await hash_struct(
                ctx=ctx,
                primary_type=struct_name,
                types=types,
                member_path=member_value_path,
                show_data=show_data,
                parent_objects=parent_objects + [member.name],
                metamask_v4_compat=metamask_v4_compat,
            )
            w.extend(res)
        elif data_type == EthereumDataType.ARRAY:
            # Getting the length of the array first
            length_res = await request_member_value(ctx, member_value_path)
            array_size = int.from_bytes(length_res.value, "big")
            entry_type = member.type.entry_type
            arr_w = get_hash_writer()
            for i in range(array_size):
                el_member_path = member_value_path + [i]
                # TODO: we do not support arrays of arrays, check if we should
                if entry_type.data_type == EthereumDataType.STRUCT:
                    struct_name = entry_type.struct_name
                    # Metamask V4 implementation has a bug, that causes the
                    # behavior of structs in array be different from SPEC
                    # Explanation at https://github.com/MetaMask/eth-sig-util/pull/107
                    # encode_data() is the way to process structs in arrays, but
                    # Metamask V4 is using hash_struct() even in this case
                    if metamask_v4_compat:
                        res = await hash_struct(
                            ctx=ctx,
                            primary_type=struct_name,
                            types=types,
                            member_path=el_member_path,
                            show_data=show_data,
                            parent_objects=parent_objects + [member.name],
                            metamask_v4_compat=metamask_v4_compat,
                        )
                        arr_w.extend(res)
                    else:
                        await get_and_encode_data(
                            ctx=ctx,
                            w=arr_w,
                            primary_type=struct_name,
                            types=types,
                            member_path=el_member_path,
                            show_data=show_data,
                            parent_objects=parent_objects + [member.name],
                            metamask_v4_compat=metamask_v4_compat,
                        )
                else:
                    value = await get_value(ctx, member, el_member_path)
                    encode_field(arr_w, entry_type, value)
                    if show_data:
                        title = ".".join(parent_objects) + " - " + primary_type
                        type_name = get_type_name(entry_type)
                        await show_data_to_user(ctx, member.name, value, title, type_name, i)
            w.extend(arr_w.get_digest())
        else:
            value = await get_value(ctx, member, member_value_path)
            encode_field(w, member.type, value)
            if show_data:
                title = ".".join(parent_objects) + " - " + primary_type
                type_name = get_type_name(member.type)
                await show_data_to_user(ctx, member.name, value, title, type_name)


async def show_data_to_user(
    ctx: Context,
    name: str,
    value: str,
    title: str,
    type_name: str,
    array_index: int = None
) -> None:
    if array_index is not None:
        array_str = "[{}]".format(array_index)
    else:
        array_str = ""

    props = [
        ("{}{} ({})".format(name, array_str, type_name), decode_data(value, type_name)),
    ]

    await confirm_properties(
        ctx,
        "show_data",
        title=title,
        props=props,
        br_code=ButtonRequestType.Other,
    )


def encode_field(
    w: HashWriter,
    field: EthereumFieldType,
    value: bytes,
) -> None:
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

    if data_type == EthereumDataType.BYTES:
        # TODO: is not tested
        if field.size is None:
            w.extend(keccak256(value))
        else:
            write_rightpad32(value)
    elif data_type == EthereumDataType.STRING:
        w.extend((keccak256(value)))
    elif data_type == EthereumDataType.INT:
        write_leftpad32(w, value, signed=True)
    elif data_type in [
        EthereumDataType.UINT,
        EthereumDataType.BOOL,
        EthereumDataType.ADDRESS,
    ]:
        write_leftpad32(w, value)
    else:
        raise ValueError  # Unsupported data type for field encoding


def write_leftpad32(w: HashWriter, value: bytes, signed: bool = False) -> None:
    assert len(value) <= 32

    # Values need to be sign-extended, so accounting for negative ints
    if signed and value[0] & 0x80:
        pad_value = b"\xff"
    else:
        pad_value = b"\x00"

    missing_bytes = 32 - len(value)
    to_write = missing_bytes * pad_value + value
    w.extend(to_write)


def write_rightpad32(w: HashWriter, value: bytes) -> None:
    assert len(value) <= 32

    missing_bytes = 32 - len(value)
    to_write = value + missing_bytes * b"\x00"
    w.extend(to_write)


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


def validate_field_type(field: EthereumFieldType) -> None:
    """
    Makes sure the field type is consistent with our expectation

    Raises wire.DataError if it encounters a problem, so clients are notified
    """
    data_type = field.data_type

    # entry_type is only for arrays
    if data_type == EthereumDataType.ARRAY:
        if field.entry_type is None:
            raise wire.DataError("Missing entry_type in array EthereumFieldType")
        # We also need to validate it recursively
        validate_field_type(field.entry_type)
    else:
        if field.entry_type is not None:
            raise wire.DataError("Redundant entry_type in nonarray EthereumFieldType")

    # struct_name is only for structs
    if data_type == EthereumDataType.STRUCT:
        if field.struct_name is None:
            raise wire.DataError("Missing struct_name in struct EthereumFieldType")
    else:
        if field.struct_name is not None:
            raise wire.DataError("Redundant struct_name in nonstruct EthereumFieldType")

    # size is special for each type
    if data_type == EthereumDataType.STRUCT:
        if field.size is None:
            raise wire.DataError("Missing size in struct EthereumFieldType")
    elif data_type == EthereumDataType.BYTES:
        if field.size is not None:
            if field.size not in range(1, 33):
                raise wire.DataError("Invalid size in bytes EthereumFieldType")
    elif data_type in [
        EthereumDataType.UINT,
        EthereumDataType.INT,
    ]:
        if field.size not in range(1, 33):
            raise wire.DataError("Invalid size in int/uint EthereumFieldType")
    elif data_type in [
        EthereumDataType.STRING,
        EthereumDataType.BOOL,
        EthereumDataType.ADDRESS,
    ]:
        if field.size is not None:
            raise wire.DataError("Redundant size in str/bool/addr EthereumFieldType")


def hash_type(
    w: HashWriter, primary_type: str, types: Dict[str, EthereumTypedDataStructAck]
) -> None:
    """
    Encodes and hashes a type using Keccak256
    """
    result = keccak256(encode_type(primary_type, types))
    w.extend(result)


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

    deps = []
    find_typed_dependencies(primary_type, types, deps)
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
    results: list,
) -> None:
    """
    Finds all types within a type definition object

    primary_type - Root type
    types - Type definitions
    results - Current set of accumulated types
    """
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
            find_typed_dependencies(member.type.struct_name, types, results)


def get_type_name(field: EthereumFieldType) -> str:
    """Create a string from type definition (like uint256 or bytes16)"""
    data_type = field.data_type
    size = field.size

    TYPE_TRANSLATION_DICT = {
        EthereumDataType.UINT: "uint",
        EthereumDataType.INT: "int",
        EthereumDataType.BYTES: "bytes",
        EthereumDataType.STRING: "string",
        EthereumDataType.BOOL: "bool",
        EthereumDataType.ADDRESS: "address",
    }

    if data_type == EthereumDataType.STRUCT:
        return field.struct_name
    elif data_type == EthereumDataType.ARRAY:
        entry_type = field.entry_type
        if size is None:
            return get_type_name(entry_type) + "[]"
        else:
            return "{}[{}]".format(get_type_name(entry_type), size)
    elif data_type in [
        EthereumDataType.STRING,
        EthereumDataType.BOOL,
        EthereumDataType.ADDRESS,
    ]:
        return TYPE_TRANSLATION_DICT[data_type]
    elif data_type in [EthereumDataType.UINT, EthereumDataType.INT]:
        return TYPE_TRANSLATION_DICT[data_type] + str(size * 8)
    elif data_type == EthereumDataType.BYTES:
        if size:
            return TYPE_TRANSLATION_DICT[data_type] + str(size)
        else:
            return TYPE_TRANSLATION_DICT[data_type]

    raise ValueError  # Unsupported data type


def decode_data(data: bytes, type_name: str) -> str:
    if type_name == "bytes":
        return hexlify(data).decode()
    elif type_name == "string":
        return data.decode()
    elif type_name == "address":
        return address_from_bytes(data)
    elif type_name == "bool":
        return "true" if data == b"\x01" else "false"
    elif type_name.startswith("uint"):
        return str(int.from_bytes(data, "big"))
    elif type_name.startswith("int"):
        # Micropython does not implement "signed" arg in int.from_bytes()
        return str(from_bytes_to_bigendian_signed(data))

    raise ValueError  # Unsupported data type for direct field decoding


def from_bytes_to_bigendian_signed(b: bytes) -> int:
    negative = b[0] & 0x80
    if negative:
        neg_b = bytearray(b)
        for i in range(len(neg_b)):
            neg_b[i] = ~neg_b[i] & 0xFF
        result = int.from_bytes(neg_b, "big")
        return -result - 1
    else:
        return int.from_bytes(b, "big")


async def get_value(
    ctx: Context,
    member: EthereumStructMember,
    member_value_path: list,
) -> bytes:
    """
    Gets a single value from the client
    """
    field_name = member.name
    res = await request_member_value(ctx, member_value_path)
    validate_field(field=member.type, field_name=field_name, value=res.value)
    return res.value


async def request_member_value(
    ctx: Context, member_path: list
) -> EthereumTypedDataValueAck:
    """
    Requests a value of member at `member_path` from the client
    """
    req = EthereumTypedDataValueRequest(
        member_path=member_path,
    )
    return await ctx.call(req, EthereumTypedDataValueAck)
