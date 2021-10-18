from ubinascii import hexlify

from trezor import wire
from trezor.crypto.hashlib import sha3_256
from trezor.enums import ButtonRequestType, EthereumDataType
from trezor.messages import (
    EthereumFieldType,
    EthereumTypedDataStructAck,
    EthereumTypedDataValueAck,
    EthereumTypedDataValueRequest,
)
from trezor.ui.layouts import confirm_blob, confirm_text
from trezor.utils import HashWriter

from .address import address_from_bytes

if False:
    from typing import Dict, Iterable, List, Optional
    from trezor.wire import Context


# TODO: the functions' docstrings need to be updated to match current situation
# TODO: address numerous mypy issues, mostly about EthereumFieldType's optional attributes
# TODO: get better layouts
# TODO: create the UI logic to ask for showing details
# TODO: create unit tests for hashing class

# Maximum data size we support
MAX_VALUE_BYTE_SIZE = 1024
# Field type for getting the array length from client, so we can check the return value
ARRAY_LENGTH_TYPE = EthereumFieldType(data_type=EthereumDataType.UINT, size=2)


def get_hash_writer() -> HashWriter:
    return HashWriter(sha3_256(keccak=True))


def keccak256(message: bytes) -> bytes:
    h = get_hash_writer()
    h.extend(message)
    return h.get_digest()


class StructHasher:
    """Putting together the main hashing functionality"""

    def __init__(
        self,
        ctx: Context,
        types: Dict[str, EthereumTypedDataStructAck],
        metamask_v4_compat: bool,
    ) -> None:
        self.ctx = ctx
        self.types = types
        self.metamask_v4_compat = metamask_v4_compat

    async def hash_struct(
        self,
        primary_type: str,
        member_path: list,
        show_data: bool,
        parent_objects: list,
    ) -> bytes:
        """
        Encodes and hashes an object using Keccak256
        """
        w = get_hash_writer()
        hash_type(w, primary_type, self.types)
        await self.get_and_encode_data(
            w=w,
            primary_type=primary_type,
            member_path=member_path,
            show_data=show_data,
            parent_objects=parent_objects,
        )
        return w.get_digest()

    async def get_and_encode_data(
        self,
        w: HashWriter,
        primary_type: str,
        member_path: list,
        show_data: bool,
        parent_objects: list,
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
        type_members = self.types[primary_type].members
        for member_index, member in enumerate(type_members):
            member_value_path = member_path + [member_index]
            data_type = member.type.data_type
            field_name = member.name

            # Arrays and structs need special recursive handling
            if data_type == EthereumDataType.STRUCT:
                assert member.type.struct_name is not None  # validate_field_type
                struct_name = member.type.struct_name
                res = await self.hash_struct(
                    primary_type=struct_name,
                    member_path=member_value_path,
                    show_data=show_data,
                    parent_objects=parent_objects + [field_name],
                )
                w.extend(res)
            elif data_type == EthereumDataType.ARRAY:
                # Getting the length of the array first, if not fixed
                if member.type.size is None:
                    array_size = await get_array_size(self.ctx, member_value_path)
                else:
                    array_size = member.type.size

                assert member.type.entry_type is not None  # validate_field_type
                entry_type = member.type.entry_type
                arr_w = get_hash_writer()
                for i in range(array_size):
                    el_member_path = member_value_path + [i]
                    # TODO: we do not support arrays of arrays, check if we should
                    if entry_type.data_type == EthereumDataType.STRUCT:
                        assert entry_type.struct_name is not None  # validate_field_type
                        struct_name = entry_type.struct_name
                        # Metamask V4 implementation has a bug, that causes the
                        # behavior of structs in array be different from SPEC
                        # Explanation at https://github.com/MetaMask/eth-sig-util/pull/107
                        # encode_data() is the way to process structs in arrays, but
                        # Metamask V4 is using hash_struct() even in this case
                        if self.metamask_v4_compat:
                            res = await self.hash_struct(
                                primary_type=struct_name,
                                member_path=el_member_path,
                                show_data=show_data,
                                parent_objects=parent_objects + [field_name],
                            )
                            arr_w.extend(res)
                        else:
                            await self.get_and_encode_data(
                                w=arr_w,
                                primary_type=struct_name,
                                member_path=el_member_path,
                                show_data=show_data,
                                parent_objects=parent_objects + [field_name],
                            )
                    else:
                        value = await get_value(self.ctx, entry_type, el_member_path)
                        encode_field(arr_w, entry_type, value)
                        if show_data:
                            await show_data_to_user(
                                ctx=self.ctx,
                                name=field_name,
                                value=value,
                                parent_objects=parent_objects,
                                primary_type=primary_type,
                                field=entry_type,
                                array_index=i,
                            )
                w.extend(arr_w.get_digest())
            else:
                value = await get_value(self.ctx, member.type, member_value_path)
                encode_field(w, member.type, value)
                if show_data:
                    await show_data_to_user(
                        ctx=self.ctx,
                        name=field_name,
                        value=value,
                        parent_objects=parent_objects,
                        primary_type=primary_type,
                        field=member.type,
                    )


async def show_data_to_user(
    ctx: Context,
    name: str,
    value: bytes,
    parent_objects: Iterable[str],
    primary_type: str,
    field: EthereumFieldType,
    array_index: Optional[int] = None,
) -> None:
    type_name = get_type_name(field)
    title = f"{'.'.join(parent_objects)} - {primary_type}"

    if array_index is not None:
        array_str = f"[{array_index}]"
    else:
        array_str = ""

    description = f"{name}{array_str} ({type_name})"
    data = decode_data(value, type_name)

    if field.data_type in (EthereumDataType.ADDRESS, EthereumDataType.BYTES):
        await confirm_blob(
            ctx,
            "show_data",
            title=title,
            data=data,
            description=description,
            br_code=ButtonRequestType.Other,
        )
    else:
        await confirm_text(
            ctx,
            "show_data",
            title=title,
            data=data,
            description=description,
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
        if field.size is None:
            w.extend(keccak256(value))
        else:
            write_rightpad32(w, value)
    elif data_type == EthereumDataType.STRING:
        w.extend(keccak256(value))
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
        pad_value = 0xFF
    else:
        pad_value = 0x00

    for _ in range(32 - len(value)):
        w.append(pad_value)
    w.extend(value)


def write_rightpad32(w: HashWriter, value: bytes) -> None:
    assert len(value) <= 32

    w.extend(value)
    for _ in range(32 - len(value)):
        w.append(0x00)


def validate_value(field: EthereumFieldType, value: bytes) -> None:
    """
    Makes sure the byte data we receive are not corrupted or incorrect

    Raises wire.DataError if it encounters a problem, so clients are notified
    """
    # Checking if the size corresponds to what is defined in types,
    # and also setting our maximum supported size in bytes
    if field.size is not None:
        if len(value) != field.size:
            raise wire.DataError("Invalid length")
    else:
        if len(value) > MAX_VALUE_BYTE_SIZE:
            raise wire.DataError("Invalid length, bigger than {MAX_VALUE_BYTE_SIZE}")

    # Specific tests for some data types
    if field.data_type == EthereumDataType.BOOL:
        if value not in (b"\x00", b"\x01"):
            raise wire.DataError("Invalid boolean value")
    elif field.data_type == EthereumDataType.ADDRESS:
        if len(value) != 20:
            raise wire.DataError("Invalid address")
    elif field.data_type == EthereumDataType.STRING:
        try:
            value.decode()
        except UnicodeError:
            raise wire.DataError("Invalid UTF-8")


def validate_field_type(field: EthereumFieldType) -> None:
    """
    Makes sure the field type is consistent with our expectation

    Raises wire.DataError if it encounters a problem, so clients are notified
    """
    data_type = field.data_type

    # entry_type is only for arrays
    if data_type == EthereumDataType.ARRAY:
        if field.entry_type is None:
            raise wire.DataError("Missing entry_type in array")
        # We also need to validate it recursively
        validate_field_type(field.entry_type)
    else:
        if field.entry_type is not None:
            raise wire.DataError("Unexpected entry_type in nonarray")

    # struct_name is only for structs
    if data_type == EthereumDataType.STRUCT:
        if field.struct_name is None:
            raise wire.DataError("Missing struct_name in struct")
    else:
        if field.struct_name is not None:
            raise wire.DataError("Unexpected struct_name in nonstruct")

    # size is special for each type
    if data_type == EthereumDataType.STRUCT:
        if field.size is None:
            raise wire.DataError("Missing size in struct")
    elif data_type == EthereumDataType.BYTES:
        if field.size is not None and not 1 <= field.size <= 32:
            raise wire.DataError("Invalid size in bytes")
    elif data_type in [
        EthereumDataType.UINT,
        EthereumDataType.INT,
    ]:
        if field.size is None or not 1 <= field.size <= 32:
            raise wire.DataError("Invalid size in int/uint")
    elif data_type in [
        EthereumDataType.STRING,
        EthereumDataType.BOOL,
        EthereumDataType.ADDRESS,
    ]:
        if field.size is not None:
            raise wire.DataError("Unexpected size in str/bool/addr")


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

    deps: List[str] = []
    find_typed_dependencies(primary_type, types, deps)
    non_primary_deps = [dep for dep in deps if dep != primary_type]
    primary_first_sorted_deps = [primary_type] + sorted(non_primary_deps)

    for type_name in primary_first_sorted_deps:
        members = types[type_name].members
        fields = ",".join([f"{get_type_name(m.type)} {m.name}" for m in members])
        result += f"{type_name}({fields})".encode()

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
    # We already have this type or it is not even a defined type
    if (primary_type in results) or (primary_type not in types):
        return

    results.append(primary_type)

    # Recursively adding all the children struct types,
    # also looking into (even nested) arrays for them
    type_members = types[primary_type].members
    for member in type_members:
        if member.type.data_type == EthereumDataType.STRUCT:
            assert member.type.struct_name is not None  # validate_field_type
            find_typed_dependencies(member.type.struct_name, types, results)
        elif member.type.data_type == EthereumDataType.ARRAY:
            # Finding the last entry_type and checking it for being struct
            assert member.type.entry_type is not None  # validate_field_type
            entry_type = member.type.entry_type
            while True:
                if entry_type.entry_type is None:
                    break
                entry_type = entry_type.entry_type
            if entry_type.data_type == EthereumDataType.STRUCT:
                assert entry_type.struct_name is not None  # validate_field_type
                find_typed_dependencies(entry_type.struct_name, types, results)


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
        assert field.struct_name is not None  # validate_field_type
        return field.struct_name
    elif data_type == EthereumDataType.ARRAY:
        assert field.entry_type is not None  # validate_field_type
        entry_type = field.entry_type
        type_name = get_type_name(entry_type)
        if size is None:
            return f"{type_name}[]"
        else:
            return f"{type_name}[{size}]"
    elif data_type in (EthereumDataType.UINT, EthereumDataType.INT):
        assert size is not None  # validate_field_type
        return TYPE_TRANSLATION_DICT[data_type] + str(size * 8)
    elif data_type == EthereumDataType.BYTES:
        if size:
            return TYPE_TRANSLATION_DICT[data_type] + str(size)
        else:
            return TYPE_TRANSLATION_DICT[data_type]
    else:
        # all remaining types can use the name directly
        # if the data_type is left out, this will raise KeyError
        return TYPE_TRANSLATION_DICT[data_type]


def decode_data(data: bytes, type_name: str) -> str:
    if type_name.startswith("bytes"):
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
        return str(from_bytes_bigendian_signed(data))

    raise ValueError  # Unsupported data type for direct field decoding


def from_bytes_bigendian_signed(b: bytes) -> int:
    negative = b[0] & 0x80
    if negative:
        neg_b = bytearray(b)
        for i in range(len(neg_b)):
            neg_b[i] = ~neg_b[i] & 0xFF
        result = int.from_bytes(neg_b, "big")
        return -result - 1
    else:
        return int.from_bytes(b, "big")


async def get_array_size(ctx: Context, member_path: list) -> int:
    """
    Gets the length of an array at specific `member_path` from the client
    """
    length_value = await get_value(ctx, ARRAY_LENGTH_TYPE, member_path)
    return int.from_bytes(length_value, "big")


async def get_value(
    ctx: Context,
    field: EthereumFieldType,
    member_value_path: list,
) -> bytes:
    """
    Gets a single value from the client and performs its validation
    """
    req = EthereumTypedDataValueRequest(
        member_path=member_value_path,
    )
    res = await ctx.call(req, EthereumTypedDataValueAck)
    value = res.value

    validate_value(field=field, value=value)

    return value
