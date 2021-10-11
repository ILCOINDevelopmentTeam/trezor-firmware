if False:
    from typing import Dict

from ubinascii import hexlify

from trezor import wire
from trezor.enums import EthereumDataType
from trezor.messages import EthereumFieldType
from trezor.messages import EthereumTypedDataStructAck

from trezor.utils import HashWriter
from trezor.crypto.hashlib import sha3_256

from .address import address_from_bytes


def get_hash_writer() -> HashWriter:
    return HashWriter(sha3_256(keccak=True))


def keccak256(message: bytes) -> bytes:
    h = get_hash_writer()
    h.extend(message)
    return h.get_digest()


def hash_struct(
    primary_type: str,
    data: dict,
    types: Dict[str, EthereumTypedDataStructAck],
    metamask_v4_compat: bool = True,
) -> bytes:
    """
    Encodes and hashes an object using Keccak256
    """
    w = get_hash_writer()
    hash_type(w, primary_type, types)
    encode_data(w, primary_type, data, types, metamask_v4_compat)
    return w.get_digest()


def encode_data(
    w: HashWriter,
    primary_type: str,
    data: dict,
    types: Dict[str, EthereumTypedDataStructAck],
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
    for member in type_members:
        encode_field(
            w=w,
            field=member.type,
            value=data[member.name],
            types=types,
            in_array=False,
            metamask_v4_compat=metamask_v4_compat,
        )


def encode_field(
    w: HashWriter,
    field: EthereumFieldType,
    value: bytes,
    types: Dict[str, EthereumTypedDataStructAck],
    in_array: bool,
    metamask_v4_compat: bool,
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

    # Arrays and structs need special recursive handling
    if data_type == EthereumDataType.ARRAY:
        arr_w = get_hash_writer()
        for element in value:
            encode_field(
                w=arr_w,
                field=field.entry_type,
                value=element,
                types=types,
                in_array=True,
                metamask_v4_compat=metamask_v4_compat,
            )
        w.extend(arr_w.get_digest())
    elif data_type == EthereumDataType.STRUCT:
        # Metamask V4 implementation has a bug, that causes the
        # behavior of structs in array be different from SPEC
        # Explanation at https://github.com/MetaMask/eth-sig-util/pull/107
        # encode_data() is the way to process structs in arrays, but
        # Metamask V4 is using hash_struct() even in this case
        if in_array and not metamask_v4_compat:
            encode_data(
                w=w,
                primary_type=field.struct_name,
                data=value,
                types=types,
                metamask_v4_compat=metamask_v4_compat,
            )
        else:
            w.extend(
                hash_struct(
                    primary_type=field.struct_name,
                    data=value,
                    types=types,
                    metamask_v4_compat=metamask_v4_compat,
                )
            )
    elif data_type == EthereumDataType.BYTES:
        # TODO: is not tested
        if field.size is None:
            w.extend(keccak256(value))
        else:
            w.extend(rightpad32(value))
    elif data_type == EthereumDataType.STRING:
        w.extend((keccak256(value)))
    elif data_type in [
        EthereumDataType.UINT,
        EthereumDataType.INT,
        EthereumDataType.BOOL,
        EthereumDataType.ADDRESS,
    ]:
        w.extend(leftpad32(value))
    else:
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


def hash_type(w: HashWriter, primary_type: str, types: Dict[str, EthereumTypedDataStructAck]) -> None:
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
        return get_type_name(entry_type) + "[]"
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
