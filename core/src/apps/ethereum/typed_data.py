from trezor.enums import EthereumDataType
from trezor.messages import EthereumFieldType


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
