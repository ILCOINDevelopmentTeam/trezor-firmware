if False:
    from typing import Dict

from trezor.crypto.curve import secp256k1
from trezor.messages import EthereumTypedDataValueAck
from trezor.messages import EthereumTypedDataValueRequest
from trezor.messages import EthereumTypedDataSignature
from trezor.messages import EthereumTypedDataStructAck
from trezor.messages import EthereumTypedDataStructRequest
from trezor.enums import EthereumDataType

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
from .typed_data import (
    hash_struct,
    keccak256,
    validate_field,
)


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
            # Getting the length of the array first
            res = await request_member_value(ctx, member_value_path)
            array_size = int.from_bytes(res.value, "big")
            entry_type = member.type.entry_type.data_type
            arr = []
            for i in range(array_size):
                # Differentiating between structs and everything else
                # (arrays of arrays are not supported)
                if entry_type == EthereumDataType.STRUCT:
                    struct_name = member.type.entry_type.struct_name
                    struct_value = await collect_values(
                        ctx, struct_name, types, member_value_path + [i]
                    )
                    arr.append(struct_value)
                else:
                    res = await request_member_value(ctx, member_value_path + [i])
                    validate_field(
                        field=member.type.entry_type,
                        field_name=field_name,
                        value=res.value
                    )
                    arr.append(res.value)
            values[field_name] = arr
        else:
            res = await request_member_value(ctx, member_value_path)
            validate_field(
                field=member.type,
                field_name=field_name,
                value=res.value
            )
            values[field_name] = res.value

    return values


async def request_member_value(ctx, member_path: list) -> EthereumTypedDataValueAck:
    """
    Requests a value of member at `member_path` from the client
    """
    req = EthereumTypedDataValueRequest(
        member_path=member_path,
    )
    return await ctx.call(req, EthereumTypedDataValueAck)
