from trezor.crypto.curve import secp256k1
from trezor.enums import EthereumDataType
from trezor.messages import (
    EthereumSignTypedData,
    EthereumTypedDataSignature,
    EthereumTypedDataStructAck,
    EthereumTypedDataStructRequest,
)

from apps.common import paths

from . import address
from .keychain import PATTERNS_ADDRESS, with_keychain_from_path
from .typed_data import (
    StructHasher,
    confirm_hash,
    keccak256,
    should_we_show_domain,
    should_we_show_struct,
    validate_field_type,
)

if False:
    from typing import Dict
    from apps.common.keychain import Keychain
    from trezor.wire import Context


# TODO: mypy issue below: Value of type variable "MsgIn" of function cannot be "EthereumSignTypedData"  [type-var]
@with_keychain_from_path(*PATTERNS_ADDRESS)  # type: ignore
async def sign_typed_data(
    ctx: Context, msg: EthereumSignTypedData, keychain: Keychain
) -> EthereumTypedDataSignature:
    await paths.validate_path(ctx, keychain, msg.address_n)

    data_hash = await generate_typed_data_hash(
        ctx, msg.primary_type, msg.metamask_v4_compat
    )

    node = keychain.derive(msg.address_n)
    signature = secp256k1.sign(
        node.private_key(), data_hash, False, secp256k1.CANONICAL_SIG_ETHEREUM
    )

    return EthereumTypedDataSignature(
        address=address.address_from_bytes(node.ethereum_pubkeyhash()),
        signature=signature[1:] + signature[0:1],
    )


async def generate_typed_data_hash(
    ctx: Context, primary_type: str, metamask_v4_compat: bool = True
) -> bytes:
    """
    Generates typed data hash according to EIP-712 specification
    https://eips.ethereum.org/EIPS/eip-712#specification

    metamask_v4_compat - a flag that enables compatibility with MetaMask's signTypedData_v4 method
    """
    types: Dict[str, EthereumTypedDataStructAck] = {}
    await collect_types(ctx, "EIP712Domain", types)
    await collect_types(ctx, primary_type, types)

    struct_hasher = StructHasher(
        ctx=ctx,
        types=types,
        metamask_v4_compat=metamask_v4_compat,
    )

    show_domain = await should_we_show_domain(ctx, types["EIP712Domain"].members)
    domain_separator = await struct_hasher.hash_struct(
        primary_type="EIP712Domain",
        member_path=[0],
        show_data=show_domain,
        parent_objects=[],
    )

    show_message = await should_we_show_struct(
        ctx, primary_type, ["data"], types[primary_type].members
    )
    message_hash = await struct_hasher.hash_struct(
        primary_type=primary_type,
        member_path=[1],
        show_data=show_message,
        parent_objects=[primary_type],
    )

    await confirm_hash(ctx, primary_type, message_hash)

    return keccak256(b"\x19" + b"\x01" + domain_separator + message_hash)


async def collect_types(
    ctx: Context, type_name: str, types: Dict[str, EthereumTypedDataStructAck]
) -> None:
    """
    Recursively collects types from the client
    """
    req = EthereumTypedDataStructRequest(name=type_name)
    current_type = await ctx.call(req, EthereumTypedDataStructAck)
    types[type_name] = current_type
    for member in current_type.members:
        validate_field_type(member.type)
        if (
            member.type.data_type == EthereumDataType.STRUCT
            and member.type.struct_name not in types
        ):
            assert member.type.struct_name is not None  # validate_field_type
            await collect_types(ctx, member.type.struct_name, types)
