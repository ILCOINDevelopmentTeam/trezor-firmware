from trezor.crypto.curve import secp256k1
from trezor.messages import EthereumSignTypedData, EthereumTypedDataSignature

from apps.common import paths

from . import address
from .keychain import PATTERNS_ADDRESS, with_keychain_from_path
from .typed_data import (
    TypedDataEnvelope,
    confirm_hash,
    keccak256,
    should_show_domain,
    should_show_struct,
)

if False:
    from apps.common.keychain import Keychain
    from trezor.wire import Context


@with_keychain_from_path(*PATTERNS_ADDRESS)
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
    Generate typed data hash according to EIP-712 specification
    https://eips.ethereum.org/EIPS/eip-712#specification

    metamask_v4_compat - a flag that enables compatibility with MetaMask's signTypedData_v4 method
    """
    typed_data_envelope = TypedDataEnvelope(
        ctx=ctx,
        primary_type=primary_type,
        metamask_v4_compat=metamask_v4_compat,
    )
    await typed_data_envelope.collect_types()

    show_domain = await should_show_domain(ctx, typed_data_envelope)
    domain_separator = await typed_data_envelope.hash_struct(
        primary_type="EIP712Domain",
        member_path=[0],
        show_data=show_domain,
        parent_objects=[],
    )

    show_message = await should_show_struct(
        ctx, primary_type, ["data"], typed_data_envelope
    )
    message_hash = await typed_data_envelope.hash_struct(
        primary_type=primary_type,
        member_path=[1],
        show_data=show_message,
        parent_objects=[primary_type],
    )

    await confirm_hash(ctx, primary_type, message_hash)

    return keccak256(b"\x19" + b"\x01" + domain_separator + message_hash)
