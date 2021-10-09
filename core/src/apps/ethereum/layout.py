from ubinascii import hexlify

if False:
    from typing import Awaitable
    from trezor.wire import Context

from trezor import ui
from trezor.enums import ButtonRequestType, EthereumDataType
from trezor.strings import format_amount
from trezor.ui.layouts import (
    confirm_address,
    confirm_amount,
    confirm_blob,
    confirm_output,
)
from trezor.ui.layouts.tt.altcoin import confirm_total_ethereum

# DO NOT use anything from trezor.ui.components (use trezor.ui.layouts)
# Try to do it with layouts (confirm_properties function)
from trezor.ui.components.tt.scroll import Paginated
from trezor.ui.components.tt.text import Text
from trezor.utils import chunks

from apps.common.confirm import confirm, require_confirm, require_hold_to_confirm

from . import networks, tokens
from .address import address_from_bytes
from .typed_data import get_type_name, decode_data


async def confirm_typed_domain_brief(ctx: Context, domain_values: dict) -> bool:
    page = Text("Typed Data", ui.ICON_SEND, icon_color=ui.GREEN)

    domain_name = decode_data(domain_values.get("name"), "string")
    domain_version = decode_data(domain_values.get("version"), "string")

    page.bold("Name: {}".format(domain_name))
    page.normal("Version: {}".format(domain_version))
    page.br()
    page.mono("View EIP712Domain?")

    return await confirm(ctx, page, ButtonRequestType.Other)


async def require_confirm_typed_domain(
    ctx: Context, domain_types: dict, domain_values: dict
) -> Awaitable[None]:
    def make_field_page(
        title: str, field_name: str, type_name: str, field_value: str
    ) -> Text:
        page = Text(title, ui.ICON_CONFIG, icon_color=ui.ORANGE_ICON)
        page.bold("{} ({})".format(field_name, type_name))
        page.mono(*split_data(field_value, 17))
        return page

    pages = []
    domain_type_members = domain_types.members
    for member in domain_type_members:
        field_name = member.name
        field_type = get_type_name(member.type)
        value = domain_values[field_name]
        pages.append(
            make_field_page(
                title="EIP712Domain {}/{}".format(
                    len(pages) + 1, len(domain_type_members)
                ),
                field_name=limit_str(field_name),
                type_name=limit_str(field_type),
                field_value=decode_data(value, field_type),
            )
        )

    return await require_hold_to_confirm(
        ctx, Paginated(pages), ButtonRequestType.ConfirmOutput
    )


async def confirm_typed_data_brief(
    ctx: Context, primary_type: str, fields: list
) -> bool:
    page = Text(primary_type, ui.ICON_SEND, icon_color=ui.GREEN)

    # We have limited screen space, so showing only a preview when having lot of fields
    MAX_FIELDS_TO_SHOW = 3
    fields_amount = len(fields)
    if fields_amount > MAX_FIELDS_TO_SHOW:
        for field in fields[:MAX_FIELDS_TO_SHOW]:
            page.bold(limit_str(field.name))
        page.mono("...and {} more.".format(fields_amount - MAX_FIELDS_TO_SHOW))
    else:
        for field in fields:
            page.bold(limit_str(field.name))

    page.mono("View full message?")

    return await confirm(ctx, page, ButtonRequestType.Other)


async def require_confirm_typed_data(
    ctx: Context, primary_type: str, data_types: dict, data_values: dict
) -> None:
    # TODO: consider this function not taking any arguments and taking
    # the values from the parent function local variables
    # (As we call it many times with the same arguments)
    # (It would need to be moved into confirm_data probably)
    def create_title_with_type_info(
        root_name: str,
        field_name: str,
        field_idx: int,
        fields_amount: int,
    ) -> Text:
        """Generates a title for a page showing the type tree of current value

        For example "Mail.from 1/3", meaning "from" property of "Mail"
        struct, which is the first of its three properties
        """
        title = limit_str("{}.{}".format(root_name, field_name), 13)
        title += " {}/{}".format(field_idx + 1, fields_amount)

        return Text(title, ui.ICON_CONFIG, icon_color=ui.ORANGE_ICON)

    async def confirm_data(
        root_name: str,
        type_members: list,
        data_values,
        require_hold: bool = False,
    ) -> Awaitable[None]:
        fields_amount = len(type_members)
        print("type_members", type_members)

        type_view_pages = []

        for field_idx, member in enumerate(type_members):
            field_name = member.name
            # TODO: it could be made general for both dicts and lists
            if isinstance(data_values, dict):
                type_name = get_type_name(member.type)
                data_type = member.type.data_type
                current_value = data_values[field_name]
            elif isinstance(data_values, list):
                # TODO: support also nested arrays, this works only for one level
                type_name = get_type_name(member.type.entry_type)
                data_type = member.type.entry_type.data_type
                current_value = data_values[field_idx]
            else:
                raise ValueError  # Values can be only dict or list

            # There can be either array, struct or atomic data type
            if data_type == EthereumDataType.ARRAY:
                array_len = len(current_value)
                array_details = "Contains {} elem{}".format(
                    array_len, "s" if array_len > 1 else ""
                )

                # Creating and showing a preview page and potentially going deeper into this array
                array_preview_page = create_title_with_type_info(
                    root_name=root_name,
                    field_name=field_name,
                    field_idx=field_idx,
                    fields_amount=fields_amount,
                )
                array_preview_page.bold(limit_str(type_name))
                array_preview_page.mono(array_details)
                array_preview_page.br()
                array_preview_page.mono("View array data?")
                go_deeper = await confirm(
                    ctx, array_preview_page, ButtonRequestType.ConfirmOutput
                )
                if go_deeper:
                    # We need to create a list of type definitions, where they are all the same
                    type_members = [member] * array_len
                    await confirm_data(
                        root_name=root_name,
                        type_members=type_members,
                        data_values=current_value,
                        require_hold=False,
                    )

                # Adding a single view page displaying summary of this array
                array_view_page = create_title_with_type_info(
                    root_name=root_name,
                    field_name=field_name,
                    field_idx=field_idx,
                    fields_amount=fields_amount,
                )
                array_view_page.bold(limit_str(type_name))
                array_view_page.mono(array_details)
                type_view_pages.append(array_view_page)
            elif data_type == EthereumDataType.STRUCT:
                fields_num = len(current_value)
                struct_details = "Contains {} field{}".format(
                    fields_num, "s" if fields_num > 1 else ""
                )

                # Creating and showing a preview page and potentially going deeper into this struct
                type_preview_page = create_title_with_type_info(
                    root_name=root_name,
                    field_name=field_name,
                    field_idx=field_idx,
                    fields_amount=fields_amount,
                )
                type_preview_page.bold(limit_str(type_name))
                type_preview_page.mono(struct_details)
                type_preview_page.br()
                type_preview_page.mono("View struct data?")
                go_deeper = await confirm(
                    ctx, type_preview_page, ButtonRequestType.ConfirmOutput
                )
                if go_deeper:
                    await confirm_data(
                        root_name=field_name,
                        type_members=data_types[type_name].members,
                        data_values=current_value,
                        require_hold=False,
                    )

                # Adding a single view page displaying summary of this struct
                type_view_page = create_title_with_type_info(
                    root_name=root_name,
                    field_name=field_name,
                    field_idx=field_idx,
                    fields_amount=fields_amount,
                )
                type_view_page.bold(limit_str(type_name))
                type_view_page.mono(struct_details)
                type_view_pages.append(type_view_page)
            else:
                # Adding a single view page displaying an atomic value
                type_view_page = create_title_with_type_info(
                    root_name=root_name,
                    field_name=field_name,
                    field_idx=field_idx,
                    fields_amount=fields_amount,
                )
                type_view_page.bold(type_name)
                value_decoded = decode_data(current_value, type_name)
                type_view_page.mono(*split_data(value_decoded, 17))
                type_view_pages.append(type_view_page)

        # Choosing whether a hold is necessary (by default only in the first call)
        func_to_call = require_hold_to_confirm if require_hold else require_confirm
        return await func_to_call(
            ctx,
            Paginated(type_view_pages)
            if len(type_view_pages) > 1
            else type_view_pages[0],
            ButtonRequestType.ConfirmOutput,
        )

    await confirm_data(
        root_name=primary_type,
        type_members=data_types[primary_type].members,
        data_values=data_values,
        require_hold=True,
    )


async def require_confirm_typed_data_hash(
    ctx: Context, primary_type: str, typed_data_hash: bytes
):
    text = Text(
        "Sign typed data?", ui.ICON_CONFIG, icon_color=ui.GREEN, new_lines=False
    )
    text.bold(limit_str(primary_type))
    text.mono(*split_data("0x" + hexlify(typed_data_hash).decode()))

    return await require_hold_to_confirm(ctx, text, ButtonRequestType.ConfirmOutput)


def require_confirm_tx(
    ctx: Context,
    to_bytes: bytes,
    value: int,
    chain_id: int,
    token: tokens.TokenInfo | None = None,
) -> Awaitable[None]:
    if to_bytes:
        to_str = address_from_bytes(to_bytes, networks.by_chain_id(chain_id))
    else:
        to_str = "new contract?"
    return confirm_output(
        ctx,
        address=to_str,
        amount=format_ethereum_amount(value, token, chain_id),
        font_amount=ui.BOLD,
        color_to=ui.GREY,
        br_code=ButtonRequestType.SignTx,
    )


def require_confirm_fee(
    ctx: Context,
    spending: int,
    gas_price: int,
    gas_limit: int,
    chain_id: int,
    token: tokens.TokenInfo | None = None,
) -> Awaitable[None]:
    return confirm_total_ethereum(
        ctx,
        format_ethereum_amount(spending, token, chain_id),
        format_ethereum_amount(gas_price, None, chain_id),
        format_ethereum_amount(gas_price * gas_limit, None, chain_id),
    )


async def require_confirm_eip1559_fee(
    ctx: Context, max_priority_fee: int, max_gas_fee: int, gas_limit: int, chain_id: int
) -> None:
    await confirm_amount(
        ctx,
        title="Confirm fee",
        description="Maximum fee per gas",
        amount=format_ethereum_amount(max_gas_fee, None, chain_id),
    )
    await confirm_amount(
        ctx,
        title="Confirm fee",
        description="Priority fee per gas",
        amount=format_ethereum_amount(max_priority_fee, None, chain_id),
    )
    await confirm_amount(
        ctx,
        title="Confirm fee",
        description="Maximum fee",
        amount=format_ethereum_amount(max_gas_fee * gas_limit, None, chain_id),
    )


def require_confirm_unknown_token(
    ctx: Context, address_bytes: bytes
) -> Awaitable[None]:
    contract_address_hex = "0x" + hexlify(address_bytes).decode()
    return confirm_address(
        ctx,
        "Unknown token",
        contract_address_hex,
        description="Contract:",
        br_type="unknown_token",
        icon_color=ui.ORANGE,
        br_code=ButtonRequestType.SignTx,
    )


def require_confirm_data(ctx: Context, data: bytes, data_total: int) -> Awaitable[None]:
    return confirm_blob(
        ctx,
        "confirm_data",
        title="Confirm data",
        description=f"Size: {data_total} bytes",
        data=data,
        br_code=ButtonRequestType.SignTx,
    )


def format_ethereum_amount(
    value: int, token: tokens.TokenInfo | None, chain_id: int
) -> str:
    if token:
        suffix = token.symbol
        decimals = token.decimals
    else:
        suffix = networks.shortcut_by_chain_id(chain_id)
        decimals = 18

    # Don't want to display wei values for tokens with small decimal numbers
    if decimals > 9 and value < 10 ** (decimals - 9):
        suffix = "Wei " + suffix
        decimals = 0

    return f"{format_amount(value, decimals)} {suffix}"


def split_data(data, width: int = 18):
    return chunks(data, width)


def limit_str(s: str, limit: int = 16) -> str:
    if len(s) <= limit + 2:
        return s

    return s[:limit] + ".."
