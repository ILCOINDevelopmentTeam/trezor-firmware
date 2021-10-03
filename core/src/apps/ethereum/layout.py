from ubinascii import hexlify

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
from trezor.ui.components.tt.scroll import Paginated
from trezor.ui.components.tt.text import Text
from trezor.utils import chunks

from apps.common.confirm import confirm, require_confirm, require_hold_to_confirm

from . import networks, tokens
from .address import address_from_bytes


async def confirm_typed_domain_brief(ctx, domain_values: dict):
    page = Text("Typed Data", ui.ICON_SEND, icon_color=ui.GREEN)

    domain_name = domain_values.get("name")
    domain_version = domain_values.get("version")

    page.bold("Name: %s" % domain_name)
    page.normal("Version: %s" % domain_version)
    page.br()
    page.mono("View EIP712Domain?")

    return await confirm(ctx, page, ButtonRequestType.Other)


async def require_confirm_typed_domain(ctx, domain_types: dict, domain_values: dict):
    def make_field_page(title, field_name, type_name, field_value):
        page = Text(title, ui.ICON_CONFIG, icon_color=ui.ORANGE_ICON)
        page.bold("%s (%s)" % (field_name, type_name))
        page.mono(*split_data("{}".format(field_value), 17))
        return page

    pages = []
    for type_def in domain_types:
        value = domain_values.get(type_def["name"])
        pages.append(
            make_field_page(
                title="EIP712Domain %d/%d" % (len(pages) + 1, len(domain_types)),
                field_name=limit_str(type_def["name"]),
                type_name=limit_str(type_def["type_name"]),
                field_value=value,
            )
        )

    return await require_hold_to_confirm(
        ctx, Paginated(pages), ButtonRequestType.ConfirmOutput
    )


TYPED_DATA_BRIEF_FIELDS = 3


async def confirm_typed_data_brief(ctx, primary_type: str, fields: list):
    page = Text(primary_type, ui.ICON_SEND, icon_color=ui.GREEN)

    limit = TYPED_DATA_BRIEF_FIELDS
    for field in fields:
        page.bold("%s" % limit_str(field["name"]))
        limit -= 1
        if limit == 0:
            break

    printed_num = TYPED_DATA_BRIEF_FIELDS - limit
    if printed_num < len(fields):
        page.mono("...and %d more." % (len(fields) - printed_num))

    page.mono("View full message?")

    return await confirm(ctx, page, ButtonRequestType.Other)


async def require_confirm_typed_data(
    ctx, primary_type: str, data_types: dict, data_values: dict
):
    def make_type_page(
        root_name, field_name, current_array_offsets, current_field, total_fields
    ):
        array_offsets = ""
        for offset in current_array_offsets:
            array_offsets += "%d." % offset

        if len(array_offsets) > 0:
            title = limit_str("%s.%s%s" % (root_name, array_offsets, field_name), 13)
        else:
            title = limit_str("%s.%s" % (root_name, field_name), 13)

        if len(array_offsets) == 0:
            title += " %d/%d" % (current_field + 1, total_fields)

        return Text(title, ui.ICON_CONFIG, icon_color=ui.ORANGE_ICON)

    async def confirm_struct(
        root_name, type_name: str, values: dict, array_offsets: list, hold: bool = False
    ):
        current_type = type_name
        current_root_name = root_name
        type_def = data_types[current_type]

        type_view_pages = []

        for (field_idx, field) in enumerate(type_def):
            current_type = field["type_name"]
            current_value = values.get(field["name"])

            if field["data_type"] == EthereumDataType.ARRAY:
                array_preview_page = make_type_page(
                    root_name=current_root_name,
                    field_name=field["name"],
                    current_array_offsets=array_offsets,
                    current_field=field_idx,
                    total_fields=len(type_def),
                )

                array_view_page = make_type_page(
                    root_name=current_root_name,
                    field_name=field["name"],
                    current_array_offsets=array_offsets,
                    current_field=field_idx,
                    total_fields=len(type_def),
                )

                array_len = len(current_value)
                array_preview_page.bold(limit_str(field["type_name"]))
                array_preview_page.mono(
                    "Contains %d elem%s." % (array_len, "s" if array_len > 1 else "")
                )
                array_preview_page.br()
                array_preview_page.mono("View data?")

                array_view_page.bold(limit_str(field["type_name"]))
                array_view_page.mono(
                    "Contains %d elem%s." % (array_len, "s" if array_len > 1 else "")
                )
                type_view_pages.append(array_view_page)

                go_deeper = await confirm(
                    ctx, array_preview_page, ButtonRequestType.ConfirmOutput
                )
                if go_deeper:
                    for array_offset in range(len(current_value)):
                        await confirm_struct(
                            root_name=field["name"],
                            type_name=field["entry_type"]["data_type"],
                            values=current_value[array_offset],
                            array_offsets=array_offsets + [array_offset],
                            hold=False,
                        )
                        continue

                continue

            type_view_page = make_type_page(
                root_name=current_root_name,
                field_name=field["name"],
                current_array_offsets=array_offsets,
                current_field=field_idx,
                total_fields=len(type_def),
            )
            if current_type in data_types:
                type_preview_page = make_type_page(
                    root_name=current_root_name,
                    field_name=field["name"],
                    current_array_offsets=array_offsets,
                    current_field=field_idx,
                    total_fields=len(type_def),
                )

                fields_num = len(data_types[current_type])
                type_preview_page.bold(limit_str(current_type))
                type_preview_page.mono(
                    "Contains %d field%s." % (fields_num, "s" if fields_num > 1 else "")
                )
                type_preview_page.br()
                type_preview_page.mono("View data?")

                type_view_page.bold(limit_str(current_type))
                type_view_page.mono(
                    "Contains %d field%s." % (fields_num, "s" if fields_num > 1 else "")
                )
                type_view_pages.append(type_view_page)

                go_deeper = await confirm(
                    ctx, type_preview_page, ButtonRequestType.ConfirmOutput
                )
                if go_deeper:
                    await confirm_struct(
                        root_name=field["name"],
                        type_name=current_type,
                        values=current_value,
                        array_offsets=[],
                        hold=False,
                    )

            else:
                type_view_page.bold(current_type)
                type_view_page.mono(*split_data(current_value, 17))
                type_view_pages.append(type_view_page)

        if hold:
            return await require_hold_to_confirm(
                ctx,
                Paginated(type_view_pages)
                if len(type_view_pages) > 1
                else type_view_pages[0],
                ButtonRequestType.ConfirmOutput,
            )
        return await require_confirm(
            ctx,
            Paginated(type_view_pages)
            if len(type_view_pages) > 1
            else type_view_pages[0],
            ButtonRequestType.ConfirmOutput,
        )

    await confirm_struct(
        root_name=primary_type,
        type_name=primary_type,
        values=data_values,
        array_offsets=[],
        hold=True,
    )


async def require_confirm_typed_data_hash(
    ctx, primary_type: str, typed_data_hash: bytes
):
    text = Text(
        "Sign typed data?", ui.ICON_CONFIG, icon_color=ui.GREEN, new_lines=False
    )
    text.bold(limit_str(primary_type))
    text.mono(*split_data("0x%s" % hexlify(typed_data_hash).decode()))

    return await require_hold_to_confirm(ctx, text, ButtonRequestType.ConfirmOutput)


if False:
    from typing import Awaitable

    from trezor.wire import Context


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
