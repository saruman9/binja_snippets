# Replace types in a function (arguments, return)

import typing

from binaryninja.binaryview import BinaryView
from binaryninja.interaction import (
    TextLineField,
    ChoiceField,
    get_form_input,
)
from binaryninja.log import log_info, log_warn
from binaryninja.types import PointerBuilder, Type

if typing.TYPE_CHECKING:
    bv: BinaryView | None = None


def get_pointer_base_type() -> Type | None:
    pass


def process():
    if bv is None or bv.arch is None:
        return
    search_type_field = TextLineField("Search type")
    replace_type_field = TextLineField("Replace type")
    option = ChoiceField("Replace option", ["typedef -> ptr", "typedef -> struct/enum"])
    if not get_form_input(
        [search_type_field, replace_type_field, option], "Change type"
    ):
        return
    search_type_str = search_type_field.result
    replace_type_str = replace_type_field.result
    if search_type_str is None or replace_type_str is None:
        return
    match option.result:
        case 0:
            base_replace_type = bv.get_type_by_name(replace_type_str)
            if base_replace_type is None:
                log_warn(f"can't find {replace_type_str} type")
                return
            replace_type = PointerBuilder.pointer(bv.arch, base_replace_type)
        case 1:
            replace_type = bv.get_type_by_name(replace_type_str)
            if replace_type is None:
                log_warn(f"can't find {replace_type_str} type")
                return
        case _:
            return
    log_info(f"search type str: {search_type_str}")
    log_info(f"replace type: {replace_type}")
    for function in bv.functions:
        changed = False
        old_function = str(function)
        return_type = function.return_type
        try:
            if return_type is not None and return_type.name == search_type_str:
                function.return_type = replace_type
                # FIXME: API didn't run `update_analysis_and_wait` after setter
                bv.update_analysis_and_wait()
                changed = True
        except NotImplementedError:
            pass
        for argument in function.parameter_vars:
            try:
                if argument.type is not None and argument.type.name == search_type_str:
                    argument.type = replace_type  # pyright: ignore[reportAttributeAccessIssue]
                    changed = True
            except NotImplementedError:
                pass
        if changed:
            log_info(f"{function.start:08x} : {old_function} ->")
            # function.reanalyze()
            log_info(f"{'':<11}{function}")


process()
