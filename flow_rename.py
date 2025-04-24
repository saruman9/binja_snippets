# Rename the (global) variable to name associated with function's parameter, variable assignation
# Shift+N
import re
import typing
from typing import Any

from binaryninja.enums import MessageBoxIcon, SymbolType, TypeClass
from binaryninja.exceptions import ILException
from binaryninja.function import Function
from binaryninja.highlevelil import (
    HighLevelILAssign,
    HighLevelILCall,
    HighLevelILConstPtr,
    HighLevelILFunction,
    HighLevelILInstruction,
    HighLevelILTailcall,
    HighLevelILVar,
    HighLevelILVarInit,
)
from binaryninja.interaction import show_message_box
from binaryninja.log import log_alert, log_debug, log_error
from binaryninja.types import Symbol
from binaryninja.variable import CoreVariable, Variable
from binaryninjaui import HighlightTokenState, UIContext  # type: ignore[import-untyped]

if typing.TYPE_CHECKING:
    from binaryninja.binaryview import BinaryView
    from binaryninja.function import Function
    from binaryninja.highlevelil import HighLevelILFunction

    bv: BinaryView | Any = None
    here: int = 0
    current_hlil: HighLevelILFunction | Any = None
    current_function: Function | Any = None
    current_ui_context: UIContext | Any = None

# FIXME: Snippet plugin doesn't have global `current_ui_token_state`
current_ui_token_state: HighlightTokenState = (
    current_ui_context.getCurrentView().getHighlightTokenState()
)


def get_struct_type(ty):
    if ty.type_class == TypeClass.PointerTypeClass:
        return get_struct_type(ty.target)
    elif ty.type_class == TypeClass.NamedTypeReferenceClass:
        return get_struct_type(ty.target(bv))
    elif ty.type_class == TypeClass.StructureTypeClass:
        return ty
    else:
        msg = f"Can't change the variable.\ntyp: {ty!r}"
        show_message_box(
            "Error",
            msg,
            icon=MessageBoxIcon.ErrorIcon,
        )
        log_error(msg)
        exit()


def get_field_name(var, offset):
    ty = var.type
    ty = get_struct_type(ty)
    return ty.member_at_offset(offset).name


def camel_to_snake(s: str) -> str:
    if s.lower() == s:
        return s

    snake_case = re.sub(r"(?<!^)(?=[A-Z])", "_", s).lower()
    return snake_case


def format_name(input: str) -> str:
    if input.startswith("get"):
        input = input.removeprefix("get")
    if input.startswith("g_"):
        input = input.removeprefix("g_")
    input = camel_to_snake(input)
    return input


def find_name(instruction: HighLevelILInstruction) -> str | bool | None:
    log_debug(
        f"{find_name.__name__}: {instruction} ({type(instruction)}) at {instruction.address:#x}"
    )
    match instruction:
        case HighLevelILConstPtr(constant=address):
            symbol = bv.get_symbol_at(address)
            if symbol is None:
                log_error(f"Can't get symbol at {address:#x}")
                return False
            return symbol.name
        case HighLevelILVar(var=var):
            return var.name
    return None


def find_variable(
    instruction: HighLevelILInstruction, core_var: CoreVariable
) -> Variable | None:
    log_debug(
        f"{find_variable.__name__}: {instruction} ({type(instruction)}) at {instruction.address:#x}"
    )
    match instruction:
        case HighLevelILVar(var=var):
            if var.core_variable == core_var:
                return var
    return None


def find_global(instruction: HighLevelILInstruction) -> int | None:
    log_debug(
        f"{find_global.__name__}: {instruction} ({type(instruction)}) at {instruction.address:#x}"
    )
    match instruction:
        case HighLevelILConstPtr(constant=address):
            return address
    return None


def find_param(instruction: HighLevelILInstruction, param_id: int) -> Variable | None:
    log_debug(
        f"{find_param.__name__}: {instruction} ({type(instruction)}) at {instruction.address:#x}"
    )
    match instruction:
        case HighLevelILConstPtr(constant=address):
            function = bv.get_function_at(address)
            if function is None:
                log_alert(f"Can't find function at {address:#x}")
                return None
            return function.parameter_vars.vars[param_id]
    return None


def rename_variable_without_collisions(variable: Variable, name: str, index: int = 1):
    function_vars = variable.function.vars
    for local_var in function_vars:
        if local_var.name == name:
            rename_variable_without_collisions(variable, f"{name}_{index}", index + 1)
            return
    variable.name = name


def rename_global_without_collisions(address: int, name: str, index: int = 1):
    while bv.get_symbols_by_name(name):
        rename_global_without_collisions(address, f"{name}_{index}", index + 1)
        return
    symbol = Symbol(SymbolType.DataSymbol, address, name)
    bv.define_user_symbol(symbol)


def set_name(
    instruction: HighLevelILInstruction, core_var: CoreVariable
) -> bool | None:
    log_debug(
        f"{set_name.__name__}: {instruction} ({type(instruction)}) at {instruction.address:#x}"
    )
    match instruction:
        case (
            HighLevelILCall(dest=dest, params=params)
            | HighLevelILTailcall(dest=dest, params=params)
        ):
            param_id: int | None = None
            target_var: Variable | None = None
            for i, param in enumerate(params):
                for var in param.traverse(find_variable, core_var):
                    target_var = var
                    param_id = i
                    break
                else:
                    continue
                break
            if target_var is None:
                log_alert("Can't find variable")
                return False
            target_param: Variable = next(dest.traverse(find_param, param_id))
            rename_variable_without_collisions(target_var, target_param.name)
            return True
        case HighLevelILVarInit(dest=target_var, src=src_instruction):
            name = next(src_instruction.traverse(find_name))  # type: ignore[arg-type]
            if not name:
                return False
            rename_variable_without_collisions(target_var, format_name(name))
            return True
        case HighLevelILAssign(dest=target_instruction, src=src_instruction):
            name = next(src_instruction.traverse(find_name))  # type: ignore[arg-type]
            if not name:
                return False
            if isinstance(target_instruction, HighLevelILVar):
                rename_variable_without_collisions(
                    target_instruction.var, format_name(name)
                )
            target_address = next(target_instruction.traverse(find_global))  # type: ignore[arg-type]
            rename_global_without_collisions(target_address, f"g_{format_name(name)}")
            return True
    return None


def process():
    if current_function is None:
        log_alert("Place the cursor inside a function")
        return
    try:
        here_llil = current_function.get_llil_at(here)
    except ILException:
        log_alert(f"Can't get LLIL at {here:#x}")
        return
    here_hlil = here_llil.hlil
    if here_hlil is None:
        log_alert(f"Can't get HLIL at {here:#x}")
        return
    if current_ui_token_state is None:
        log_alert("Set the cursor on the target token")
        return
    local_var = current_ui_token_state.localVar
    if local_var is None:
        log_alert("Set the cursor on the variable")
        return
    next(here_hlil.traverse(set_name, local_var))
    return


process()
