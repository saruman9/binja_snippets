# Rename the variable to name associated with function's parameter
#Shift+N
import typing
from typing import Any

from binaryninja.highlevelil import (
    HighLevelILInstruction,
    HighLevelILFunction,
    HighLevelILCall,
    HighLevelILTailcall,
    HighLevelILVar,
    HighLevelILConstPtr,
)
from binaryninja.function import Function
from binaryninja.interaction import show_message_box
from binaryninja.enums import MessageBoxIcon, TypeClass
from binaryninja.log import log_error, log_alert, log_debug
from binaryninja.exceptions import ILException
from binaryninja.variable import CoreVariable, Variable
from binaryninjaui import HighlightTokenState, UIContext

if typing.TYPE_CHECKING:
    from binaryninja.binaryview import BinaryView
    from binaryninja.highlevelil import HighLevelILFunction
    from binaryninja.function import Function

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
        case _:
            return None
    return None


def find_param(instruction: HighLevelILInstruction, param_id: int) -> Variable | None:
    log_debug(
        f"{find_param.__name__}: {instruction} ({type(instruction)}) at {instruction.address:#x}"
    )
    match instruction:
        case HighLevelILConstPtr(constant=address):
            function = bv.get_function_at(address)
            if not function:
                log_alert(f"Can't find function at {address:#x}")
                return None
            return function.parameter_vars.vars[param_id]
    return None


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
                    if not var:
                        continue
                    target_var = var
                    param_id = i
                    break
                else:
                    continue
                break
            if not target_var:
                log_error("Can't find variable")
                return False
            target_param: Variable = next(dest.traverse(find_param, param_id))
            target_var.name = target_param.name
            return True
    return None


def process():
    if not current_function:
        log_alert("Place the cursor inside a function")
        return
    try:
        here_llil = current_function.get_llil_at(here)
    except ILException:
        log_alert(f"Can't get LLIL at {here:#x}")
        return
    here_hlil = here_llil.hlil
    if not here_hlil:
        log_alert(f"Can't get HLIL at {here:#x}")
        return
    if not current_ui_token_state:
        log_alert("Set the cursor on the target token")
        return
    local_var = current_ui_token_state.localVar
    if not local_var:
        log_alert("Set the cursor on the variable")
        return
    if not next(here_hlil.traverse(set_name, local_var)):
        log_alert("Can't find name")
    return


process()
