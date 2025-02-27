# Rename the function to name, getting from string from parameter
#
import typing
from typing import Any

from binaryninja.exceptions import ILException
from binaryninja.function import Function
from binaryninja.highlevelil import (
    HighLevelILAssign,
    HighLevelILAssignUnpack,
    HighLevelILCall,
    HighLevelILConstPtr,
    HighLevelILInstruction,
    HighLevelILRet,
    HighLevelILTailcall,
    HighLevelILVar,
    HighLevelILVarInit,
)
from binaryninja.interaction import get_choice_input
from binaryninja.log import log_alert, log_debug, log_warn
from binaryninja.variable import Variable

if typing.TYPE_CHECKING:
    from binaryninja.binaryview import BinaryView

    bv: BinaryView | Any = None
    current_function: Function | Any = None


def find_name(instruction: HighLevelILInstruction, index: int) -> str | Variable | None:
    log_debug(f"inst: {instruction} ({type(instruction)}) at {instruction.address:#x}")
    match instruction:
        case HighLevelILCall() | HighLevelILTailcall():
            param: HighLevelILInstruction = instruction.params[index]
            log_debug(f"param: {param} ({type(param)}) at {param.address:#x}")
            match param:
                case HighLevelILConstPtr(string=string):
                    return None if string is None else string[0]
                case HighLevelILVar(var=var):
                    log_warn(
                        f"Found variable `{var}` ({type(var)}) at {param.address:#x}"
                    )
                    return var
                case _:
                    log_warn(
                        f"Unknown parameter `{param}` ({type(param)}) at {param.address:#x}"
                    )
        case (
            HighLevelILVarInit()
            | HighLevelILAssignUnpack()
            | HighLevelILVar()
            | HighLevelILAssign()
            | HighLevelILRet()
        ):
            return None
        case _:
            log_warn(
                f"Unknown instruction `{instruction}` ({type(instruction)}) at {instruction.address:#x}"
            )
    return None


def process() -> None:
    if current_function is None:
        log_alert("Place the cursor inside the target function")
        return
    parameter_id = get_choice_input(
        "Argument that contains the function name:",
        "Arguments",
        [f"{p.type} {p.name}" for p in current_function.parameter_vars],
    )
    if parameter_id is None:
        return

    names: dict[Function, set[str]] = {}
    for ref in current_function.caller_sites:
        try:
            if ref.hlil is None:
                log_warn(f"Can't find HLIL at {ref.address:#x}")
                continue
        except ILException:
            log_warn(f"Can't get LLIL at {ref.address:#x}")
            continue
        function = ref.function
        if function is None:
            log_warn(f"Can't find function at {ref.address:#x}")
            continue
        if not function.symbol.auto:
            log_debug(f"skip: {function.name} ({function.lowest_address:#x})")
            continue
        name = next(ref.hlil.traverse(find_name, parameter_id))
        if isinstance(name, Variable):
            continue
        if function in names:
            names[function].add(name)
        else:
            names[function] = {name}

    for function in names:
        variants = names[function]
        if len(variants) > 1:
            log_warn(
                f"Multiple names for {function.name} ({function.lowest_address:#x}): {variants}"
            )
        else:
            function.name = variants.pop()


process()
