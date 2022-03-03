# Set name and type for parameter of the function
#
import itertools
import typing

from binaryninja.highlevelil import (
    HighLevelILFunction,
    HighLevelILInstruction,
    HighLevelILOperation,
)

if typing.TYPE_CHECKING:
    import binaryninja

    bv: binaryninja.BinaryView = None
    here: int = 0
    current_hlil: HighLevelILFunction = None


def change_type_name(operand: HighLevelILInstruction, ty, ty_name):
    operand.var.set_name_and_type_async(ty_name, ty)
    pass


def process_hlil(hlil: HighLevelILInstruction, ty, ty_name, parameter_id):
    operand = hlil.operands[1]
    if (
        not isinstance(operand, typing.List)
        and operand.operation == HighLevelILOperation.HLIL_CALL
    ):
        process_hlil(operand, ty, ty_name, parameter_id)
        return
    if isinstance(operand, typing.List):
        operand = operand[parameter_id]
    if operand.operation == HighLevelILOperation.HLIL_ADDRESS_OF:
        change_type_name(operand.operands[0], ty.target, ty_name)
    elif operand.operation == HighLevelILOperation.HLIL_VAR:
        change_type_name(operand, ty, ty_name)
        hlil_function = operand.function
        var = operand.var
        var_defs = hlil_function.get_var_definitions(var)
        if var_defs:
            process_hlil(var_defs[0], ty, ty_name, parameter_id)
            return
        elif var in hlil_function.aliased_vars:
            binaryninja.log_warn(f"Used aliased variable: {operand.address:#x}")
            return
    else:
        binaryninja.log_error(f"{operand} ({operand.address:#x})")


def process():
    target_function = bv.get_function_at(bv.get_callees(here)[0])
    parameters = list(target_function.parameter_vars)
    parameter_id = binaryninja.get_choice_input(
        "Parameter", "parameters", [f"{p.type} {p.name}" for p in parameters]
    )
    parameter = parameters[parameter_id]
    ty = parameter.type
    ty_name = parameter.name
    referencese = bv.get_callers(target_function.start)

    for ref in referencese:
        reference_function = bv.get_functions_containing(ref.address)[0]
        mlil = reference_function.mlil
        reference_mlil_index = mlil.get_instruction_start(ref.address)
        reference_hlil = next(
            itertools.islice(
                reference_function.mlil_instructions, reference_mlil_index, None
            )
        ).hlil
        binaryninja.log_info(f"{ref.address:#x}")
        process_hlil(reference_hlil, ty, ty_name, parameter_id)


process()
