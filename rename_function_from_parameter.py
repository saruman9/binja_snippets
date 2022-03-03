# Rename the function to name, getting from string from parameter
#
import itertools
import typing

from binaryninja.highlevelil import (
    HighLevelILFunction,
    HighLevelILInstruction,
    HighLevelILOperation,
)
from binaryninja import Function

if typing.TYPE_CHECKING:
    import binaryninja

    bv: binaryninja.BinaryView = None
    here: int = 0
    current_hlil: HighLevelILFunction = None


def parse_and_set_name(signature: str, function: Function):
    signature = signature.removeprefix("virtual ")
    signature = signature.removeprefix("static ")
    signature = signature.removesuffix(" const")
    signature = signature.replace("~", "__")
    signature = signature.replace("operator=", "operator_equal")
    signature = signature.replace("operator<", "operator_less")
    signature = signature.replace("operator>", "operator_greater")
    (signature, _, _) = signature.partition("(")
    signature = signature + "()"
    (_, _, signature) = signature.rpartition(" ")
    signature = "void *" + signature
    try:
        ty, name = bv.parse_type_string(signature)
        function.name = str(name)
    except SyntaxError:
        binaryninja.log_error(
            f"Can't parse signature {signature} at {function.start:#x}"
        )
        return


def process_hlil(hlil: HighLevelILInstruction, parameter_id):
    if hlil.operation == HighLevelILOperation.HLIL_VAR_INIT:
        process_hlil(hlil.operands[1], parameter_id)
        return
    elif hlil.operation == HighLevelILOperation.HLIL_ASSIGN_UNPACK:
        process_hlil(hlil.operands[1], parameter_id)
        return
    elif hlil.operation == HighLevelILOperation.HLIL_CALL:
        parameter = hlil.params[parameter_id]
        signature = bv.get_string_at(parameter.value).value
        function = hlil.function.source_function
        function.comment = signature
        parse_and_set_name(signature, function)
    else:
        binaryninja.log_error(f"{hlil} ({hlil.address:#x})")
        return


def process():
    target_function = bv.get_function_at(bv.get_callees(here)[0])
    parameters = list(target_function.parameter_vars)
    parameter_id = binaryninja.get_choice_input(
        "Parameter", "parameters", [f"{p.type} {p.name}" for p in parameters]
    )
    references = bv.get_callers(target_function.start)

    for ref in itertools.islice(references, None):
        reference_function = bv.get_functions_containing(ref.address)[0]
        mlil = reference_function.mlil
        reference_mlil_index = mlil.get_instruction_start(ref.address)
        reference_hlil = next(
            itertools.islice(
                reference_function.mlil_instructions, reference_mlil_index, None
            )
        ).hlil
        process_hlil(reference_hlil, parameter_id)


process()
