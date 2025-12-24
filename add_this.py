# Add manually `this` argument as first
#
import typing

from binaryninja.architecture import InstructionTextToken
from binaryninja.binaryview import BinaryView
from binaryninja.demangle import demangle_gnu3
from binaryninja.enums import StructureVariant
from binaryninja.function import Function
from binaryninja.mediumlevelil import (
    MediumLevelILCall,
    MediumLevelILConstPtr,
    MediumLevelILFunction,
    MediumLevelILInstruction,
    MediumLevelILTailcall,
)
from binaryninja.log import log_alert, log_info, log_warn
from binaryninja.types import FunctionParameter, FunctionType, Type

if typing.TYPE_CHECKING:
    bv: BinaryView = None  # pyright: ignore[reportAssignmentType]
    current_token: InstructionTextToken | None = None
    current_mlil: MediumLevelILFunction | None = None
    current_function: Function | None = None


def get_const(instr: MediumLevelILInstruction) -> int | None:
    match instr:
        case MediumLevelILConstPtr(constant=constant):
            return constant


def get_dest_from_call(
    instr: MediumLevelILInstruction,
) -> MediumLevelILInstruction | None:
    match instr:
        case MediumLevelILCall(dest=dest) | MediumLevelILTailcall(dest=dest):
            return dest


def process():
    if bv is None or bv.arch is None:
        return
    if current_token is None:
        log_warn("token not selected")
        return
    if current_mlil is None:
        log_warn("can't get current MLIL function")
        return
    address = current_token.address
    if address == 0:
        method = current_function
        if method is None:
            log_warn("can't get function with 0 token address")
            return
        method_address = method.start
    else:
        mlil_index = current_mlil.get_instruction_start(address)
        if mlil_index is None:
            log_warn(f"can't get index of MLIL instruction at address {address:016x}")
            return
        try:
            mlil_instruction = current_mlil[mlil_index]
        except IndexError:
            log_warn(f"can't get MLIL instruction by index {mlil_index}")
            return
        method_dest_instr: MediumLevelILInstruction | None = next(
            mlil_instruction.traverse(get_dest_from_call),  # pyright: ignore[reportArgumentType]
            None,
        )
        if method_dest_instr is None:
            log_warn(
                f"can't find dest in the instruction at {mlil_instruction.address:016x}"
            )
            return
        method_address: int | None = next(method_dest_instr.traverse(get_const), None)  # pyright: ignore[reportArgumentType]
        if method_address is None:
            log_warn(f"can't get address of method at {mlil_instruction.address:016x}")
            return
        method = bv.get_function_at(method_address)

    if method is None:
        log_warn(f"can't find method at {method_address:016x}")
        return
    demangled = demangle_gnu3(bv.arch, method.symbol.raw_name)
    if demangled[0] is None:
        log_warn(f"method already demangled at {method_address:016x}")
        return
    demangled_type = demangled[0]
    if not isinstance(demangled_type, FunctionType):
        log_warn(
            f"demangled method type at {method_address:016x} is not FunctionType ({type(demangled_type)})"
        )
        return

    class_name = "::".join(demangled[1][:-1])
    if (class_type := bv.get_type_by_name(class_name)) is None:
        bv.define_user_type(
            class_name,
            Type.structure(members=None, type=StructureVariant.ClassStructureType),
        )
        class_type = bv.get_type_by_name(class_name)
        if class_type is None:
            log_alert(f"can't create class type {class_name}")
            return
        log_info(f"create new type {class_type}")
    this_type = Type.pointer(bv.arch, class_type)

    this_param = FunctionParameter(this_type, "this")
    new_params = [this_param] + demangled_type.parameters
    return_type = demangled_type.return_value
    new_method_type = FunctionType.create(ret=return_type, params=new_params)
    method.type = new_method_type

    log_info(f"replaced type for {method} ({method.start:016x}) to {new_method_type}")


process()
