#Rename the variable to name associated with initial var
#Shift+N
import typing
import re

from binaryninja.highlevelil import (
    HighLevelILFunction,
    HighLevelILOperation,
)
from binaryninja import Function
from binaryninja.interaction import show_message_box
from binaryninja.enums import MessageBoxIcon, TypeClass

if typing.TYPE_CHECKING:
    import binaryninja

    bv: binaryninja.BinaryView = None
    here: int = 0
    current_hlil: HighLevelILFunction = None
    current_function: Function = None


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
        binaryninja.log_error(msg)
        exit()


def get_field_name(var, offset):
    ty = var.type
    ty = get_struct_type(ty)
    return ty.member_at_offset(offset).name


def process_operand(operand):
    if operand.operation == HighLevelILOperation.HLIL_ADDRESS_OF:
        (var, name) = process_operand(operand.operands[0])
        return (var, name)
    elif operand.operation == HighLevelILOperation.HLIL_DEREF:
        (var, name) = process_operand(operand.operands[0])
        return (var, name)
    elif operand.operation == HighLevelILOperation.HLIL_DEREF_FIELD:
        (var, _) = process_operand(operand.operands[0])
        name = get_field_name(var, operand.operands[1])
        return (var, name)
    elif operand.operation == HighLevelILOperation.HLIL_CALL:
        (var, name) = process_operand(operand.operands[0])
        return (var, name)
    elif operand.operation == HighLevelILOperation.HLIL_CONST_PTR:
        sym = bv.get_symbol_at(operand.constant)
        return (sym, sym.name)
    elif operand.operation == HighLevelILOperation.HLIL_VAR:
        var = operand.var
        return (var, var.name)
    else:
        msg = f"Can't change the variable.\noperand: {operand!r}"
        show_message_box(
            "Error",
            msg,
            icon=MessageBoxIcon.ErrorIcon,
        )
        binaryninja.log_error(msg)
        exit()


def process_expr(expr):
    if expr.operation == HighLevelILOperation.HLIL_VAR_INIT:
        var = expr.operands[0]
        (_, name) = process_operand(expr.operands[1])
        if re.match('.*_\d\d', name):
            name = name[:-3]
        vars = [v for v in current_function.vars if v.name.startswith(name)]
        var.name = name + f'_{len(vars):02d}'
    # elif expr.operation == HighLevelILOperation.HLIL_ASSIGN_UNPACK:
    #     var0 = expr.operands[0][0]
    #     var1 = expr.operands[0][1]
    else:
        msg = f"Can't change the variable.\nhlil: {expr!r}"
        show_message_box(
            "Error",
            msg,
            icon=MessageBoxIcon.ErrorIcon,
        )
        binaryninja.log_error(msg)
        exit()


def process():
    expr = current_function.get_llil_at(here).hlil
    process_expr(expr)


process()
