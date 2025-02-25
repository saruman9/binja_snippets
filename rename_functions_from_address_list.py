# Rename all functions from address list to the same name
#
import typing

from binaryninja.binaryview import BinaryView
from binaryninja.function import Function
from binaryninja.highlevelil import HighLevelILFunction
from binaryninja.interaction import MultilineTextField, TextLineField

if typing.TYPE_CHECKING:
    import binaryninja

    bv: BinaryView | None = None
    here: int = 0
    current_hlil: HighLevelILFunction | None = None
    current_function: Function | None = None


def process():
    name_f = TextLineField("Name:")
    addresses_f = MultilineTextField("Addresses (hex):")
    binaryninja.get_form_input([name_f, addresses_f], "Rename functions")
    name = name_f.result
    addresses = [int(a, 16) for a in addresses_f.result.split()]
    for a in addresses:
        f = bv.get_function_at(a)
        f.name = name


process()
