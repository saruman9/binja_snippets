# Dump functions names
#
import typing

from binaryninja.binaryview import BinaryView
from binaryninja.interaction import get_save_filename_input
from binaryninja.log import log_info, log_warn

if typing.TYPE_CHECKING:
    bv: BinaryView | None = None


def process():
    filename = get_save_filename_input(
        "File with functions", default_name="functions.txt"
    )
    if filename is None:
        return
    functions = []
    with open(filename, "w") as f:
        for function in bv.functions:
            if not function.symbol.auto:
                f.write(hex(function.start))
                f.write(" ")
                f.write(function.name)
                f.write("\n")
                if function.name in functions:
                    log_warn(f"Duplicate: {function.name} ({function.start:#x})")
                functions.append(function.name)
    log_info(f"Dumped {len(functions):08} function(s) to {filename}")


process()
