# Dump functions names
#
import typing

from binaryninja.binaryview import BinaryView
from binaryninja.interaction import get_save_filename_input
from binaryninja.log import log_info, log_warn

if typing.TYPE_CHECKING:
    bv: BinaryView = None  # pyright: ignore[reportAssignmentType]


def process():
    filename = get_save_filename_input(
        "File with functions", default_name="functions.txt"
    )
    if filename is None:
        return
    functions: list[str] = []
    with open(filename, "w") as f:
        for function in bv.functions:
            if not function.symbol.auto:
                if function.name in functions:
                    log_warn(f"Duplicate: {function.name} ({function.start:08x})")
                    continue
                f.write(f"{function.start:08x} : {function.name}\n")
                functions.append(function.name)
    log_info(f"Dumped {len(functions)} function(s) to {filename}")


process()
