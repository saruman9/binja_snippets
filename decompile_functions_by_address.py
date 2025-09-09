# Decompile functions by address (from a file)
#
from pathlib import Path
import typing

from binaryninja.binaryview import BinaryView
from binaryninja.interaction import (
    get_open_filename_input,
)
from binaryninja.log import log_info, log_warn

if typing.TYPE_CHECKING:
    bv: BinaryView | None = None


def process():
    if bv is None or bv.arch is None:
        return
    path = get_open_filename_input("File with addresses")
    if path is None:
        return
    directory = Path(path).parent / "decomp"
    try:
        directory.mkdir()
    except (FileNotFoundError, OSError):
        log_warn(f"can't create 'decomp' directory at {directory}")
        return
    with open(path) as f:
        for address in f.readlines():
            try:
                address = int(address)
            except ValueError:
                log_warn(f"{address} is not int")
                continue
            function = bv.get_function_at(address)
            if function is None:
                log_warn(f"the function doesn't exist at {address:08x}")
                continue
            hlil = function.hlil
            if hlil is None or hlil.root is None:
                log_warn(f"{function} ({address:08x}) doesn't have HLIL")
                continue
            out_file = directory / f"{address:08x}.txt"
            with open(out_file, "x", encoding="utf-8") as out:
                out.write("".join([x + "\n" for x in map(str, hlil.root.lines)]))
            log_info(f"HLIL wrote to {out_file}")


process()
