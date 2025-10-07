# Extract ramfs files from Cisco ASA
#
from pathlib import Path
import typing

from binaryninja import (
    HighLevelILAdd,
    HighLevelILAssign,
    HighLevelILConst,
    HighLevelILDeref,
    HighLevelILDerefField,
    HighLevelILVar,
)
from binaryninja.binaryview import BinaryView
from binaryninja.highlevelil import (
    HighLevelILCall,
    HighLevelILConstPtr,
    HighLevelILInstruction,
)
from binaryninja.interaction import (
    get_address_input,
    get_directory_name_input,
    get_text_line_input,
)
from binaryninja.log import log_debug, log_info, log_warn
from binaryninja.types import StructureType
from binaryninja.variable import Variable

if typing.TYPE_CHECKING:
    bv: BinaryView = None  # pyright: ignore[reportAssignmentType]


def get_int(instr: HighLevelILInstruction) -> int | None:
    match instr:
        case HighLevelILConstPtr(constant=constant):
            value = bv.read_int(constant, 4, sign=False)
            if value is None:
                log_warn(
                    f"can't find size at {constant:08x} (instr at {instr.address:08x})"
                )
                return
            return value
        case _:
            log_debug(f"found not ConstPtr at {instr.address:08x}")


def get_data_address(instr: HighLevelILInstruction) -> int | None:
    match instr:
        case HighLevelILConstPtr(constant=constant):
            return constant
        case _:
            log_debug(f"found not ConstPtr at {instr.address:08x}")


def get_data(instr: HighLevelILInstruction, size: int) -> bytes | None:
    match instr:
        case HighLevelILConstPtr(constant=constant):
            data = bv.read(constant, size)
            if data is None:
                log_warn(
                    f"can't find data at {constant:08x} (instr at {instr.address:08x})"
                )
                return
            return data
        case _:
            log_debug(f"found not ConstPtr at {instr.address:08x}")


def get_string(instr: HighLevelILInstruction) -> str | None:
    match instr:
        case HighLevelILConstPtr(constant=constant):
            string = bv.get_ascii_string_at(constant)
            if string is None:
                log_warn(
                    f"can't find string at {constant:08x} (instr at {instr.address:08x})"
                )
                return
            return string.value
        case _:
            log_debug(f"found not ConstPtr at {instr.address:08x}")


def get_params(
    instr: HighLevelILInstruction, type: str
) -> HighLevelILInstruction | None:
    match instr:
        case HighLevelILCall(params=params):
            try:
                name = next(params[1].traverse(get_string))  # pyright: ignore[reportArgumentType]
                if name == "handler":
                    return params[2]
            except IndexError:
                log_warn(f"can't find parameters at {instr.address:08x}")
            except StopIteration:
                log_warn(f"can't get string at {instr.address:08x}")


def get_var(instr: HighLevelILInstruction) -> Variable | None:
    match instr:
        case HighLevelILVar(var=var):
            return var


def get_add(instr: HighLevelILInstruction) -> int | None:
    match instr:
        case HighLevelILAdd(right=right):
            match right:
                case HighLevelILConst(constant=constant):
                    return constant


def get_field_offset(
    instr: HighLevelILInstruction,
    structure: StructureType,
    field_name: str,
) -> bool | None:
    src = None
    match instr:
        case HighLevelILDerefField(offset=offset, src=src):
            log_debug(f"DerefField: src={src} ({src.address:08x})")
            if structure.member_at_offset(offset).name == field_name:
                return True
        case HighLevelILDeref(src=src):
            log_debug(f"Deref: src={src} ({src.address:08x})")
            offset = next(src.traverse(get_add), None)  # pyright: ignore[reportArgumentType]
            if offset is None:
                return None
            log_debug(f"with offset={offset:03x}")
            if structure.member_at_offset(offset).name == field_name:
                return True


def get_filename_or_mime(src: HighLevelILInstruction) -> str | None:
    try:
        return next(src.traverse(get_string))  # pyright: ignore[reportArgumentType]
    except StopIteration:
        log_warn(f"can't get string at {src.address:08x}")
        return


def get_size(src: HighLevelILInstruction) -> int | None:
    try:
        var: Variable = next(src.traverse(get_var))  # pyright: ignore[reportArgumentType]
    except StopIteration:
        log_warn(f"can't get var for size at {src.address:08x}")
        return
    try:
        definition = src.function.get_var_definitions(var)[0]
    except IndexError:
        log_warn(f"can't find definition of the size's var near {src.address:08x}")
        return
    try:
        return next(definition.traverse(get_int))  # pyright: ignore[reportArgumentType]
    except StopIteration:
        log_warn(f"can't get int for size at {src.address:08x}")
        return


def get_content_address(src: HighLevelILInstruction) -> int | None:
    log_debug(f"content instr: {src} at {src.address:08x}")
    try:
        return next(src.traverse(get_data_address))  # pyright: ignore[reportArgumentType]
    except StopIteration:
        log_warn(f"can't get content address at {src.address:08x}")
        return


def get_content(src: HighLevelILInstruction, size: int):
    log_debug(f"data instr: {src} at {src.address:08x}")
    try:
        return next(src.traverse(get_data, size))  # pyright: ignore[reportArgumentType]
    except StopIteration:
        log_warn(f"can't get data at {src.address:08x}")
        return


def process():
    if bv is None or bv.arch is None:
        return
    directory = get_directory_name_input("Directory for save:")
    if directory is not None:
        directory = Path(directory)
    functions = bv.get_functions_by_name("ramfs_mdata_set")
    if len(functions) != 1:
        address = get_address_input(
            "Address of ramfs_mdata_set function:", "ramfs_mdata_set"
        )
        if address is None:
            return
        function = bv.get_function_at(address)
        if function is None:
            log_warn(f"can't find function at {address:08x}")
            return
    else:
        function = functions[0]
    structure_type = bv.get_type_by_name("ramfs_file_handler_info_t")
    if structure_type is None:
        structure_name = get_text_line_input(
            "Structure name:", "ramfs_file_handler_info_t another name"
        )
        if structure_name is None:
            return
        structure_name = structure_name.decode()
        structure_type = bv.get_type_by_name(structure_name)
        if structure_type is None:
            log_warn(f"can't find {structure_name} type")
            return

    for caller_site in function.caller_sites:
        hlil = caller_site.hlil
        if hlil is None:
            log_warn(f"can't get HLIL at {caller_site.address}")
            continue
        hlil_function = hlil.function
        try:
            file_handler_info: HighLevelILInstruction = next(
                hlil.traverse(get_params, "handler")
            )
        except StopIteration:
            log_debug(
                f"can't find file_handler_info param or not handler at {hlil.address:08x}"
            )
            continue
        match file_handler_info:
            case HighLevelILVar(var=var):
                var_refs = hlil_function.source_function.get_hlil_var_refs(var)
            case _:
                log_warn(f"can't find variable at {file_handler_info.address:08x}")
                continue
        filename = None
        mime = None
        size = None
        content_address = None
        for ref in var_refs:
            expr_id = ref.expr_id
            try:
                hlil_instr = hlil_function[expr_id]
            except IndexError:
                log_warn(
                    f"can't get HLIL instruction via expr_id ({expr_id}) at {ref.address:08x}"
                )
                continue

            log_debug(f"{hlil_instr} : {hlil_instr.address:08x}")

            dest = None
            match hlil_instr:
                case HighLevelILAssign(dest=dest, src=src):
                    src = src
                    dest = dest
                case _:
                    log_debug(f"not Assign at {ref.address:08x}")
                    continue

            if next(
                dest.traverse(
                    get_field_offset,  # pyright: ignore[reportArgumentType]
                    structure_type,
                    "filename",
                ),
                None,
            ):
                filename = get_filename_or_mime(src)
                log_debug(f"filename = {filename}")

            if next(
                dest.traverse(
                    get_field_offset,  # pyright: ignore[reportArgumentType]
                    structure_type,
                    "mime",
                ),
                None,
            ):
                mime = get_filename_or_mime(src)
            log_debug(f"mime = {mime}")

            if next(
                dest.traverse(get_field_offset, structure_type, "size"),  # pyright: ignore[reportArgumentType]
                None,
            ):
                size = get_size(src)
                log_debug(f"size = {size}")

            if next(
                dest.traverse(
                    get_field_offset,  # pyright: ignore[reportArgumentType]
                    structure_type,
                    "content",
                ),
                None,
            ):
                content_address = get_content_address(src)
                log_debug(f"content_address = {content_address:08x}")

        if (
            (filename is None and mime is None)
            or size is None
            or content_address is None
        ):
            log_warn(f"can't get info about fields at {caller_site.address:08x}")
            continue
        if filename is not None:
            log_info(f"filename: {filename}")
        else:
            log_info(f"mime: {mime}")
        log_info(
            f"content: {content_address:08x} with size: {size} at {caller_site.address:08x}"
        )
        if directory is None or filename is None:
            continue
        content = bv.read(content_address, size)
        path = directory / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, mode="bw") as f:
            f.write(content)
        log_info(f"successfully write to {path}")


process()
