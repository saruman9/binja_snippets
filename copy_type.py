# Copy type from one tab to another
#
import itertools
import typing

from binaryninja.highlevelil import HighLevelILFunction
from binaryninja.types import QualifiedName
from binaryninjaui import UIActionContext
from binaryninja import MessageBoxIcon, MessageBoxButtonSet, MessageBoxButtonResult

if typing.TYPE_CHECKING:
    import binaryninja

    current_view: binaryninja.BinaryView = None
    here: int = 0
    current_hlil: HighLevelILFunction = None
    uicontext: UIActionContext = None


def process():
    ty = binaryninja.get_text_line_input("Type:", "Type")
    if ty == None:
        exit()
    type_name = ty.split(b"::")
    name = QualifiedName(type_name)
    ty = current_view.get_type_by_name(name)
    if ty == None:
        binaryninja.show_message_box(
            "Type", f"Type {name!s} not defined.", icon=MessageBoxIcon.ErrorIcon
        )
        exit()

    context = uicontext.context
    views = context.getAvailableBinaryViews()
    tabs = context.getTabs()
    tab_id = binaryninja.get_choice_input(
        "Tab:", "Tab", [f"{t.getTabName()}" for t in tabs]
    )
    if tab_id == None:
        exit()
    new_view = views[tab_id][0]

    if new_view.get_type_by_name(name):
        if (
            binaryninja.show_message_box(
                "Type",
                f"Type {name!s} already defined. Redefine?",
                buttons=MessageBoxButtonSet.YesNoButtonSet,
            )
            == MessageBoxButtonResult.NoButton
            or MessageBoxButtonResult.CancelButton
        ):
            exit()

    new_view.define_user_type(name, ty)


process()
