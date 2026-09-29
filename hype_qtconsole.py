r"""
IDA Pro 9.4+ plugin that opens a dockable Qt widget hosting a rich Jupyter qtconsole,
connected to an already-running Jupyter kernel (e.g. one started by HYPE) via a fixed connection file.

This does NOT start a kernel. It only opens a *client* view onto a kernel that is already listening on the ports described in the connection file
(the same file you would otherwise hand to `jupyter console --existing`).

Requires (in IDA's bundled Python / site-packages):
pip install --upgrade qtconsole jupyter_client

Usage:
Edit > Plugins > HYPE Qt Console (default hotkey: Ctrl-Alt-J)
"""

from __future__ import annotations

__version__ = "2026-09-30 00:17:26"
__author__ = "Harding"
__description__ = __doc__
__copyright__ = "Copyright 2026"
__credits__ = ["https://github.com/eset/ipyida"]
__license__ = "GPL 3.0"
__maintainer__ = "Harding"
__email__ = "not.at.the.moment@example.com"
__status__ = "Development"
__url__ = "https://github.com/Harding-Stardust/hype"

import os as _os
from typing import Optional

try:
    import community_base  # https://github.com/Harding-Stardust/community_base
except Exception:
    print(f"{__file__}: Failed to import community_base. You need to install it from https://github.com/Harding-Stardust/community_base")
    raise

from PySide6 import QtWidgets # type: ignore[import-untyped]

try:
    import qtconsole.styles # type: ignore[import-untyped]
    from qtconsole.client import QtKernelClient # type: ignore[import-untyped]
    from qtconsole.manager import QtKernelManager # type: ignore[import-untyped]
    from qtconsole.rich_jupyter_widget import RichJupyterWidget # type: ignore[import-untyped]
    _G_QTCONSOLE_IMPORT_ERROR: Optional[BaseException] = None
except ImportError as arg_import_error:  # pragma: no cover - environment dependent
    qtconsole = None  # type: ignore[assignment]
    QtKernelClient = None  # type: ignore[assignment,misc]
    QtKernelManager = None  # type: ignore[assignment,misc]
    RichJupyterWidget = None  # type: ignore[assignment,misc]
    _G_QTCONSOLE_IMPORT_ERROR = arg_import_error


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
_G_USE_DARK_STYLE: bool = True # Set to False to use qtconsole's default light theme instead.

g_connection_file: str = _os.path.join(community_base.ida_user_dir(), "hype_jupyter_connection.json")

def _resolve_connection_file() -> str:
    """
    Prefer the PID-specific connection file for this IDA process, if the
    kernel had to fall back to a non-default port (e.g. because another IDA
    process already held the default port). Otherwise fall back to the
    default connection file.
    """
    l_pid_variant: str = _os.path.join(community_base.ida_user_dir(), f"hype_jupyter_connection_{_os.getpid()}.json")
    if _os.path.isfile(l_pid_variant):
        return l_pid_variant
    return g_connection_file

# --------------------------------------------------------------------------
# Console widget
# --------------------------------------------------------------------------

class JupyterConsoleForm(community_base._ida_kernwin.PluginForm):
    """Dockable IDA form hosting a RichJupyterWidget connected to a
    pre-existing remote kernel described by a Jupyter connection file."""

    def __init__(self, arg_connection_file_path: str) -> None:
        super().__init__()
        self.connection_file_path: str = arg_connection_file_path  # placeholder; re-resolved in _connect_kernel()
        self.kernel_manager: Optional[QtKernelManager] = None
        self.kernel_client: Optional[QtKernelClient] = None
        self.jupyter_widget: Optional[RichJupyterWidget] = None
        self.parent_widget = None

    def OnCreate(self, arg_form: community_base._ida_kernwin.TWidget) -> None:
        """Called by IDA once the underlying TWidget has been created."""
        community_base.log_print("Creating Jupyter console form", arg_type="DEBUG")
        self.parent_widget = self.FormToPyQtWidget(arg_form)
        self._build_ui()

    def _build_ui(self) -> None:
        """Build the layout and attempt to connect to the kernel."""
        l_layout: QtWidgets.QVBoxLayout = QtWidgets.QVBoxLayout()
        l_layout.setContentsMargins(0, 0, 0, 0)
        if self.parent_widget is not None:
            self.parent_widget.setLayout(l_layout)

        if RichJupyterWidget is None:
            l_message: str = f"qtconsole is not installed in IDA's Python environment. Import error: {_G_QTCONSOLE_IMPORT_ERROR} Install it with: pip install --upgrade qtconsole jupyter_client"
            community_base.log_print(l_message, arg_type="ERROR")
            l_label: QtWidgets.QLabel = QtWidgets.QLabel(l_message)
            l_label.setWordWrap(True); l_layout.addWidget(l_label)
            return

        try:
            self._connect_kernel()
        except Exception as arg_connect_error:  # noqa: BLE001 - surfaced to user
            community_base.log_print(f"Failed to connect to kernel: {arg_connect_error}", arg_type="ERROR")
            l_error_label: QtWidgets.QLabel = QtWidgets.QLabel(f"Failed to connect to kernel at '{self.connection_file_path}': {arg_connect_error}"); l_error_label.setWordWrap(True); l_layout.addWidget(l_error_label)
            return

        self.jupyter_widget = RichJupyterWidget()
        if _G_USE_DARK_STYLE:
            self._apply_dark_style(self.jupyter_widget)
        self.jupyter_widget.kernel_manager = self.kernel_manager
        self.jupyter_widget.kernel_client = self.kernel_client
        l_layout.addWidget(self.jupyter_widget)
        community_base.log_print(f"Loaded HYPE Qt Console version: {__version__} by {__author__}. This version was released {community_base._time_since(__version__)}", arg_type="INFO")

    @staticmethod
    def _apply_dark_style(arg_widget: RichJupyterWidget) -> None:
        """Apply qtconsole's built-in dark theme to a RichJupyterWidget.

        Equivalent to the old IPyIDA pattern of setting `style_sheet=qtconsole.styles.default_dark_style_sheet` and `syntax_style=qtconsole.styles.default_dark_syntax_style`,
        just applied directly rather than via ipyida.ida_qtconsole's set_widget_options() helper (which no longer applies here since we build the widget ourselves).
        """
        arg_widget.style_sheet = qtconsole.styles.default_dark_style_sheet
        arg_widget.syntax_style = qtconsole.styles.default_dark_syntax_style
        arg_widget.set_default_style(colors="linux")

    def _connect_kernel(self) -> None:
        """Load the connection file and start client channels.

        The connection file is resolved fresh on every call (rather than
        once at plugin load time), so multiple console windows opened later
        still resolve to whichever kernel is actually running right now.

        Raises:
            FileNotFoundError: if the connection file does not exist.
            Exception: any error raised by qtconsole/jupyter_client while
                loading the connection file or starting channels.
        """
        self.connection_file_path = _resolve_connection_file()

        if not _os.path.isfile(self.connection_file_path):
            raise FileNotFoundError(f"Connection file not found: {self.connection_file_path}")

        community_base.log_print(f"Connecting to kernel using connection file: {self.connection_file_path}", arg_type="INFO")

        l_kernel_manager: QtKernelManager = QtKernelManager(connection_file=self.connection_file_path)
        l_kernel_manager.load_connection_file()
        l_kernel_manager.client_factory = QtKernelClient

        l_kernel_client: QtKernelClient = l_kernel_manager.client()
        l_kernel_client.start_channels()

        self.kernel_manager = l_kernel_manager
        self.kernel_client = l_kernel_client

    def OnClose(self, arg_form: community_base._ida_kernwin.TWidget) -> None:
        """Called by IDA when the form is closed; tear down channels."""
        del arg_form # Not used but needed in prototype
        community_base.log_print("Closing Jupyter console form", arg_type="DEBUG")
        if self.kernel_client is not None:
            try:
                self.kernel_client.stop_channels()
            except Exception:  # noqa: BLE001 - best-effort cleanup
                community_base.log_print("Error stopping kernel client channels", arg_type="ERROR")
        self.kernel_manager = None
        self.kernel_client = None
        self.jupyter_widget = None

class JupyterConsolePlugmod(community_base._ida_idaapi.plugmod_t):
    """Per-database plugin instance (IDA 9.x multi-plugin model)."""

    def __init__(self) -> None:
        super().__init__()
        self.form: Optional[JupyterConsoleForm] = None

    def run(self, arg_user_argument: int) -> int:
        del arg_user_argument # Not used but needed in prototype

        if self.form is None:
            self.form = JupyterConsoleForm(g_connection_file)
        self.form.Show(
            "HYPE Qt Console",
            options=(
                community_base._ida_kernwin.PluginForm.WOPN_TAB
                | community_base._ida_kernwin.PluginForm.WOPN_MENU
                | community_base._ida_kernwin.PluginForm.WOPN_RESTORE
                | community_base._ida_kernwin.PluginForm.WOPN_PERSIST
            ),
        )
        # Show() alone brings the tab/dock into view but does not guarantee
        # keyboard focus lands in the console; explicitly focus the widget
        # (or its input area, if qtconsole exposes one) so pressing the
        # hotkey again always drops the user straight into the prompt.
        if self.form.jupyter_widget is not None:
            l_focus_target = getattr(self.form.jupyter_widget, "_control", None) or self.form.jupyter_widget
            l_focus_target.setFocus()
        return 0

    def __del__(self) -> None:
        community_base.log_print("JupyterConsolePlugmod destructor called", arg_type="DEBUG")
        return

class JupyterConsolePlugin(community_base._ida_idaapi.plugin_t):
    flags = community_base._ida_idaapi.PLUGIN_MULTI
    comment = f"HYPE Qt Console - A Rich Jupyter console connected to an existing kernel. Version {__version__}"
    help = 'Opens a window inside IDA Pro that connects to the ipykernel started by this IDA Pro'
    wanted_name = "HYPE Qt Console"
    wanted_hotkey = "Ctrl-Alt-J"

    def init(self) -> JupyterConsolePlugmod:
        return JupyterConsolePlugmod()

def PLUGIN_ENTRY() -> community_base._ida_idaapi.plugin_t:
    return JupyterConsolePlugin()
