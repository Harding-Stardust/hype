r"""
HYPE (Here's Your Python Executor) - A Jupyter Kernel for IDA Pro.

It starts a real ipykernel using a FIXED connection file (same ip/ports every time IDA starts). From your host, point jupyter at the same fixed json file.

jupyter console --existing "%APPDATA%\Hex-Rays\IDA Pro\hype_jupyter_connection.json"

This plug in has no qtconsole widget and no window inside IDA, it is purely a socket you connect to from outside.
If you want to use a widget, you can use the plugin named "hype_qtconsole.py" to create a widget that connects to the kernel.

Requirements:
pip install --upgrade ipykernel

Long-running code will block IDA's UI for their duration while they run on the main thread, exactly like any other synchronous IDA script.
"""

from __future__ import annotations

__version__ = "2026-09-04 01:12:57"
__author__ = "Harding"
__description__ = __doc__
__copyright__ = "Copyright 2026"
__credits__ = ["https://github.com/eset/ipyida"]
__license__ = "GPL 3.0"
__maintainer__ = "Harding"
__email__ = "not.at.the.moment@example.com"
__status__ = "Development"
__url__ = "https://github.com/Harding-Stardust/hype"

import os
import json
import signal
import asyncio
import inspect
import threading
import socket
import traceback
import secrets
from collections.abc import Callable
from typing import Any, Optional, TypeVar
try:
    import community_base  # https://github.com/Harding-Stardust/community_base
except Exception:
    print(f"Failed to import community_base. You need to install it from https://github.com/Harding-Stardust/community_base")
    raise

try:
    import ipykernel
    from ipykernel.kernelapp import IPKernelApp
    from ipykernel.ipkernel import IPythonKernel
    # community_base.log_print(f"ipykernel imported OK, version {getattr(ipykernel, '__version__', 'unknown')}", arg_type="DEBUG")
except Exception:
    community_base.log_print(f"failed to import ipykernel - it is probably not installed: pip install --upgrade ipykernel\n{traceback.format_exc()}", arg_type="ERROR")
    raise

community_base.log_print("all imports OK, module ready", arg_type="INFO")

# ------------------------
#         Config
# ------------------------

g_default_shell_port: int = 17001
g_use_auth: bool = True
g_rc_filename: str = "hyperc.py"

g_port_search_step: int = 1000
g_port_search_max_attempts: int = 20
g_port_span: int = 5  # shell, iopub, stdin, hb, control

# These are resolved at kernel startup time in _run_kernel(), since which port block (and therefore which connection file)
# we end up on depends on whether another HYPE instance is already running in another IDA process.
g_connection_file: str | None = None
g_shell_port: int | None = None
g_iopub_port: int | None = None
g_stdin_port: int | None = None
g_hb_port: int | None = None
g_control_port: int | None = None

def _resolve_bind_ip() -> str:
    """
    Pick an IP clients can use to reach this kernel.

    gethostbyname(hostname) can fail or return an address that is not reachable from remote hosts; fall back to loopback in that case.
    Set g_bind_ip manually below if you need a specific LAN address.
    """
    try:
        l_ip: str = socket.gethostbyname(socket.gethostname())
        if l_ip:
            return l_ip
    except OSError:
        community_base.log_print("Could not resolve bind IP from hostname; using 127.0.0.1", arg_type="WARNING")
    return "127.0.0.1"

g_bind_ip: str = _resolve_bind_ip()

def _port_block_is_free(arg_ip: str, arg_base_port: int, arg_span: int = g_port_span) -> bool:
    """ Return True if none of arg_base_port .. arg_base_port + arg_span - 1 are currently bound on arg_ip. """
    for l_offset in range(arg_span):
        l_sock: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            l_sock.settimeout(0.2)
            l_result: int = l_sock.connect_ex((arg_ip, arg_base_port + l_offset))
            if l_result == 0:
                return False  # something answered - port taken
        except OSError:
            pass  # treat connect errors as "not in use" for our purposes
        finally:
            l_sock.close()
    return True

def _find_free_port_block(arg_ip: str) -> int:
    """
    Prefer the default fixed base port (so the common single-IDA case always gets the same, predictable port block). If that block is taken - most
    likely by another HYPE instance in another IDA process - search upward in steps of g_port_search_step until a free block is found.
    """
    l_check_ip: str = arg_ip if arg_ip != "0.0.0.0" else "127.0.0.1"
    for l_attempt in range(g_port_search_max_attempts):
        l_candidate: int = g_default_shell_port + l_attempt * g_port_search_step
        if _port_block_is_free(l_check_ip, l_candidate):
            return l_candidate
    raise RuntimeError(
        f"HYPE: could not find a free port block after {g_port_search_max_attempts} attempts "
        f"starting at {g_default_shell_port} (step {g_port_search_step})"
    )

# ---------------------------------------------------------------------------
# signal.signal() only works on the interpreter's main thread. ipykernel calls it during startup and on every shell dispatch (pre_handler_hook).
# Since the kernel's networking runs on a worker thread here, make those calls a safe no-op instead of letting them raise and kill the thread.
# ---------------------------------------------------------------------------
g_orig_signal: Callable[[signal.Signals | int, Any], Any] = signal.signal
T = TypeVar("T")

def _safe_signal(arg_sig: signal.Signals | int, arg_handler: Any) -> Any:
    if threading.current_thread() is not threading.main_thread():
        # community_base.log_print(f"signal.signal({arg_sig!r}, ...) suppressed - not on the main thread", arg_type="DEBUG")
        return None
    return g_orig_signal(arg_sig, arg_handler)

signal.signal = _safe_signal # type: ignore[assignment]

def run_on_main_thread(
    arg_func: Callable[..., T],
    *args: Any,
    **kwargs: Any,
) -> T:
    """
    Run arg_func(*args, **kwargs) on IDA's main thread and return its result.
    Blocks the calling (kernel) thread until IDA has run it.
    """
    l_box: dict[str, Any] = {}

    def runner() -> int:
        try:
            l_box["result"] = arg_func(*args, **kwargs)
        except BaseException as arg_exc:  # noqa: BLE001 - re-raised on caller thread
            l_box["exc"] = arg_exc
        return 1

    # TODO: Should I use idc.batch() here?
    community_base._idaapi_execute_sync(runner, community_base._ida_kernwin.MFF_WRITE)

    if "exc" in l_box:
        raise l_box["exc"]
    return l_box["result"]

def _run_coroutine_on_main_thread(arg_coro: Any) -> Any:
    """
    Run an awaitable on IDA's main thread without nesting inside a running loop.

    asyncio.run() raises if a loop is already running on that thread; IDA's main thread normally has none, but we still manage the loop explicitly so stale loop state cannot leak between cells.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        l_loop: asyncio.AbstractEventLoop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(l_loop)
            return l_loop.run_until_complete(arg_coro)
        finally:
            asyncio.set_event_loop(None)
            l_loop.close()

    raise RuntimeError("IDA main thread already has a running asyncio event loop; cannot execute kernel cell safely")

class MainThreadKernel(IPythonKernel):
    """
    IPython kernel whose cell execution runs on IDA's main thread, since idc/idaapi (and anything built on it) can only be called safely from there.
    Networking (zmq/asyncio) stays on the background kernel thread; only the actual code execution hops over to IDA's main thread and back.
    """
    async def do_execute(
        self,
        code: str,
        silent: bool,
        store_history: bool = True,
        user_expressions: dict[str, Any] | None = None,
        allow_stdin: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        # ipykernel calls this via do_execute(**{"code": ..., "silent": ...});
        # parameter names must match the parent API - alias to arg_* locally.
        arg_code: str = code
        arg_silent: bool = silent
        arg_store_history: bool = store_history
        arg_user_expressions: dict[str, Any] | None = user_expressions
        arg_allow_stdin: bool = allow_stdin

        # l_preview: str = arg_code if len(arg_code) <= 200 else arg_code[:200]
        # community_base.log_print(f"dispatching cell to IDA main thread: {l_preview!r}", arg_type="DEBUG")

        def run_cell_sync() -> dict[str, Any]:
            # super() does not work inside nested functions; call parent explicitly.
            l_coro = IPythonKernel.do_execute(
                self,
                arg_code,
                arg_silent,
                arg_store_history,
                arg_user_expressions,
                arg_allow_stdin,
                **kwargs,
            )
            return _run_coroutine_on_main_thread(l_coro)

        try:
            l_result: dict[str, Any] = run_on_main_thread(run_cell_sync)
            # community_base.log_print("cell finished on main thread", arg_type="DEBUG")
            return l_result
        except Exception:
            community_base.log_print(f"cell execution failed on IDA's main thread\n{traceback.format_exc()}", arg_type="ERROR")
            raise

    async def do_complete(self, code: str, cursor_pos: int) -> dict[str, Any]:
        # Tab-completion. IPython's completer can end up touching live IDA/SWIG
        # objects (attribute lookups etc.) while building completion candidates,
        # which is only safe from IDA's main thread - same reasoning as do_execute.
        arg_code: str = code
        arg_cursor_pos: int = cursor_pos

        def run_complete_sync() -> dict[str, Any]:
            # IPythonKernel.do_complete is a coroutine function on some ipykernel
            # versions and a plain sync method on others - handle both.
            l_result = IPythonKernel.do_complete(self, arg_code, arg_cursor_pos)
            if inspect.isawaitable(l_result):
                return _run_coroutine_on_main_thread(l_result)
            return l_result

        try:
            return run_on_main_thread(run_complete_sync)
        except Exception:
            community_base.log_print(f"do_complete failed on IDA's main thread\n{traceback.format_exc()}", arg_type="ERROR")
            raise

    async def do_inspect(
        self,
        code: str,
        cursor_pos: int,
        detail_level: int = 0,
        omit_sections: tuple[str, ...] = (),
    ) -> dict[str, Any]:
        # Object inspection (e.g. the '?'/'??' operator, hover/tooltip info in
        # some clients, and completion-adjacent introspection). Same main-thread
        # requirement as do_execute/do_complete - IPython's inspector walks
        # attributes on the target object, which can be an IDA/SWIG object.
        arg_code: str = code
        arg_cursor_pos: int = cursor_pos
        arg_detail_level: int = detail_level
        arg_omit_sections: tuple[str, ...] = omit_sections

        def run_inspect_sync() -> dict[str, Any]:
            # Same story as do_complete - IPythonKernel.do_inspect is async on
            # some ipykernel versions, plain sync on others.
            l_result = IPythonKernel.do_inspect(
                self,
                arg_code,
                arg_cursor_pos,
                arg_detail_level,
                arg_omit_sections,
            )
            if inspect.isawaitable(l_result):
                return _run_coroutine_on_main_thread(l_result)
            return l_result

        try:
            return run_on_main_thread(run_inspect_sync)
        except Exception:
            community_base.log_print(f"do_inspect failed on IDA's main thread\n{traceback.format_exc()}", arg_type="ERROR")
            raise

g_app: IPKernelApp | None = None
g_kernel_thread: threading.Thread | None = None


def _load_one_rc_file(arg_path: str, arg_user_ns: dict[str, Any]) -> None:
    """
    Execute a single hyperc.py file's source directly in arg_user_ns (the kernel's own user namespace), so anything it defines/imports
    (e.g. `import community_base as cb`) is immediately available in every cell the user types afterwards.

    Errors are logged with a full traceback but never raised further, since a broken hyperc.py should not prevent the kernel from starting
    or from being usable - the user can fix the file and call hype_reload_rc_files() from within the console to pick up the fix.
    """
    if not os.path.isfile(arg_path):
        community_base.log_print(f"No rc file found at {arg_path}, skipping", arg_type="INFO")
        return

    community_base.log_print(f"Loading rc file {arg_path}", arg_type="INFO")
    try:
        with open(arg_path, encoding="utf-8") as l_f:
            l_source: str = l_f.read()
        l_code = compile(l_source, arg_path, "exec")
        arg_user_ns["__file__"] = arg_path  # mimic normal module-import behaviour so rc files can use __file__
        exec(l_code, arg_user_ns)  # noqa: S102 - intentional, this is the whole point of an rc file
        community_base.log_print(f"rc file {arg_path} loaded OK", arg_type="INFO")
    except Exception:
        community_base.log_print(f"rc file {arg_path} failed to load\n{traceback.format_exc()}", arg_type="ERROR")

def _local_rc_path() -> Optional[str]:
    """
    Path to the per-IDB hyperc.py, sitting next to the currently open database. Returns None if there is no known idb path (e.g. no database open yet), in which case the local rc file is skipped.
    """

    l_idb_path: str = community_base.input_file.idb_path
    return os.path.join(os.path.dirname(l_idb_path), g_rc_filename)

def hype_reload_rc_files() -> None:
    """
    Re-run the global hyperc.py (in community_base.ida_user_dir()) followed by the local, per-IDB hyperc.py (next to the open database), both executed directly in the running kernel's user namespace.
    Callable from within the console itself (it is injected into the kernel's user namespace at startup), so a broken rc file can be fixed on disk and picked up again without restarting IDA:
    hype_reload_rc_files()
    """
    if g_app is None or g_app.kernel is None:
        community_base.log_print("hype_reload_rc_files() called but no kernel is running", arg_type="ERROR")
        return

    l_user_ns: dict[str, Any] = g_app.kernel.shell.user_ns

    l_global_rc_path: str = os.path.join(community_base.ida_user_dir(), g_rc_filename)
    _load_one_rc_file(l_global_rc_path, l_user_ns)

    l_local_rc_path: Optional[str] = _local_rc_path()
    if l_local_rc_path is not None:
        _load_one_rc_file(l_local_rc_path, l_user_ns)
    else:
        community_base.log_print("HYPE: no IDB open (or path unknown) - skipping local rc file lookup", arg_type="INFO")

def _run_kernel() -> None:
    global g_app, g_shell_port, g_iopub_port, g_stdin_port, g_hb_port, g_control_port
    global g_connection_file

    try:
        l_base_port: int = _find_free_port_block(g_bind_ip)
        g_shell_port = l_base_port
        g_iopub_port = l_base_port + 1
        g_stdin_port = l_base_port + 2
        g_hb_port = l_base_port + 3
        g_control_port = l_base_port + 4

        if l_base_port == g_default_shell_port:
            g_connection_file = os.path.join(community_base.ida_user_dir(), "hype_jupyter_connection.json")
        else:
            g_connection_file = os.path.join(community_base.ida_user_dir(), f"hype_jupyter_connection_{os.getpid()}.json")
            community_base.log_print(f"HYPE: default port {g_default_shell_port} was taken - using port block {l_base_port} and connection file {g_connection_file}", arg_type="INFO")

        os.makedirs(os.path.dirname(g_connection_file), exist_ok=True)
        community_base.log_print(f"Creating IPKernelApp instance on base port {l_base_port}", arg_type="DEBUG")
        l_app: IPKernelApp = IPKernelApp.instance(
            connection_file=g_connection_file,
            ip=g_bind_ip,
            transport="tcp",
            shell_port=g_shell_port,
            iopub_port=g_iopub_port,
            stdin_port=g_stdin_port,
            control_port=g_control_port,
            hb_port=g_hb_port,
            kernel_class=MainThreadKernel,
        )

        # community_base.log_print("calling app.initialize()", arg_type="DEBUG")
        l_app.initialize(argv=[])
        # community_base.log_print("app.initialize() returned OK", arg_type="DEBUG")

        l_app.session.key = secrets.token_hex(32).encode() if g_use_auth else b""
        l_app.write_connection_file()  # persist the fixed ip/ports/key to disk
        community_base.log_print(f"Wrote connection file to {l_app.connection_file}", arg_type="DEBUG")

        try:
            with open(l_app.connection_file, encoding="utf-8") as l_f:
                l_actual: dict[str, Any] = json.load(l_f)
            community_base.log_print(f"Connection file contents: {json.dumps(l_actual)}", arg_type="INFO")
        except Exception:
            community_base.log_print(f"Could not read back connection file for verification\n{traceback.format_exc()}", arg_type="ERROR")

        g_app = l_app

        community_base.log_print(f"Jupyter Kernel is up - listening on tcp://{g_bind_ip} (shell={g_shell_port})", arg_type="INFO")
        community_base.log_print(f'On the host, run: jupyter console --existing "{g_connection_file}"', arg_type="INFO")

        # Make hype_reload_rc_files() callable directly from inside the console
        # itself (as a bare name, no import needed), then run it once now
        # to load the initial global + local hyperc.py files. Both the
        # injection and the rc files themselves must run on IDA's main
        # thread, same as any other idc/idaapi-touching code.
        def _prime_rc_files() -> None:
            l_app.kernel.shell.user_ns["hype_reload_rc_files"] = hype_reload_rc_files
            hype_reload_rc_files()

        run_on_main_thread(_prime_rc_files)

        l_app.start()  # blocks this thread; runs the kernel's own asyncio loop
        community_base.log_print("app.start() returned - kernel loop exited unexpectedly", arg_type="WARNING")

    except Exception:
        community_base.log_print(f"kernel thread crashed\n{traceback.format_exc()}", arg_type="ERROR")

def start_kernel() -> None:
    global g_kernel_thread

    if g_kernel_thread is not None and g_kernel_thread.is_alive():
        community_base.log_print("start_kernel() called but a kernel thread is already running", arg_type="WARNING")
        return
    community_base.log_print("Starting kernel thread", arg_type="INFO")
    g_kernel_thread = threading.Thread(target=_run_kernel, name="ida-jupyter-kernel", daemon=True)
    g_kernel_thread.start()

def stop_kernel() -> None:
    """ The kernel thread is a daemon thread; it'll be torn down with IDA.
    """
    community_base.log_print("stop_kernel() called", arg_type="DEBUG")

    if g_connection_file:
        os.remove(g_connection_file)

class hype_plugmod_t(community_base._ida_idaapi.plugmod_t):
    ''' This is the code that is actually run. Starting the kernel here is the PLUGIN_MULTI equivalent of the old plugin_t.init(). '''

    def __init__(self) -> None:
        try:
            start_kernel()
        except Exception:
            community_base.log_print(f"plugmod __init__() failed to start the kernel\n{traceback.format_exc()}", arg_type="ERROR")
        return

    def run(self, arg_user_argument: int) -> int:
        del arg_user_argument
        community_base.log_print(f'The Jupyter Kernel is started when the plugin is loaded. Use jupyter console --existing "{g_connection_file}" to connect.', arg_type="INFO")
        return 0

    def __del__(self) -> None:
        ''' This code is run when the user closes the IDB '''
        stop_kernel()
        return

class hype_plugin_t(community_base._ida_idaapi.plugin_t):
    ''' This is the config for the plugin, the actual code is in hype_plugmod_t() '''
    flags = community_base._ida_idaapi.PLUGIN_MULTI  # if this flag is set, then init have to return a ida_idaapi.plugmod_t()
    comment = f"HYPE (Here's Your Python Executor) - A Jupyter Kernel for IDA Pro. Version {__version__}"
    help = f'Connect from a host with: jupyter console --existing "{os.path.join(community_base.ida_user_dir(), "hype_jupyter_connection.json")}" (or the PID-specific variant if the default port was taken)'
    wanted_name = "HYPE"
    wanted_hotkey = ""

    def init(self) -> Optional[community_base._ida_idaapi.plugmod_t]:
        ''' We can do checking and if we don't want to be loaded, we can return None.
        If we want to be loaded, then we return a ida_idaapi.plugmod_t
        '''
        return hype_plugmod_t()

def PLUGIN_ENTRY() -> community_base._ida_idaapi.plugin_t:
    return hype_plugin_t()
