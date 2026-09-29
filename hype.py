r"""
HYPE (Here's Your Python Executor) - A Jupyter Kernel for IDA Pro.

It starts a real ipykernel using a FIXED connection file (same ip/ports every time IDA starts). From your host, point jupyter at the same fixed json file.

jupyter console --existing "%APPDATA%\Hex-Rays\IDA Pro\hype_jupyter_connection.json"

This plug in has no qtconsole widget and no window inside IDA, it is purely a socket you connect to from outside.
If you want to use a widget, you can use the plugin named "hype_qtconsole.py" to create a widget that connects to the kernel.

Requirements:
pip install --upgrade ipykernel

Long-running code will block IDA's UI for their duration while they run on the main thread, exactly like any other synchronous IDA script.

By default the kernel only listens on 127.0.0.1. Set g_bind_to_lan = True (or g_bind_ip_override) to make it reachable from other hosts.

At startup, hyperc.py in the IDA user dir (community_base.ida_user_dir()) is executed in the kernel's namespace. A hyperc.py next to an IDB is
deliberately NOT executed - it comes from wherever the IDB came from. If you want per-IDB setup, do it from the global hyperc.py
(e.g. by looking at community_base.input_file.idb_path).
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

import os
import re
import sys
import json
import errno
import atexit
import signal
import asyncio
import inspect
import threading
import socket
import traceback
import secrets
from contextlib import contextmanager
from collections.abc import Callable, Iterator
from typing import Any, Optional, TypeVar
try:
    import community_base  # https://github.com/Harding-Stardust/community_base
except Exception:
    print(f"{__file__}: Failed to import community_base. You need to install it from https://github.com/Harding-Stardust/community_base")
    raise

try:
    import zmq
    import ipykernel
    from ipykernel.kernelapp import IPKernelApp
    from ipykernel.ipkernel import IPythonKernel
    from ipykernel.zmqshell import ZMQInteractiveShell
    # community_base.log_print(f"ipykernel imported OK, version {getattr(ipykernel, '__version__', 'unknown')}", arg_type="DEBUG")
except Exception:
    community_base.log_print(f"failed to import ipykernel - it is probably not installed: pip install --upgrade ipykernel\n{traceback.format_exc()}", arg_type="ERROR")
    raise

_G_IDAPYTHON_VERSION: Optional[str] = getattr(sys.modules.get("__main__"), "IDAPYTHON_VERSION", None)
community_base.log_print("all imports OK, module ready", arg_type="INFO")

# ------------------------
#         Config
# ------------------------

g_default_shell_port: int = 17001
g_use_auth: bool = True  # Ignored (forced to True) when binding to anything other than loopback
g_rc_filename: str = "hyperc.py"

# Network exposure. Default is loopback only.
g_bind_to_lan: bool = False  # True = bind to the address gethostbyname(gethostname()) resolves to
g_bind_ip_override: Optional[str] = None  # Set to a specific address (e.g. "192.168.1.10") to bind exactly there. Wins over g_bind_to_lan

# ipykernel replaces sys.stdout/stderr/displayhook/excepthook and sys.modules["__main__"] for the whole process during initialize().
# When True, IDA's originals are put back right after initialize() and the kernel's versions are only swapped in while a kernel
# request (cell, completion, inspection) is running on IDA's main thread. That keeps IDA's Output window, excepthook and __main__ intact.
g_isolate_ida_io: bool = True

g_port_search_step: int = 1000
g_port_search_max_attempts: int = 20
g_port_span: int = 5  # shell, iopub, stdin, hb, control

g_connection_file_basename: str = "hype_jupyter_connection"

# These are resolved at kernel startup time in _run_kernel(), since which port block (and therefore which connection file)
# we end up on depends on whether another HYPE instance is already running in another IDA process.
g_connection_file: str | None = None
g_shell_port: int | None = None
g_iopub_port: int | None = None
g_stdin_port: int | None = None
g_hb_port: int | None = None
g_control_port: int | None = None

def _is_loopback(arg_ip: str) -> bool:
    return arg_ip.startswith("127.") or arg_ip in ("::1", "localhost")

def _resolve_bind_ip() -> str:
    """
    Pick the IP the kernel binds to (and that clients use to reach it).

    Loopback unless the user explicitly opted in to network exposure with g_bind_ip_override or g_bind_to_lan (see the Config section above).
    gethostbyname(hostname) can fail or return an address that is not reachable from remote hosts; fall back to loopback in that case.
    """
    if g_bind_ip_override:
        return g_bind_ip_override

    if not g_bind_to_lan:
        return "127.0.0.1"

    try:
        l_ip: str = socket.gethostbyname(socket.gethostname())
        if l_ip:
            return l_ip
    except OSError:
        pass
    community_base.log_print("Could not resolve bind IP from hostname; using 127.0.0.1", arg_type="WARNING")
    return "127.0.0.1"

g_bind_ip: str = _resolve_bind_ip()

def _remove_file_quietly(arg_path: Optional[str]) -> None:
    if not arg_path:
        return
    try:
        os.remove(arg_path)
    except FileNotFoundError:
        pass
    except OSError:
        community_base.log_print(f"Could not remove {arg_path}\n{traceback.format_exc()}", arg_type="WARNING")

def _port_is_free(arg_bind_ip: str, arg_port: int) -> bool:
    """ True if nothing is listening on arg_port and we are able to bind it ourselves. """
    l_check_ip: str = arg_bind_ip if arg_bind_ip != "0.0.0.0" else "127.0.0.1"

    # 1) Is someone listening there?
    l_sock: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        l_sock.settimeout(0.2)
        if l_sock.connect_ex((l_check_ip, arg_port)) == 0:
            return False  # something answered - port taken
    except OSError:
        pass  # connect errors mean "nobody listening", the bind test below decides
    finally:
        l_sock.close()

    # 2) Can we actually bind it? Catches ports that are bound but not listening, bound on the wildcard address,
    #    and Windows' excluded port ranges (Hyper-V/WSL reservations), none of which the connect test sees.
    l_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            l_sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)  # type: ignore[attr-defined]
        l_sock.bind((arg_bind_ip, arg_port))
    except OSError:
        return False
    finally:
        l_sock.close()
    return True

def _port_block_is_free(arg_ip: str, arg_base_port: int, arg_span: int = g_port_span) -> bool:
    """ Return True if all of arg_base_port .. arg_base_port + arg_span - 1 are free on arg_ip. """
    return all(_port_is_free(arg_ip, arg_base_port + l_offset) for l_offset in range(arg_span))

def _find_free_port_block(arg_ip: str, arg_first_attempt: int = 0) -> tuple[int, int]:
    """
    Prefer the default fixed base port (so the common single-IDA case always gets the same, predictable port block). If that block is taken - most
    likely by another HYPE instance in another IDA process - search upward in steps of g_port_search_step until a free block is found.

    Returns (attempt_index, base_port). arg_first_attempt lets the caller skip blocks that turned out to be unusable after all
    (another process grabbed them between our probe and ipykernel's bind).
    """
    for l_attempt in range(arg_first_attempt, g_port_search_max_attempts):
        l_candidate: int = g_default_shell_port + l_attempt * g_port_search_step
        if _port_block_is_free(arg_ip, l_candidate):
            return l_attempt, l_candidate
    raise RuntimeError(
        f"HYPE: could not find a free port block after {g_port_search_max_attempts} attempts "
        f"starting at {g_default_shell_port} (step {g_port_search_step})"
    )

def _is_addr_in_use(arg_exc: BaseException) -> bool:
    """ True if arg_exc is a bind failure that is worth retrying on another port block. """
    l_codes: set[int] = {errno.EADDRINUSE, errno.EACCES, 10048, 10013}  # 10048 = WSAEADDRINUSE, 10013 = WSAEACCES (excluded port range)
    l_zmq_code: Optional[int] = getattr(zmq, "EADDRINUSE", None)
    if l_zmq_code is not None:
        l_codes.add(l_zmq_code)
    return isinstance(arg_exc, (zmq.ZMQError, OSError)) and getattr(arg_exc, "errno", None) in l_codes

def _pid_is_alive(arg_pid: int) -> bool:
    if os.name == "nt":
        # NOTE: os.kill(pid, 0) on Windows calls TerminateProcess() - never use it as a liveness check there.
        import ctypes
        from ctypes import wintypes
        l_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        l_k32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        l_k32.OpenProcess.restype = wintypes.HANDLE
        l_k32.GetExitCodeProcess.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
        l_k32.GetExitCodeProcess.restype = wintypes.BOOL
        l_k32.CloseHandle.argtypes = (wintypes.HANDLE,)
        l_k32.CloseHandle.restype = wintypes.BOOL

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        STILL_ACTIVE = 259
        ERROR_ACCESS_DENIED = 5

        l_handle = l_k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, arg_pid)
        if not l_handle:
            return ctypes.get_last_error() == ERROR_ACCESS_DENIED  # exists but we may not look at it
        try:
            l_code = wintypes.DWORD()
            if not l_k32.GetExitCodeProcess(l_handle, ctypes.byref(l_code)):
                return True  # can't tell - assume alive so we never delete a live instance's file
            return l_code.value == STILL_ACTIVE
        finally:
            l_k32.CloseHandle(l_handle)

    try:
        os.kill(arg_pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True

def _cleanup_stale_pid_connection_files() -> None:
    """ Remove hype_jupyter_connection_<pid>.json files left behind by IDA processes that no longer exist (e.g. after a crash). """
    l_dir: str = community_base.ida_user_dir()
    l_pattern = re.compile(rf"^{re.escape(g_connection_file_basename)}_(\d+)\.json$")
    try:
        l_names: list[str] = os.listdir(l_dir)
    except OSError:
        return
    for l_name in l_names:
        l_match = l_pattern.match(l_name)
        if not l_match:
            continue
        l_pid: int = int(l_match.group(1))
        if l_pid == os.getpid() or _pid_is_alive(l_pid):
            continue
        community_base.log_print(f"Removing stale connection file {l_name} (pid {l_pid} is gone)", arg_type="INFO")
        _remove_file_quietly(os.path.join(l_dir, l_name))

# ---------------------------------------------------------------------------
# signal.signal() only works on the interpreter's main thread. ipykernel calls it during startup and on every shell dispatch (pre_handler_hook).
# Since the kernel's networking runs on a worker thread here, make those calls a safe no-op instead of letting them raise and kill the thread.
# Guarded so that reloading this module does not wrap the wrapper again.
# ---------------------------------------------------------------------------
if getattr(signal.signal, "_hype_safe_signal", False):
    g_orig_signal: Callable[[signal.Signals | int, Any], Any] = signal.signal._hype_orig_signal  # type: ignore[attr-defined]
else:
    g_orig_signal = signal.signal
T = TypeVar("T")

def _safe_signal(arg_sig: signal.Signals | int, arg_handler: Any) -> Any:
    if threading.current_thread() is not threading.main_thread():
        # community_base.log_print(f"signal.signal({arg_sig!r}, ...) suppressed - not on the main thread", arg_type="DEBUG")
        return None
    return g_orig_signal(arg_sig, arg_handler)

_safe_signal._hype_safe_signal = True  # type: ignore[attr-defined]
_safe_signal._hype_orig_signal = g_orig_signal  # type: ignore[attr-defined]
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
    l_ret: Any = community_base._idaapi_execute_sync(runner, community_base._ida_kernwin.MFF_WRITE)

    if "exc" in l_box:
        raise l_box["exc"]
    if "result" not in l_box:
        raise RuntimeError(f"HYPE: execute_sync() did not run the request on IDA's main thread (returned {l_ret!r}) - is IDA shutting down?")
    return l_box["result"]

def _run_coroutine_on_main_thread(arg_coro: Any) -> Any:
    """
    Run an awaitable on IDA's main thread without nesting inside a running loop.

    A private loop is used per call and it is never installed with set_event_loop(), so whatever event loop the main thread
    already had (e.g. another plugin's) is left alone. Code inside the coroutine still sees this loop via get_running_loop()/get_event_loop().
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        pass
    else:
        if hasattr(arg_coro, "close"):
            arg_coro.close()  # avoid "coroutine was never awaited"
        raise RuntimeError("IDA main thread already has a running asyncio event loop; cannot execute kernel cell safely")

    l_loop: asyncio.AbstractEventLoop = asyncio.new_event_loop()
    try:
        return l_loop.run_until_complete(arg_coro)
    finally:
        try:
            l_loop.run_until_complete(l_loop.shutdown_asyncgens())
        except Exception:
            pass
        l_loop.close()

# ---------------------------------------------------------------------------
# Process-wide IO state (see g_isolate_ida_io)
# ---------------------------------------------------------------------------
_IO_SYS_ATTRS: tuple[str, ...] = ("stdout", "stderr", "displayhook", "excepthook")

def _capture_io() -> dict[str, Any]:
    l_state: dict[str, Any] = {l_name: getattr(sys, l_name) for l_name in _IO_SYS_ATTRS}
    l_state["__main__"] = sys.modules.get("__main__")
    return l_state

def _apply_io(arg_state: Optional[dict[str, Any]]) -> None:
    if not arg_state:
        return
    for l_name, l_value in arg_state.items():
        if l_name == "__main__":
            if l_value is not None:
                sys.modules["__main__"] = l_value
        else:
            setattr(sys, l_name, l_value)

def _flush_quietly(arg_stream: Any) -> None:
    try:
        if arg_stream is not None:
            arg_stream.flush()
    except Exception:
        pass

def _get_kernel_io() -> dict[str, Any]:
    """ The kernel's stdout/stderr/displayhook/__main__ captured by _initialize_app() (empty if not isolating or not started yet). """
    l_app: Optional[IPKernelApp] = _get_app()
    return getattr(l_app, "_hype_kernel_io", None) or {}

@contextmanager
def _kernel_io() -> Iterator[None]:
    """
    While a kernel request runs on IDA's main thread, point stdout/stderr/displayhook/__main__ at the kernel's versions so output goes to the
    Jupyter client, then put back whatever was there before. Re-entrant (hype_reload_rc_files() called from a cell just nests).
    """
    l_kernel_io: dict[str, Any] = _get_kernel_io()
    if not g_isolate_ida_io or not l_kernel_io:
        yield
        return

    l_previous: dict[str, Any] = {l_name: (sys.modules.get("__main__") if l_name == "__main__" else getattr(sys, l_name)) for l_name in l_kernel_io}
    _apply_io(l_kernel_io)
    try:
        yield
    finally:
        # ipykernel flushes sys.stdout/stderr on the kernel thread after do_execute() returns - by then IDA's streams are back,
        # so flush the kernel streams here to make sure all output reaches the client before the execute_reply / idle status.
        _flush_quietly(l_kernel_io.get("stdout"))
        _flush_quietly(l_kernel_io.get("stderr"))
        _apply_io(l_previous)

class MainThreadKernel(IPythonKernel):
    """
    IPython kernel whose cell execution runs on IDA's main thread, since idc/idaapi (and anything built on it) can only be called safely from there.
    Networking (zmq/asyncio) stays on the background kernel thread; only the actual code execution hops over to IDA's main thread and back.
    """
    def set_parent(self, ident: Any, parent: Any, channel: str = "shell") -> None:
        super().set_parent(ident, parent, channel)
        # ZMQInteractiveShell.set_parent() tags output with the current request via sys.stdout/sys.stderr.set_parent(). With g_isolate_ida_io
        # those are IDA's streams at this point (on the kernel thread), so tag the kernel's own streams too - otherwise clients drop the
        # cell's output because it doesn't belong to their request.
        if channel == "shell":
            l_kernel_io: dict[str, Any] = _get_kernel_io()
            for l_stream in (l_kernel_io.get("stdout"), l_kernel_io.get("stderr")):
                if hasattr(l_stream, "set_parent"):
                    l_stream.set_parent(parent)

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
            with _kernel_io():
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
            with _kernel_io():
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
            with _kernel_io():
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

# State of the kernel, stored on the IPKernelApp singleton itself (as _hype_state) so it survives this module's globals being reset.
_STATE_STARTING: str = "starting"
_STATE_RUNNING: str = "running"
_STATE_STOPPED: str = "stopped"

def _get_app() -> Optional[IPKernelApp]:
    """ The running IPKernelApp. Falls back to the ipykernel singleton in case this module's globals were reset. """
    if g_app is not None:
        return g_app
    if IPKernelApp.initialized():
        return IPKernelApp.instance()
    return None

# ---------------------------------------------------------------------------
# rc file
# ---------------------------------------------------------------------------
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

    try:
        with open(arg_path, "rb") as l_f:
            l_raw: bytes = l_f.read()
    except Exception:
        community_base.log_print(f"rc file {arg_path} could not be read\n{traceback.format_exc()}", arg_type="ERROR")
        return

    community_base.log_print(f"Loading rc file {arg_path}", arg_type="INFO")
    l_missing: object = object()
    l_previous_file: Any = arg_user_ns.get("__file__", l_missing)
    arg_user_ns["__file__"] = arg_path  # mimic normal module-import behaviour so rc files can use __file__
    try:
        l_code = compile(l_raw, arg_path, "exec")  # bytes: honours a BOM / coding cookie like a normal import does
        exec(l_code, arg_user_ns)  # noqa: S102 - intentional, this is the whole point of an rc file
        community_base.log_print(f"rc file {arg_path} loaded OK", arg_type="INFO")
    except Exception:
        community_base.log_print(f"rc file {arg_path} failed to load\n{traceback.format_exc()}", arg_type="ERROR")
    finally:
        if l_previous_file is l_missing:
            arg_user_ns.pop("__file__", None)
        else:
            arg_user_ns["__file__"] = l_previous_file

def _global_rc_path() -> str:
    return os.path.join(community_base.ida_user_dir(), g_rc_filename)

def hype_reload_rc_files() -> None:
    """
    Re-run the global hyperc.py (in community_base.ida_user_dir()), executed directly in the running kernel's user namespace.
    Callable from within the console itself (it is injected into the kernel's user namespace at startup), so a broken rc file can be fixed on disk and picked up again without restarting IDA:
    hype_reload_rc_files()
    Must run on IDA's main thread (it does when called from a cell).
    """
    l_app: Optional[IPKernelApp] = _get_app()
    if l_app is None or getattr(l_app, "kernel", None) is None or getattr(l_app.kernel, "shell", None) is None:
        community_base.log_print("hype_reload_rc_files() called but no kernel is running", arg_type="ERROR")
        return

    _load_one_rc_file(_global_rc_path(), l_app.kernel.shell.user_ns)

# ---------------------------------------------------------------------------
# Kernel lifecycle
# ---------------------------------------------------------------------------
def _set_idapython_marker(arg_module: Any) -> None:
    ''' ipykernel runs cells in its own user-namespace module (installed as sys.modules["__main__"]), which does not have the
        IDAPYTHON_VERSION attribute that some third party code (correctly) uses to detect "already hosted inside IDA".
        Add it so those checks keep working from inside the Jupyter kernel too.
    '''
    if _G_IDAPYTHON_VERSION is None or arg_module is None:
        return  # We were not inside a real IDAPython session ourselves, nothing to restore

    if getattr(arg_module, "IDAPYTHON_VERSION", None) is not None:
        return  # Already present, do not overwrite it

    arg_module.IDAPYTHON_VERSION = _G_IDAPYTHON_VERSION  # Restore the marker other tools rely on

def _initialize_app(arg_app: IPKernelApp) -> None:
    """ app.initialize(), keeping IDA's process-wide IO state intact when g_isolate_ida_io is set. """
    l_ida_io: dict[str, Any] = arg_app._hype_ida_io  # type: ignore[attr-defined]
    try:
        arg_app.initialize(argv=[])
    except BaseException:
        _apply_io(l_ida_io)  # init_io() may already have replaced sys.stdout/stderr with streams that are about to die
        raise

    l_user_module: Any = getattr(getattr(arg_app, "shell", None), "user_module", None) or sys.modules.get("__main__")
    _set_idapython_marker(l_user_module)

    if g_isolate_ida_io:
        arg_app._hype_kernel_io = {  # type: ignore[attr-defined]
            "stdout": sys.stdout,
            "stderr": sys.stderr,
            "displayhook": sys.displayhook,
            "__main__": l_user_module,
        }
        _apply_io(l_ida_io)  # excepthook included - IPKernelApp's crash handler writes to sys.__stderr__, which is None inside IDA

def _reset_kernel_singletons(arg_app: Optional[IPKernelApp]) -> None:
    """
    Best-effort teardown of a dead/half-initialized kernel so a new one can be created in the same process
    (ipykernel's app, kernel and shell are all process-wide singletons).
    """
    if arg_app is not None:
        try:
            atexit.unregister(arg_app.close)
            arg_app.close()
        except Exception:
            community_base.log_print(f"Closing the old kernel failed (continuing anyway)\n{traceback.format_exc()}", arg_type="DEBUG")
        finally:
            _apply_io(getattr(arg_app, "_hype_ida_io", None))  # close() -> reset_io() sets sys.stdout = sys.__stdout__, which is None inside IDA

    for l_cls in (MainThreadKernel, ZMQInteractiveShell, IPKernelApp):
        try:
            l_cls.clear_instance()
        except Exception:
            community_base.log_print(f"clear_instance() failed for {l_cls.__name__}\n{traceback.format_exc()}", arg_type="DEBUG")

def _ensure_connection_file(arg_app: IPKernelApp) -> None:
    """ Re-create the connection file of a running kernel if it has gone missing. """
    try:
        if not os.path.isfile(arg_app.abs_connection_file):
            arg_app.write_connection_file()
            community_base.log_print(f"Re-wrote missing connection file {arg_app.abs_connection_file}", arg_type="INFO")
    except Exception:
        community_base.log_print(f"Could not re-write the connection file\n{traceback.format_exc()}", arg_type="ERROR")

def _run_kernel() -> None:
    global g_app, g_shell_port, g_iopub_port, g_stdin_port, g_hb_port, g_control_port
    global g_connection_file

    l_app: Optional[IPKernelApp] = None
    try:
        _cleanup_stale_pid_connection_files()

        l_use_auth: bool = g_use_auth
        if not l_use_auth and not _is_loopback(g_bind_ip):
            community_base.log_print(f"g_use_auth is False but the kernel binds to {g_bind_ip}, which is reachable from the network. Refusing to run unauthenticated - enabling auth.", arg_type="WARNING")
            l_use_auth = True

        l_first_attempt: int = 0
        while True:
            l_attempt, l_base_port = _find_free_port_block(g_bind_ip, l_first_attempt)
            g_shell_port = l_base_port
            g_iopub_port = l_base_port + 1
            g_stdin_port = l_base_port + 2
            g_hb_port = l_base_port + 3
            g_control_port = l_base_port + 4

            if l_base_port == g_default_shell_port:
                g_connection_file = os.path.join(community_base.ida_user_dir(), f"{g_connection_file_basename}.json")
            else:
                g_connection_file = os.path.join(community_base.ida_user_dir(), f"{g_connection_file_basename}_{os.getpid()}.json")
                community_base.log_print(f"HYPE: default port {g_default_shell_port} was taken - using port block {l_base_port} and connection file {g_connection_file}", arg_type="INFO")

            os.makedirs(os.path.dirname(g_connection_file), exist_ok=True)

            # A leftover file (e.g. IDA crashed last time) would be *loaded* by ipykernel's init_connection_file(): it takes the ip
            # (and key) from it, so a changed LAN IP makes the bind fail, and a corrupt file makes ipykernel call self.exit(1).
            # The port block is free, so no live kernel is using this file.
            _remove_file_quietly(g_connection_file)

            community_base.log_print(f"Creating IPKernelApp instance on base port {l_base_port}", arg_type="DEBUG")
            l_app = IPKernelApp.instance(
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
            l_app._hype_state = _STATE_STARTING  # type: ignore[attr-defined]
            l_app._hype_ida_io = _capture_io()  # type: ignore[attr-defined]

            try:
                # community_base.log_print("calling app.initialize()", arg_type="DEBUG")
                _initialize_app(l_app)
                # community_base.log_print("app.initialize() returned OK", arg_type="DEBUG")
            except Exception as l_exc:
                # Someone grabbed one of the ports between our probe and ipykernel's bind - try the next block.
                if _is_addr_in_use(l_exc) and l_attempt + 1 < g_port_search_max_attempts:
                    community_base.log_print(f"Port block {l_base_port} became unavailable during startup ({l_exc}), trying the next one", arg_type="WARNING")
                    _reset_kernel_singletons(l_app)
                    l_app = None
                    l_first_attempt = l_attempt + 1
                    continue
                raise
            break

        l_app.session.key = secrets.token_hex(32).encode() if l_use_auth else b""
        l_app.write_connection_file()  # persist the fixed ip/ports/key to disk
        atexit.register(_remove_file_quietly, l_app.abs_connection_file)
        community_base.log_print(f"Wrote connection file to {l_app.connection_file}", arg_type="DEBUG")

        try:
            with open(l_app.connection_file, encoding="utf-8") as l_f:
                l_actual: dict[str, Any] = json.load(l_f)
            l_redacted: dict[str, Any] = {k: ("<redacted>" if k in ("key", "curve_secretkey") and v else v) for k, v in l_actual.items()}
            community_base.log_print(f"Connection file contents: {json.dumps(l_redacted)}", arg_type="INFO")
        except Exception:
            community_base.log_print(f"Could not read back connection file for verification\n{traceback.format_exc()}", arg_type="ERROR")

        g_app = l_app

        community_base.log_print(f"Jupyter Kernel is up - listening on tcp://{g_bind_ip} (shell={g_shell_port})", arg_type="INFO")
        community_base.log_print(f'On the host, run: jupyter console --existing "{g_connection_file}"', arg_type="INFO")

        # Make hype_reload_rc_files() callable directly from inside the console
        # itself (as a bare name, no import needed), then run it once now
        # to load the global hyperc.py file. Both the
        # injection and the rc files themselves must run on IDA's main
        # thread, same as any other idc/idaapi-touching code.
        def _prime_rc_files() -> None:
            l_app.kernel.shell.user_ns["hype_reload_rc_files"] = hype_reload_rc_files
            hype_reload_rc_files()

        run_on_main_thread(_prime_rc_files)

        l_app._hype_state = _STATE_RUNNING  # type: ignore[attr-defined]
        l_app.start()  # blocks this thread; runs the kernel's own asyncio loop
        community_base.log_print("app.start() returned - the kernel was shut down (e.g. by a client). It will be restarted when the next IDB is opened, or call hype_claude.start_kernel()", arg_type="WARNING")

    except BaseException:  # SystemExit too - ipykernel uses self.exit() for some startup errors
        community_base.log_print(f"kernel thread crashed\n{traceback.format_exc()}", arg_type="ERROR")
    finally:
        if l_app is not None:
            l_app._hype_state = _STATE_STOPPED  # type: ignore[attr-defined]
            _apply_io(getattr(l_app, "_hype_ida_io", None))  # never leave IDA pointing at a dead kernel's streams

def start_kernel() -> None:
    """ Start the kernel, or - if it is already running - make sure it is usable for the newly opened IDB. Call on IDA's main thread. """
    global g_kernel_thread, g_app, g_connection_file

    if IPKernelApp.initialized():
        # The singleton state on IPKernelApp lives in the ipykernel module, which stays cached in sys.modules for the lifetime of the
        # process. hype's own globals (g_kernel_thread) can get reset when ida_domain opens a new database in the same process, so the
        # singleton (and the _hype_state we keep on it) is the reliable source of truth.
        l_app: IPKernelApp = IPKernelApp.instance()
        l_state: Optional[str] = getattr(l_app, "_hype_state", None)

        if l_state is None:
            community_base.log_print("start_kernel(): an IPKernelApp not created by this plugin already exists in this process (is hype.py also installed?), skipping", arg_type="WARNING")
            return

        if l_state in (_STATE_STARTING, _STATE_RUNNING):
            g_app = l_app
            g_connection_file = str(l_app.abs_connection_file)
            if l_state == _STATE_RUNNING:
                # A new IDB was opened in the same IDA process: the kernel keeps running, make sure clients can still find it.
                _ensure_connection_file(l_app)
                community_base.log_print(f'Kernel already running. Connect with: jupyter console --existing "{g_connection_file}"', arg_type="INFO")
            return

        community_base.log_print("start_kernel(): previous kernel has stopped - tearing it down and starting a new one", arg_type="INFO")
        try:
            _reset_kernel_singletons(l_app)
        except Exception:
            community_base.log_print(f"Could not tear down the old kernel - restart IDA to get a new one\n{traceback.format_exc()}", arg_type="ERROR")
            return
        g_app = None
        g_connection_file = None

    if g_kernel_thread is not None and g_kernel_thread.is_alive():
        community_base.log_print("start_kernel() called but a kernel thread is already running", arg_type="WARNING")
        return

    community_base.log_print("Starting kernel thread", arg_type="INFO")
    g_kernel_thread = threading.Thread(target=_run_kernel, name="ida-jupyter-kernel", daemon=True)
    g_kernel_thread.start()

def stop_kernel() -> None:
    """
    Called when an IDB is closed. The kernel deliberately keeps running (it is a daemon thread that lives as long as IDA does, and it will serve
    the next IDB opened in this process), so its connection file is kept too. The file is removed at process exit (atexit).
    """
    community_base.log_print("stop_kernel() called - kernel keeps running for the next IDB in this IDA process", arg_type="DEBUG")

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
        l_app: Optional[IPKernelApp] = _get_app()
        l_file: Optional[str] = g_connection_file or (str(l_app.abs_connection_file) if l_app is not None else None)
        if l_file:
            community_base.log_print(f'The Jupyter Kernel is started when the plugin is loaded. Use jupyter console --existing "{l_file}" to connect.', arg_type="INFO")
        else:
            community_base.log_print("The Jupyter Kernel is not running (see earlier log messages for why).", arg_type="WARNING")
        return 0

    def __del__(self) -> None:
        ''' This code is run when the user closes the IDB '''
        try:
            stop_kernel()
        except Exception:
            pass
        return

class hype_plugin_t(community_base._ida_idaapi.plugin_t):
    ''' This is the config for the plugin, the actual code is in hype_plugmod_t() '''
    flags = community_base._ida_idaapi.PLUGIN_MULTI  # if this flag is set, then init have to return a ida_idaapi.plugmod_t()
    comment = f"HYPE (Here's Your Python Executor) - A Jupyter Kernel for IDA Pro. Version {__version__}"
    help = f'Connect from a host with: jupyter console --existing "{os.path.join(community_base.ida_user_dir(), g_connection_file_basename + ".json")}" (or the PID-specific variant if the default port was taken)'
    wanted_name = "HYPE"
    wanted_hotkey = ""

    def init(self) -> Optional[community_base._ida_idaapi.plugmod_t]:
        ''' We can do checking and if we don't want to be loaded, we can return None.
        If we want to be loaded, then we return a ida_idaapi.plugmod_t
        '''
        return hype_plugmod_t()

def PLUGIN_ENTRY() -> community_base._ida_idaapi.plugin_t:
    return hype_plugin_t()
