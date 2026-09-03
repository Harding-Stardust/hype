# HYPE — Here's Your Python Executor

A real Jupyter kernel running *inside* IDA Pro, so you can drive `idc`/`idaapi`/`ida_*` (and anything built on top of them, like [community_base](https://github.com/Harding-Stardust/community_base) from a proper Jupyter console with support for tab completion, history, rich output, multiple simultaneous clients.

Two plugins with different responsibilites:

| Plugin | What it does |
|---|---|
| **`hype.py`** | Starts the actual `ipykernel` inside IDA on a fixed connection file. This is the whole thing — a socket you can connect to from anywhere. No UI. |
| **`hype_qtconsole.py`** | *Optional.* A dockable Qt widget inside IDA that connects to the kernel started by `hype.py`, so you get a Jupyter console docked in the IDA window itself instead of (or in addition to) an external terminal. |

You only need `hype.py` to get a working kernel. `hype_qtconsole.py` is a convenience client for people who want the console embedded in IDA rather than in a separate window.

## Why

IDA's built-in Python console is fine for one-liners but has no real tab completion, no persistent rich history, no `%magic`, and only one client at a time. HYPE gives you a powerful `ipykernel` so you can connect `jupyter console`, `jupyter qtconsole`, JupyterLab (untested), VS Code's Jupyter extension (untested), or anything else that speaks the Jupyter protocol, straight into a live IDA session, from the same machine or over the network.

## Architecture

- `hype.py` starts an `ipykernel` on a background thread with fixed, predictable ports, and writes a standard Jupyter connection file so any Jupyter client can attach.
- IDA's API is only safe to call from IDA's *main* thread. The kernel's networking (zmq, message dispatch, heartbeat) has to stay on its own thread. `MainThreadKernel` bridges this: every cell you execute is transparently hopped over to IDA's main thread via `community_base.idaapi_execute_sync()`, run there, and the result is hopped back so there is no manual wrapping needed in your own code.
- Because of this, long-running cells block IDA's UI for their duration, exactly like any other synchronous IDA script would.
- `hype_qtconsole.py` never starts a kernel itself. It just loads a connection file and opens a `qtconsole` client against whatever kernel `hype.py` already has running, the same thing `jupyter console --existing <file>` does, but docked inside IDA.

### Port handling

HYPE tries a fixed default port block first (`17001`–`17005`: shell/iopub/stdin/hb/control) so the common single-IDA-instance case always lands on the same, predictable ports. If that block is already taken (most likely by another IDA process also running HYPE) it then searches upward in steps of 1000 until it finds a free block, and writes a PID-suffixed connection file (`hype_jupyter_connection_<pid>.json`) instead of the default one. `hype_qtconsole.py` resolves this automatically: it looks for the PID-specific file for the current IDA process first and falls back to the default file. This is so you can have multiple IDA processes running at the same time and still connect to each of the Jupyter kernels.

### Authentication

The kernel session is HMAC-authenticated by default using a random key generated per kernel start and stored in the connection file, same as any standard Jupyter kernel.

If you have your setup in a LAN that no one else can reach, you can turn off the authentication with just setting `g_use_auth = False` in `hype.py`

### rc files

On startup (and on demand), HYPE loads:

1. A global `hyperc.py` next to your IDA user directory (Found by `community_base.ida_user_dir()`).
2. A local, per-IDB `hyperc.py` sitting next to the currently open database (if one is open).

Both are `exec()`'d directly into the kernel's own namespace, so anything they define or import is immediately available in every cell you type afterwards — handy for auto-importing `community_base`, project-specific helpers, etc. Call `hype_reload_rc_files()` from inside the console at any time to re-run both without restarting IDA (useful while you're actively editing your rc file).

## Requirements

- IDA Pro 9.x (atm only tested on 9.4), with IDA's bundled Python (3.14) on Windows 10.
- [community_base](https://github.com/Harding-Stardust/community_base) required by both plugins since it is my glue between my code and IDAs Python API.
- `hype.py`:
  ```
  pip install --upgrade ipykernel
  ```
- `hype_qtconsole.py` (only if you want the docked widget):
  ```
  pip install --upgrade qtconsole jupyter_client
  ```

Make sure you are installing the packages in the virtual environment that IDA is running in.

## Installation

Drop `hype.py` (and, optionally, `hype_qtconsole.py`) into your IDA plugins folder, e.g.:

```python
import idaapi; print(idaapi.get_ida_subdirs("plugins")[0]) # On Windows that is %APPDATA%\Hex-Rays\IDA Pro\plugins\
```

Restart IDA. `hype.py` starts its kernel automatically when it loads.

## Usage

### Connect from outside IDA Pro

`hype.py` prints the connection file path to the log on startup. Point any Jupyter client at it:

```
jupyter console --existing "%APPDATA%\Hex-Rays\IDA Pro\hype_jupyter_connection.json"
```

Or `jupyter qtconsole --existing ...`, or open it from JupyterLab (untested), VS Code (untested), etc. If the default port block was taken (e.g. a second IDA instance), use the PID-specific file instead. The log message on startup tells you exactly which file to use.

### Connect from inside IDA Pro (docked console)

With `hype_qtconsole.py` installed, open **Edit → Plugins → HYPE Qt Console** (default hotkey `Ctrl-Alt-J`). This docks a window inside IDA connected to the same kernel `hype.py` already started, just another client on the same session. You can have this docked console *and* an external `jupyter console` attached at the same time; they share state.

The docked console uses qtconsole's built-in dark theme by default but it is easy to turn off by settings `_G_USE_DARK_STYLE = False` at the top of `hype_qtconsole.py`.

## Notes

- Every code you run (from any client) executes on IDA's main thread and will block IDA's UI while it runs, same as `idc.exec()`/`idaapi.execute_sync`. This is unavoidable given IDA's threading model; it's not a bug in HYPE.
- Both plugins use the `PLUGIN_MULTI` model (one instance per open database), matching IDA 9.x's multi-database plugin architecture.

## Credits

I would want to give a huge thank you to [ipyida](https://github.com/eset/ipyida) by ESET.
I love that plugin but it has given me so much headache in the past, specially that it requires very outdated Jupyter-client (`jupyter-client<6.1.13`) so I wrote this as much as a fix as a tribute!


## License

GPL 3.0
