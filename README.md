# HiveMind
![HiveMind Logo](assets/hivemind_logo.jpg)

HiveMind is a powerful reverse shell multi-handler designed for managing multiple active sessions efficiently. It supports Windows and Linux payloads, automatic session aliasing, and interactive shell handling with TTY upgrades.

## Features

- Color-coded menu with an intuitive interface
- Help menu accessible via the `help` command
- Payload generation for Windows and Linux reverse shells
- Automatic network interface resolution to an IP address
- Multi-session management with session switching
- Assign aliases to sessions for easier control

## Installation

### Prerequisites

Ensure you have Python installed along with the necessary dependencies:

```bash
pip install termcolor netifaces
```

### Cloning the Repository

```bash
git clone https://github.com/yourusername/HiveMind.git
cd HiveMind
```

## Usage

Run HiveMind with:

```bash
python hivemind.py
```

### Commands

- `alias <id|alias> <new_alias>` – Assign an alias to a session
- `cleanup` – Remove inactive sessions
- `cmd <command>` – Execute a local shell command
- `exit` – Exit HiveMind
- `help` – Show available commands
- `kill <id|alias>` – Kill a session
- `session <id|alias>` – Interact with a specific session
- `sessions` – List all active sessions
- `set payload <Type> <LHOST> [base64]` – Generate a payload
- `show payloads` – List available payloads
- `upgrade <id|alias>` – Upgrade a session to full TTY mode

## Payloads

HiveMind supports various payloads:

- **Windows**:
  - `windows/reverse_tcp/powershell`
  - `windows/conpty`
- **Linux**:
  - `linux/reverse_tcp/bash`
  - `linux/reverse_tcp/python`

To generate a payload, use:

```bash
set payload <payload_type> <LHOST> [base64]
```

Example:

```bash
set payload windows/reverse_tcp/powershell 192.168.1.100
```

## Interactive Shell

To interact with a session, use:

```bash
session <id|alias>
```

To upgrade a session to TTY mode:

```bash
upgrade <id|alias>
```

## License

This project is open-source and available under the [MIT License](LICENSE).

## Disclaimer

HiveMind is intended for educational and authorized penetration testing purposes only. Unauthorized use of this tool is prohibited.
