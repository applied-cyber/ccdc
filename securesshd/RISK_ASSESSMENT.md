# securesshd

- **Tool to be used:** securesshd
- **Actions:** Deploy a hardened SSH server alongside the existing one by installing a systemd service file and starting it on a designated port.
- **Rationale:** Provides a more secure remote access channel without touching or replacing the existing SSH daemon or any running processes.
- **Risk:** Low - only adds a new systemd service; does not modify, stop, or interfere with any existing services or configuration.
- **Recovery:** Stop and disable the securesshd systemd service.
