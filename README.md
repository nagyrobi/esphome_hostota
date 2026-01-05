# esphome_hostota

A standalone C++17 application that emulates the ESPHome/Arduino OTA server logic on a Linux host.  
It listens for OTA invitations on the usual ESPHome port, authenticates with the same PBKDF2/SHA256 challenge used by ESPHome devices, pulls the pushed binary from the builder, rotates backups, and relaunches the updated binary without requiring elevated privileges.

## Features

- Listens on the ESPHome OTA UDP port and follows the same invitation/authentication flow as ESPHome firmware.
- Accepts binaries pushed by the ESPHome builder (`espota.py`) and validates the MD5 reported by the client.
- Stores incoming binaries in a configurable temporary directory before promoting them.
- Gracefully stops the previous binary, rotates backups with timestamped filenames, and enforces a retention count.
- Moves the freshly downloaded binary into the configured running path, marks it executable, and starts it (optionally daemonized).
- Optional exit after launching the new binary so you can hand off control entirely to the updated artifact.

## Building

Requirements:
- A C++17-capable compiler (tested with `g++`)
- OpenSSL development headers (`libssl-dev` on Debian/Ubuntu)

Build with:

```bash
make
```

This produces the `esphome_hostota` binary in the repository root.

## Configuration

The server uses a simple `key=value` configuration file. It is searched in this order:
1. Directory of the executable (`./esphome_hostota.conf`)
2. `./config/esphome_hostota.conf` relative to the binary
3. `/etc/esphome_hostota.conf`
4. `/etc/esphome_hostota/esphome_hostota.conf`
5. `~/.config/esphome_hostota.conf`

If no configuration file is found, the server logs a warning and runs with safe defaults. Create one using `config.example.conf` as a reference:

```ini
# Example configuration
ota_port=3232               # UDP port to listen on
ota_password=supersecret    # Leave empty for no authentication
bind_address=0.0.0.0        # Interface to bind on
running_path=/opt/esphome_hostota/bin/host_firmware
backup_path=/opt/esphome_hostota/backups
temp_path=/opt/esphome_hostota/tmp
backup_keep=10              # number of backups to retain
run_in_background=false     # daemonize after start
exit_after_exec=false       # stop the OTA server after launching the new binary
```

## Running

Basic usage:

```bash
./esphome_hostota
```

Options:
- `-c <path>`: Explicit configuration file path.
- `--foreground`: Force foreground mode even if `run_in_background=true` in the config.
- `-h` / `--help`: Show a short help message.

### Additional configuration

- `running_filename`: When `running_path` points to a directory, override the filename for the incoming binary (the file pushed by OTA will be renamed to this).
- `watchdog_interval_seconds`: Periodic interval (in seconds) for the watchdog to check the configured binary. Set to `0` or negative to disable. Default: `30`.
- `log_path`: Path for the application log file. Defaults to `/var/log/esphome_hostota.log`. The server writes human-readable timestamps and log levels to both stderr and this file when configured.

The process will:
1. Listen on the configured OTA port (default `3232`) and respond to ESPHome/`espota.py` invitations.
2. If a password is set, issue an `AUTH <nonce>` challenge; otherwise respond with `OK`.
3. Pull the binary from the builder over TCP, acknowledging chunks and validating the reported MD5.
4. Stop any previously launched binary (tracked via a PID file next to `running_path`), move it to `backup_path/bak_<timestamp>`, and keep only the configured number of backups.
5. Promote the new binary to `running_path`, ensure it is executable, and launch it. If `exit_after_exec=true`, the OTA server terminates afterward.

## Notes

- The OTA server uses only unprivileged ports and standard Linux APIs—no root privileges required.
- MD5 validation matches the ESPHome/Arduino OTA protocol to catch corrupted transfers.
- If you are running on embedded Linux, ensure OpenSSL is available or cross-compile with an appropriate toolchain.
