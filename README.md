# NetMosaic Sensor

NetMosaic Sensor is a Windows network telemetry agent built on top of WinDivert and nDPI. It captures packets, performs deep packet inspection, enriches the flow with Lua helpers, and emits structured JSON lines for logging and syslog streaming.

## Project Overview

- **Capture**: WinDivert is used to sniff (or reinject, in active mode) network traffic.
- **Classification**: nDPI 4.6 classifies flows, generates L7 metadata, and surfaces risk flags.
- **Enrichment**: Lua scripts can augment flow records via helper functions (IPs, protocol names, SNI, hashes).
- **Output**: A custom JSON builder writes events to `logs/network.jsonl` and optionally syslog; fields include byte/packet counters, detection changes, risks, and nDPI JSON blobs.
- **Workers**: Packets travel through a ring buffer to worker threads which manage flow tables, TCP termination, and reporting thresholds.

## Required Libraries

The repository embeds the third-party sources that are needed but keeps them unbuilt so you can track upstream releases.

| Library     | Version | Location                                      | Notes |
|-------------|---------|-----------------------------------------------|-------|
| WinDivert   | 2.2     | `libs/windivert/`                             | Provides `WinDivert.dll` and headers. Grab binaries from https://reqrypt.org/windivert.html if you need updated drivers.|
| nDPI        | 4.6     | `libs/nDPI-4.6/`                              | DPI engine; build the static library before compiling the sensor.|
| Lua         | 5.4.x   | `libs/lua/`                                   | Embedded scripting runtime.

### Building nDPI (MSYS2 / MinGW64)

```bash
# from the project root in MSYS2 MinGW64 shell
cd libs/nDPI-4.6
./autogen.sh
./configure --enable-static --disable-shared CC=gcc
make -j$(nproc)
```

After compilation the static library `src/lib/libndpi.a` is what the sensor links against (the Makefile already points to `libs/nDPI-4.6/src/lib`).

### Building Lua (already handled)

`mingw32-make` in the project root builds Lua automatically into `build/lua/liblua.a` using the bundled sources; no manual steps required.

## Building the Sensor with MSYS2 (no Visual Studio)

1. **Install MSYS2** and ensure the MinGW64 toolchain is present:
   ```bash
   pacman -S --needed mingw-w64-x86_64-toolchain
   ```

2. **Open a MinGW64 shell** (not MSYS). Prepend the toolchain path when you build from PowerShell:
   ```powershell
   $env:PATH="C:\\msys64\\mingw64\\bin;C:\\msys64\\mingw64\\lib\\gcc\\x86_64-w64-mingw32\\<gcc-version>;" + $env:PATH
   ```

3. **Build dependencies** (nDPI as described above, WinDivert binaries copied into `libs/windivert/x64`).

4. **Compile the sensor** from the project root:
   ```bash
   mingw32-make
   ```
   This produces `netmosaic_sensor.exe` in the root directory.

   - Use `mingw32-make clean` to remove build artifacts.
   - `mingw32-make build/worker.o` is handy for recompiling a single translation unit.

5. **Runtime files**: place `WinDivert.dll` and `WinDivert32.sys/WinDivert64.sys` next to the executable or install the WinDivert driver globally.

6. **Execution**: run from an elevated prompt for sniffing, e.g.:
   ```powershell
   .\netmosaic_sensor.exe --log-file .\logs\network.jsonl
   ```
   Optional flags include `--include-loopback`, `--active`, and `--stdout-minimal`. Configuration is documented in `src/config.c` usage text.
