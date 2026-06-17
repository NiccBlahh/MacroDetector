# MacroDetector

**Advanced forensic detection tool for gaming mouse macro software and configuration files on Windows systems.**

MacroDetector is a comprehensive PowerShell-based scanner that analyzes your Windows system for installed gaming peripheral software, identifies macro-related configuration and data files, parses their contents for macro indicators using pattern-matched keyword analysis, and presents the findings in a compact, color-coded terminal display. Built for esports integrity monitoring, system administration audits, peripheral forensic analysis, and cheating detection in competitive gaming environments.

Unlike simple file watchers or timestamp checkers, MacroDetector performs actual content-level analysis — reading configuration files (JSON, XML, LDB, DAT, BIN, and more), scanning for known macro definition patterns, and correlating findings with live process detection to confirm whether the associated software is actively running.


## Installation

**One-liner (run from CMD):**

```cmd
powershell -ExecutionPolicy Bypass -Command "Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/NiccBlahh/MacroDetector/refs/heads/main/MacroDetector.ps1')"
```

---

## Table of Contents

- [Features](#features)
- [Supported Software](#supported-software)
- [Installation](#installation)
- [Usage](#usage)
- [Example Output](#example-output)
- [How It Works](#how-it-works)
- [Detection Methodology](#detection-methodology)
- [Technical Details](#technical-details)
- [Requirements](#requirements)
- [Notes](#notes)

---

## Features

- **Hardware-Level Detection** — Identifies all connected and historically connected mouse devices via WMI (Windows Management Instrumentation), the Windows Registry Enum tree (HID, USB, BTH, BTHLE), and Bluetooth driver parameters. Each device is cross-referenced against a 50+ entry brand keyword map to identify the manufacturer.

- **Software Discovery** — Scans the Windows Registry Uninstall keys (LocalMachine 64-bit, LocalMachine 32-bit, and CurrentUser) for over 80 known gaming mouse software titles across 16 brands. Displays detected software with version numbers and installation details.

- **Content-Aware Macro Scanning** — Goes beyond filename or timestamp analysis. Opens each discovered configuration file and scans its raw text content for macro-related keywords and patterns:

  - Direct keyword matches: `macro`, `Macro`, `action`, `Action`, `script`, `Script`, `assignment`, `binding`, `command`, `sequence`, `shot`
  - Timing patterns: `"delay": <number>` (JSON-formatted delay values indicating timed macro sequences)
  - Control flow: `"repeat"` (loop/repeat blocks), `"sequence"` (key press sequences)
  - Storage indicators: `"onboard"` (onboard memory flags), `"device"` (device-specific profiles), `"engine"` (engine-linked macros)

- **Process Verification** — For each file flagged as containing macro content, checks whether the corresponding software process is actively running on the system. For example, if a Razer macro file is detected, the tool verifies whether `RazerCentralService.exe`, `Razer Synapse.exe`, or `RazerStats.exe` is currently running, confirming the software is active and the macro could be in use.

- **Intelligent Noise Filtering** — Automatically excludes known non-relevant directories from the scan to reduce false positives and improve scan speed:

  - Browser/Electron cache: `\Cache\`, `\GPUCache\`, `\Code Cache\`
  - Storage backends: `\Session Storage\`, `\IndexedDB\`, `\Service Worker\`
  - Crash reporting: `\Crashpad\`, `\CrashReports\`
  - Dictionaries and other static assets: `\Dictionaries\`, `\GrpcChann`

- **Multi-Directory Probing** — For each detected software title, the tool probes all known installation path variants:

  - `%LOCALAPPDATA%` — Per-user local application data (most common for modern Electron-based apps)
  - `%APPDATA%` — Per-user roaming application data (common for legacy .NET apps and settings)
  - `%PROGRAMDATA%` — Common application data (used by system-level services and drivers)
  - `%USERPROFILE%\Documents` — User documents folder (used by some ASUS and legacy software)

- **Compact Terminal Output** — Color-coded display with ASCII art banner, auto-detected PC owner name, sectioned output for mice, software, directories, scanned files, and macro findings. Uses ANSI colors for improved readability on modern terminals.

- **MD5 Change Detection** — Uses native .NET `System.Security.Cryptography.MD5` to compute file hashes for detecting actual content changes (as opposed to metadata-only changes like timestamp updates).

---

## Supported Software

| Brand | Software Detected | Process Names | Config Extensions |
|-------|-------------------|---------------|-------------------|
| Logitech | G HUB, Gaming Software (Legacy), Logitech Options, Options+, Unifying Software, Bolt Receiver | `LGHUB`, `LGHUB Agent`, `LCore` | `.json`, `.xml`, `.db` |
| Razer | Synapse 3, Synapse 4, Cortex, Central, RazerAppEngine | `Razer Synapse`, `RazerCentralService`, `RazerStats` | `.json`, `.xml`, `.ldb`, `.log` |
| SteelSeries | GG, Engine 3 (Legacy), Engine 2 (Legacy) | `SteelSeriesGG`, `SteelSeriesEngine`, `SteelSeriesEngine3` | `.json` |
| Corsair | iCUE 5, iCUE 4, iCUE (Legacy) | `iCUE`, `CorsairService`, `Cue` | `.cueprofile`, `.json` |
| ASUS | Armoury Crate, AURA | `ArmouryCrate`, `ASUSOptimization` | `.json`, `.xml` |
| HyperX | NGENUITY (Desktop + Store) | `NGENUITY` | `.json` |
| Wooting | Wooting (UAC Helper) | `WootingUACHelper`, `Wooting` | `.json` |
| Glorious | CORE | `GloriousCORE` | `.json` |
| Bloody | Bloody 7, A4Tech | `Bloody7`, `A4Tech` | `.dat`, `.json`, `.xml`, `.bin` |
| Cooler Master | MasterPlus+ | `MasterPlus` | `.json`, `.xml` |
| ROCCAT | Swarm, Titan | `Roccat Swarm`, `Titan` | `.xml`, `.json` |
| Redragon | Gaming Mouse | `Redragon` | `.ini`, `.json` |
| Marvo | BY-COMBO (multiple model variants) | — | `.dct`, `.json` |
| Ajazz | BYCOMBO-2 | — | `.json` |
| Endgame Gear | Software | — | `.db` |
| Finalmouse | Software | — | `.db` |
| Pulsar | Fusion | — | `.json` |
| Kensington | Works | — | `.db` |
| Cougar | UIX | — | `.json` |
| Alienware | Command Center | — | `.json` |
| Fantech | VX7 | — | `.ini` |
| Marsgaming | MMGX | — | `.json` |
| Motospeed | Gaming Mouse | — | `.json` |
| SPC Gear | LIX | — | `.json` |
| Ayax | Gaming Mouse | — | `.ini` |
| Turtle Beach | Software | — | `.json` |
| Blackweb | Gaming AP | — | `.json` |
| ZOWIE | Mouse Config | — | `.json` |
| Xenon200 | Configs | — | `.json` |
| Krom Kolt | KOLT | — | `.dat` |

---



This downloads and runs the latest version directly from GitHub. No files to download manually.

**Or download and run locally:**

1. Download `MacroDetector.ps1` to any directory
2. Open a Command Prompt (`cmd.exe`)
3. Run:

```cmd
powershell -ExecutionPolicy Bypass -File "MacroDetector.ps1"
```

---

## Usage

```cmd
powershell -ExecutionPolicy Bypass -File "MacroDetector.ps1"
```

No administrator privileges required. Some registry-based historical device data may require elevated access.

> **⚠️ This is not 100% accurate — double check to be sure.** The tool scans file contents for macro-related keywords, which can sometimes produce false positives (e.g., the word "macro" appearing in a UI log or cached webpage). Always verify flagged files manually by opening the software's macro editor or inspecting the file directly.

---

## Example Output

```
  ▄▄▄     ▄▄▄
   ███▄ ▄███
   ██ ▀█▀ ██               ▄
   ██     ██   ▄▀▀█▄ ▄███▀ ████▄▄███▄
   ██     ██   ▄█▀██ ██    ██   ██ ██
 ▀██▀     ▀██▄▄▀█▄██▄▀███▄▄█▀  ▄▀███▀

                ▄▄▄▄▄▄
               █▀██▀▀██        █▄             █▄
                 ██   ██      ▄██▄           ▄██▄      ▄
                 ██   ██ ▄█▀█▄ ██ ▄█▀█▄ ▄███▀ ██ ▄███▄ ████▄
               ▄ ██   ██ ██▄█▀ ██ ██▄█▀ ██    ██ ██ ██ ██
               ▀██▀███▀ ▄▀█▄▄▄▄██▄▀█▄▄▄▄▀███▄▄██▄▀███▀▄█▀
  MacroDetector  |  @imnicc.dll
  PC Owner: Nic

  Detected Mice (recent):
    connected  HID-compliant mouse
    connected  USB Input Device  [Razer]

  Installed Software:
    Logitech G HUB  [Logitech] v2026.3.880543
    Razer Synapse  [Razer] v4.0.683
    Razer Cortex  [Razer] v11.8.1.3

  Software Directories:
    Logitech G HUB
    Razer Synapse

  Macro Content Detected:
    ! Razer Synapse | 000106.ldb
        C:\Users\Nic\...\Local Storage\leveldb\000106.ldb
        [key:'macro', key:'Macro']
        Process: RazerCentralService

  Macro Found:
    ! Razer Synapse | C:\Users\Nic\...\000106.ldb
```

---

## How It Works

MacroDetector operates in 5 sequential phases:

### Phase 1: Hardware Detection

The script queries three data sources to build a complete picture of connected and historical mouse devices:

1. **WMI (Win32_PointingDevice)** — Retrieves currently connected pointing devices including mice, trackpads, and stylus devices. Extracts manufacturer, name, and PNP device ID.

2. **Windows Registry Enum Tree** — Scans `SYSTEM\CurrentControlSet\Enum\HID` and `SYSTEM\CurrentControlSet\Enum\USB` for all devices that have ever been connected. Filters for recognized gaming mouse brands. Extracts FriendlyName, DeviceDesc, and connection timestamps using the `{83da6326-97a6-4088-9453-a1923f573b29}` property GUID.

3. **Bluetooth Registry** — Scans `BTHPORT\Parameters\Devices` (classic Bluetooth), `BTHLE` (Bluetooth Low Energy), and `BTH` (BLE enumeration) for previously paired Bluetooth mice. Reads device names from binary registry values and extracts last-seen timestamps.

All found devices are merged, deduplicated by device ID, and filtered to show only recently connected devices (within the last 20 minutes) or currently connected devices.

### Phase 2: Software Discovery

The script opens three Windows Registry Uninstall paths:
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`
- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`

Each subkey is checked against a list of over 80 known gaming mouse software titles organized by brand. When a match is found, the script extracts DisplayVersion, InstallLocation, and InstallDate. Results are deduplicated by brand and software name.

### Phase 3: Directory Probing

For each brand in the software profiles database (16 entries, each with multiple path variants), the script:
1. Checks if any of the known installation paths exist on disk
2. Lists which software directories were found
3. Walks each found directory tree looking for files matching known config extensions

### Phase 4: Content Scanning

Each discovered file is:
1. **Filtered** — Checked against the noise path exclusion list
2. **Timelocked** — Only files modified in the last 20 minutes are processed
3. **Read** — Opened with `[System.IO.File]::ReadAllText()` for fast, non-blocking reads
4. **Parsed** — Scanned against pre-compiled regex patterns for:
   - Direct keyword presence (case-insensitive substring match)
   - JSON delay patterns (`"delay": <number>`)
   - Repeat/loop indicators (`"repeat"`)
   - Sequence markers (`"sequence"`)
5. **Verified** — Each file flagged with macro content triggers a process check using `Get-Process` against known executable names for that software brand

### Phase 5: Reporting

Results are displayed in a color-coded terminal output with the following sections:
- **Banner + PC Owner** — ASCII art and username
- **Detected Mice** — Connected and historical devices with connection type and brand
- **Installed Software** — Registry-discovered software titles with version numbers
- **Software Directories** — Profile entries that were found on disk
- **Macro Content Detected** — Files containing macro keywords, with full path, matches, and process status
- **Macro Found** — Summary listing of all flagged files

---

## Detection Methodology

MacroDetector uses a multi-layered approach to minimize false positives while maintaining high detection sensitivity:

| Layer | Method | False Positive Risk |
|-------|--------|---------------------|
| Path Existence | Checks if known software directories exist | Very Low |
| Extension Filter | Only scans relevant config extensions (`.json`, `.xml`, `.ldb`, etc.) | Very Low |
| Noise Exclusion | Skips cache, service worker, indexDB, crashpad directories | Very Low |
| Timestamp Gate | Only processes files modified in the last 20 minutes | Low |
| Content Scan | Searches file text for macro-related keywords and patterns | Medium |
| Process Verify | Confirms software process is running before flagging | Low |
| Pattern Weights | Multiple keyword hits increase confidence score | Medium |

A single keyword match (e.g., the word "macro" appearing in a log file) may be a false positive. Multiple keyword matches combined with an active software process provide a high-confidence macro detection.

---

## Technical Details

- **Language:** PowerShell 5.1 (Windows native, no additional runtimes required)
- **File I/O:** Uses `[System.IO.File]::ReadAllText()` and `[System.IO.Directory]::GetFiles()` for maximum performance
- **Hashing:** `System.Security.Cryptography.MD5` for change detection
- **Regex:** Pre-compiled `[regex]::new()` patterns for content scanning
- **Registry Access:** `[Microsoft.Win32.Registry]::LocalMachine` and `::CurrentUser` for direct hive access
- **WMI:** `Get-CimInstance` for hardware enumeration
- **Process:** `Get-Process` for runtime software verification
- **Concurrency:** `System.Threading.SpinLock` for thread-safe logging
- **File System Monitoring:** `System.IO.FileSystemWatcher` with 64KB internal buffer for real-time change detection
- **Encoding:** UTF8 with BOM for proper Unicode character display
- **Script Size:** ~880 lines
- **Profiles:** 16 brand definitions with 42 path variants and 30+ config file extensions

---

## Requirements

- **Operating System:** Windows 10 (build 1809+) or Windows 11
- **PowerShell:** Version 5.1 (included with Windows)
- **Permissions:** None required for basic detection. Registry-based historical device data may require administrative privileges.
- **Dependencies:** None. All APIs used are part of the .NET Framework 4.x and Windows built-in modules.

---

## Notes

- The script only processes files modified in the last 20 minutes by default. This window can be adjusted by modifying the `-RecentMins` parameter in `Invoke-ContentScan`.
- Files inside cache, service worker, indexDB, crashpad, and grpc channel directories are excluded to reduce noise from browser-based application data.
- Razer Synapse 4 stores macro data inside Chromium LevelDB databases (`*.ldb` files under `RazerAppEngine\User Data\Default\Local Storage\leveldb\`). These files are binary but may contain readable JSON fragments with macro definitions.
- Logitech G HUB stores macro definitions in `settings.db` (SQLite database) and individual JSON files.
- The content scanner reads raw text from files, which works effectively for JSON, XML, and text-based configs. Binary-only formats (SQLite databases, encrypted storage) may require a database reader for complete analysis.
- Script-only — no binaries, no external downloads, no network access required.
- Detection results depend on which files were recently modified. Software that caches macros in memory or on remote servers may not leave local forensic traces.
- The exclamation mark (`!`) in the Macro Found section indicates files with confirmed macro-related content.
