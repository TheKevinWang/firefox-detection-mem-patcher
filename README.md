# Firefox Detection Mem Patcher POC

This Windows x64 proof of concept applies small, exact-build patches to Firefox process memory. It currently demonstrates two changes commonly studied in browser-automation detection research:

- `navigator.webdriver` returns `false`.
- CSS pointer and hover media queries report a fine pointer with hover support.

The program does not modify Firefox files. It verifies the complete `xul.dll` identity and the original machine code before writing, patches the browser parent and its current descendants transactionally, and can monitor for later content processes. All changes disappear when the patched processes exit.

This is research software, not a general-purpose Firefox modification framework. Use it only with browser processes you own or are authorized to test.

## Supported builds

Each manifest supports one exact `xul.dll`:

| Manifest | Browser build | Architecture |
| --- | --- | --- |
| `manifests/firefox-155.0.1-win64.ini` | Mozilla Firefox 155.0.1, build `20260903215306` | x64 |
| `manifests/tor-browser-15.0.21-win64.ini` | Tor Browser 15.0.21 / Firefox 140.15.0esr, build `20260901104146` | x64 |

An update normally changes the DLL hash, layout, and instructions. The controller deliberately refuses an updated or otherwise unknown binary until a matching manifest is resolved and reviewed.

## Requirements

- 64-bit Windows 10 or newer
- CMake 3.20 or newer
- Visual Studio with the Desktop development with C++ workload and a Windows SDK
- A supported 64-bit Firefox-family build

The process owner must have permission to open and modify the target processes. Depending on how the browser was started, an elevated shell may be required.

## Build and test

Open an x64 Visual Studio Developer PowerShell in the repository root:

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

The executable is written to `build\Release\firefox-detection-mem-patcher.exe`.

## Inspect a browser installation

Inspection reads the installed `xul.dll` and compares it with the manifest without opening a running process:

```powershell
.\build\Release\firefox-detection-mem-patcher.exe inspect `
  --firefox "C:\Browsers\Firefox\firefox.exe" `
  --manifest .\manifests\firefox-155.0.1-win64.ini
```

A supported binary prints `MATCH`. Any identity difference prints `REFUSED` with the observed architecture, sizes, timestamp, and SHA-256.

## Check a running browser without writing

The executable path is normally the easiest selector:

```powershell
.\build\Release\firefox-detection-mem-patcher.exe attach `
  --firefox "C:\Browsers\Firefox\firefox.exe" `
  --manifest .\manifests\firefox-155.0.1-win64.ini `
  --dry-run --once
```

The controller finds the topmost matching process with `xul.dll` loaded. If multiple independent instances use the same executable, it refuses the ambiguous selection and lists the parent PIDs. Supply one explicitly:

```powershell
.\build\Release\firefox-detection-mem-patcher.exe attach `
  --pid 1234 `
  --manifest .\manifests\firefox-155.0.1-win64.ini `
  --dry-run --once
```

Expected sites are reported as `WOULD_APPLY`; sites already containing the replacement are reported as `ALREADY_APPLIED`.

## Patch and monitor an existing browser

Omit `--dry-run` to write memory. Omit `--once` to keep monitoring for new descendants:

```powershell
.\build\Release\firefox-detection-mem-patcher.exe attach `
  --firefox "C:\Browsers\Firefox\firefox.exe" `
  --manifest .\manifests\firefox-155.0.1-win64.ini
```

Press `Ctrl+C` to stop monitoring. Existing memory changes remain until those processes exit. Attach monitoring checks for new descendants every 100 milliseconds, so a newly created process can execute briefly before it is discovered and suspended.

## Start a browser under controlled execution

Launch mode starts the supplied executable as a Windows debugger. It patches each matching `xul.dll` load before continuing that debug event:

```powershell
.\build\Release\firefox-detection-mem-patcher.exe launch `
  --firefox "C:\Browsers\Firefox\firefox.exe" `
  --manifest .\manifests\firefox-155.0.1-win64.ini `
  -- -no-remote -profile "C:\BrowserProfiles\Disposable"
```

Use a disposable profile. Launch mode supplies stronger startup ordering than attach monitoring because the target cannot continue past the DLL-load event until validation and patching finish.

## How manifests work

A manifest pins the module name, architecture, file size, in-memory image size, PE timestamp, and SHA-256. Each patch line contains:

```text
patch=name|RVA|expected-bytes|replacement-bytes
```

An RVA is a relative virtual address: an offset from the randomized module base. At runtime the controller calculates `loaded xul.dll base + RVA`, so normal address-space layout randomization is supported. The expected and replacement sequences have equal length.

The controller validates every site in a process before changing any site. It suspends the process threads, refuses to write while a thread's instruction pointer is inside a patch region, temporarily changes page protection, restores protection, and flushes the instruction cache. A later failure rolls back earlier writes from the same transaction.

See [docs/manifest-format.md](docs/manifest-format.md) before adding support for another browser build.

## Integration validation

The validator creates a unique temporary Firefox profile, runs a local page, and removes the profile afterward:

```powershell
python .\tests\integration_validation.py `
  --mode attach `
  --firefox "C:\Browsers\Firefox\firefox.exe" `
  --controller .\build\Release\firefox-detection-mem-patcher.exe `
  --manifest .\manifests\firefox-155.0.1-win64.ini
```

Available modes are `baseline`, `attach`, and `launch`. The manifest must match the supplied browser exactly.

## License

Source code is available under the [Mozilla Public License 2.0](LICENSE).
