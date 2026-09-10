# Manifest format and update workflow

Manifests are line-oriented UTF-8 text files. Empty lines and lines beginning with `#` are ignored. Format version 1 accepts these module fields:

```ini
format=1
module=xul.dll
architecture=x64
file_size=176911488
image_size=0xA952000
timestamp=0x6A99FF10
sha256=2E27788E95B02D2FC140B1137D7A3E02775602749B66756C68F91C994133D533
```

`file_size` is the on-disk length. `image_size` and `timestamp` come from the PE headers. A timestamp value of zero is valid when a reproducible build deliberately clears that field. `sha256` is the complete on-disk DLL digest.

Each patch is one line:

```text
patch=name|RVA|expected-bytes|replacement-bytes
```

The name is used in logs. The RVA is the function or instruction offset from the module base. The last two values are hexadecimal byte strings with equal, nonzero lengths.

## Resolving a new build

Never copy RVAs from a different Firefox version, distribution, architecture, or optimization configuration. Source-level similarity does not imply binary compatibility.

For a new build:

1. Record the exact DLL SHA-256, file size, PE image size, timestamp, architecture, browser version, and build ID.
2. Obtain symbols that match the DLL's embedded CodeView GUID and age. Mozilla publishes symbols for official Firefox releases. Other distributors may publish separate debug-symbol archives.
3. Resolve `mozilla::dom::Navigator::Webdriver()`, `Gecko_MediaFeatures_PrimaryPointerCapabilities`, and `Gecko_MediaFeatures_AllPointerCapabilities` in those symbols.
4. Convert each symbol address to an RVA and disassemble the corresponding bytes from the exact DLL.
5. Choose a replacement that obeys the Windows x64 calling convention and covers complete instructions. The current boolean replacement clears `EAX` and returns. The pointer replacement returns numeric value 6, the bitwise combination of fine-pointer and hover capabilities.
6. Create a new manifest rather than changing an existing released manifest.
7. Run `inspect`, then `attach --dry-run --once`. Every site in every applicable process must match the expected bytes or the candidate manifest is rejected.
8. Use a disposable browser profile for observable `baseline`, `attach`, and `launch` validation.

Keep symbol downloads, PDB files, debugger caches, browser profiles, and extracted browser packages outside the repository. Record public provenance in a review description without committing those large artifacts.

## Review requirements

A manifest review should establish that the hash identifies the intended public build, symbol identity matches the DLL, RVAs point to the intended functions, byte sequences end on instruction boundaries, replacements follow the ABI, dry-run output covers the browser process tree, and JavaScript-visible behavior matches the manifest's purpose.

An unknown current-byte sequence is a hard refusal. Do not add wildcard bytes or scanning fallbacks to make an unverified build pass.
