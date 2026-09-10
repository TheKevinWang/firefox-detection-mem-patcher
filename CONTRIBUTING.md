# Contributing

Build the project with MSVC in an x64 Visual Studio developer shell and run the unit tests before submitting a change:

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

Use a disposable Firefox profile for integration validation. Changes to process discovery, suspension, memory protection, transactions, or rollback should include focused tests and updated public architecture or safety documentation when behavior changes.

New manifests must follow [docs/manifest-format.md](docs/manifest-format.md). Include public build provenance, exact symbol identity, disassembly evidence, a clean dry run, and observable validation. Do not weaken identity or expected-byte checks to support additional versions.

Do not commit generated binaries, build directories, PDBs, browser profiles, crash dumps, debugger caches, browsing data, personal paths, or credentials.
