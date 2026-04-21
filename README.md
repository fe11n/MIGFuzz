# MIGFuzz

MIGFuzz is a research fuzzer for macOS Mach servers (launchd-managed services that dispatch MIG-based Mach messages). It combines static service extraction, LLM-assisted message-generator synthesis, LLM-based reachability checking, and a [Jackalope](https://github.com/googleprojectzero/Jackalope) + TinyInst coverage-guided driver. The end product, per service, is a compiled `harness` binary plus a generated `generate_message.cc` that Jackalope runs against the real service binary.

## Pipeline

The workflow is organized around four stages; each stage assumes the previous stage's artifacts already exist on disk.

### 1. Constraint extraction & generator synthesis

```bash
python llm_function_generator/generate_all_in_one.py
```

Walks every service directory under `mig_services/`, asks the configured LLM to extract message-construction *constraints* from the MIG routines of each service, and then synthesizes the corresponding `generate_message.cc`. Results are written into the matching workspace under `fuzz_exec/<service-name>/`.

### 2. Reachability verification & regeneration

```bash
python llm_message_checker/check_all_in_one.py
```

Iterates over `fuzz_exec/`, drives the external checker binary (under `llm_message_checker/checker_exec/`) to verify that every generated message ID is actually reachable on the live system, and re-asks the LLM to fix unreachable messages. Verification results land in `check_result.json` and `check_fail_log/` inside each workspace.

### 3. Fuzzing environment preparation

```bash
sudo -E python fuzzkit/fuzz_prepare.py
```

Builds `libmach-modify.dylib`, compiles the per-service `harness` (combining `harness.mm` + `fuzz_helpers/*.cc` + the LLM-generated `generate_message.cc`), seeds the `corpus/` and `out/` directories, and emits a ready-to-run `run.sh` inside each `fuzz_exec/<service-name>/`. Requires `sudo` because build artifacts and injected dylibs may touch root-owned files.

### 4. Fuzzing

```bash
cd fuzz_exec/<service-name>
sudo ./run.sh
```

Each service workspace under `fuzz_exec/` is self-contained — `run.sh` `cd`s into its own directory and invokes Jackalope with `DYLD_INSERT_LIBRARIES=../../libmach-modify.dylib` against the service-specific `harness`.

## Repository layout

| Path | Purpose |
| --- | --- |
| [service_file_extractor/](service_file_extractor/) | Extracts launchd-managed Mach services from the live system (`extract_services.sh`). |
| [mig_services/](mig_services/) | Per-service MIG metadata (`mig_information.json`, `mig_functions.json`). Prepared manually/externally; gitignored. |
| [llm_function_generator/](llm_function_generator/) | Constraint extraction + `generate_message.cc` synthesis via LLM. |
| [llm_message_checker/](llm_message_checker/) | Reachability verification and failed-message regeneration. |
| [llm_utils/](llm_utils/) | Shared LLM plumbing: `APIClient`, prompt bank (`prompts/`), path constants, logging. |
| [fuzzkit/](fuzzkit/) | Build + fuzz orchestration (`fuzz_prepare.py`, `fuzzer_builder.py`, `message_generator.py`, ...). |
| [fuzz_helpers/](fuzz_helpers/) + [harness.mm](harness.mm) | C++/Obj-C++ harness runtime shared across services. |
| [jackalope-modifications/](jackalope-modifications/) | Custom Jackalope + TinyInst sources for the `coreaudiofuzzer` driver. |
| [fuzz_exec/](fuzz_exec/) | Per-service fuzzing workspaces — the output tree of the whole pipeline. |
| [poc_construct/](poc_construct/) | Standalone crash reproducers built from Jackalope crashes. |
| [mach-modify.c](mach-modify.c) | Source for `libmach-modify.dylib` (low-level Mach interposition during fuzzing). |

## Requirements

- macOS (service extraction is keyed off `sw_vers -productVersion`).
- Python 3.13 (the repository ships with a local `.venv`).
- Clang / Xcode command-line tools for building the dylib, harness, and Jackalope.
- A pre-built Jackalope binary at `jackalope-modifications/build/Release/coreaudiofuzzer` (see [jackalope-modifications/README.md](jackalope-modifications/README.md)).
- An OpenAI-compatible LLM endpoint configured in [llm_utils/api_client.py](llm_utils/api_client.py).

## Service workspace (`fuzz_exec/<service>/`)

Each workspace is keyed by `service.json` (authoritative `library_path`, `subsystem_num`, `dispatch_routines`, `dispatch_routine_offsets`, and a `fuzz` block). Alongside it you will find the generated `generate_message.cc`, the compiled `harness`, the injected `libmach-modify.dylib`, the auto-generated `run.sh`, and the runtime artifacts (`corpus/`, `out/`, `log.txt`, `check_result.json`, `check_fail_log/`).
