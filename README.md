# Lab 3A — Memory Defect Detection and Remediation with Valgrind and ASan

**Subject:** Secure Coding and Vulnerabilities  
**Experiment:** 3  
**Lab designation:** Lab 3A  
**Student:** Aditey Mehra  
**Roll Number:** 2301730266  
**University:** K.R. Mangalam University  
**Programme:** B.Tech CSE (AI & ML)  
**Section:** D  
**Semester:** 7  

**GitHub repository:** https://github.com/incognito-unlimited/Exp3-Memory-Defects

---

## Aim

To create, detect, interpret and remediate three memory defects in C — an uninitialised read, a heap memory leak and a double-free — using Valgrind Memcheck and AddressSanitizer, and to preserve genuine before-and-after evidence.

## Objectives

1. Create separate buggy programs for an uninitialised read, a memory leak and a double-free.
2. Run every buggy and fixed program under Valgrind Memcheck with origin tracking and full leak checking.
3. Build ASan versions and run every applicable program, recording complete stdout and stderr.
4. Explain each diagnostic, including the fact that ASan normally does not detect uninitialised scalar reads.
5. Create corrected programs that initialise variables, check allocations, free each block exactly once, set pointers to `NULL` and handle errors safely.
6. Compare buggy and fixed results with actual byte/block counts.
7. Publish source code, logs, screenshots and reports on GitHub.

## Source provenance

No faculty-provided source snippets were present in the workspace. The three buggy programs were therefore written from the experiment specification. Each program isolates one defect, and each corrected program preserves the same scenario while fixing that defect.

## Defects studied

| Defect | Buggy file | Fixed file | CWE | Exact mistake |
|---|---|---|---|---|
| Uninitialised read | `buggy/uninitialised.c` | `fixed/uninitialised_fixed.c` | CWE-457 | `int value;` is read in a condition and in `printf()` before assignment. |
| Memory leak | `buggy/leak.c` | `fixed/leak_fixed.c` | CWE-401 | A 40-byte `malloc()` block is never freed and the only pointer is discarded. |
| Double-free | `buggy/double_free.c` | `fixed/double_free_fixed.c` | CWE-415 | The same 4-byte allocation is passed to `free()` twice. |

### 1. Uninitialised read

The buggy program declares `int value;` and immediately uses it in `if (value > 0)` and `printf()`. The value is indeterminate, so the branch and printed value are undefined. The fix initialises `value = 0` before any read.

**Impact:** incorrect decisions, non-reproducible output, information leakage from stack residue and undefined behaviour.

### 2. Memory leak

The buggy program allocates `10 * sizeof(int)` bytes, writes to the block, then discards the pointer without calling `free()`. The fixed program frees the block and sets the pointer to `NULL`.

**Impact:** heap exhaustion in long-running processes, performance degradation and denial of service.

### 3. Double-free

The buggy program frees a 4-byte allocation and then frees the same address again. The second release is in a `noinline` helper so the optimiser does not remove the deliberately undefined operation in the ASan build. The fixed program uses a guarded helper that frees once and sets the caller's pointer to `NULL`.

**Impact:** heap metadata corruption, crashes and possible exploitation through crafted allocator state.

## Environment and tools

```text
Host            : Linux 6.18.54.1-microsoft-standard-WSL2 x86_64
Distribution    : Ubuntu 26.04.1 LTS
Compiler        : gcc (Ubuntu 15.2.0-16ubuntu1) 15.2.0
Valgrind        : valgrind-3.26.0
ASan runtime    : libasan.so.8 (GCC 15.2.0)
ASAN_OPTIONS    : detect_leaks=1:halt_on_error=1:print_stacktrace=1
```

## Repository structure

```text
Exp3-Memory-Defects/
├── buggy/
│   ├── uninitialised.c
│   ├── leak.c
│   └── double_free.c
├── fixed/
│   ├── uninitialised_fixed.c
│   ├── leak_fixed.c
│   └── double_free_fixed.c
├── evidence/
│   ├── tool_versions.txt
│   ├── compilation_results.txt
│   ├── fixed_execution.txt
│   ├── valgrind_uninitialised.txt
│   ├── valgrind_uninitialised_fixed.txt
│   ├── valgrind_leak.txt
│   ├── valgrind_leak_fixed.txt
│   ├── valgrind_double_free.txt
│   ├── valgrind_double_free_fixed.txt
│   ├── asan_uninitialised.txt
│   ├── asan_uninitialised_fixed.txt
│   ├── asan_leak.txt
│   ├── asan_leak_fixed.txt
│   ├── asan_double_free.txt
│   ├── asan_double_free_fixed.txt
│   └── screenshots/
├── report/
│   ├── Lab3A_Report.md
│   └── Lab_3A_Exp3_Memory_Defect_Detection_Aditey_Mehra.docx
├── README.md
└── .gitignore
```

Build binaries are written to `build/` and excluded by `.gitignore`.

## Compilation

Valgrind builds:

```bash
mkdir -p build/valgrind build/asan

gcc -Wall -Wextra -g -O0 buggy/uninitialised.c -o build/valgrind/uninitialised
gcc -Wall -Wextra -g -O0 buggy/leak.c -o build/valgrind/leak
gcc -Wall -Wextra -g -O0 buggy/double_free.c -o build/valgrind/double_free

gcc -Wall -Wextra -g -O0 fixed/uninitialised_fixed.c -o build/valgrind/uninitialised_fixed
gcc -Wall -Wextra -g -O0 fixed/leak_fixed.c -o build/valgrind/leak_fixed
gcc -Wall -Wextra -g -O0 fixed/double_free_fixed.c -o build/valgrind/double_free_fixed
```

ASan builds:

```bash
gcc -g -O1 -fsanitize=address -fno-omit-frame-pointer buggy/uninitialised.c -o build/asan/uninitialised_asan
gcc -g -O1 -fsanitize=address -fno-omit-frame-pointer buggy/leak.c -o build/asan/leak_asan
gcc -g -O1 -fsanitize=address -fno-omit-frame-pointer buggy/double_free.c -o build/asan/double_free_asan

gcc -g -O1 -fsanitize=address -fno-omit-frame-pointer fixed/uninitialised_fixed.c -o build/asan/uninitialised_fixed_asan
gcc -g -O1 -fsanitize=address -fno-omit-frame-pointer fixed/leak_fixed.c -o build/asan/leak_fixed_asan
gcc -g -O1 -fsanitize=address -fno-omit-frame-pointer fixed/double_free_fixed.c -o build/asan/double_free_fixed_asan
```

Valgrind and ASan binaries are built separately; the tools are not combined in one executable. See `evidence/compilation_results.txt`.

## Valgrind commands

```bash
valgrind --tool=memcheck --track-origins=yes --leak-check=full \
  --show-leak-kinds=all --errors-for-leak-kinds=all ./build/valgrind/uninitialised
```

Run the same command with `leak`, `double_free`, `uninitialised_fixed`, `leak_fixed` and `double_free_fixed`. Full logs are in `evidence/valgrind_*.txt`.

## ASan commands

```bash
export ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:print_stacktrace=1
./build/asan/uninitialised_asan
./build/asan/leak_asan
./build/asan/double_free_asan
./build/asan/uninitialised_fixed_asan
./build/asan/leak_fixed_asan
./build/asan/double_free_fixed_asan
```

## Actual results

### Valgrind Memcheck

| Defect | Buggy result | Fixed result |
|---|---|---|
| Uninitialised read | 5 errors from 5 contexts; `Conditional jump or move depends on uninitialised value(s)` at `uninitialised.c:17`, origin `uninitialised.c:12` | 0 errors from 0 contexts |
| Memory leak | `in use at exit: 40 bytes in 1 blocks`; `definitely lost: 40 bytes in 1 blocks` | `in use at exit: 0 bytes in 0 blocks`; 0 errors |
| Double-free | `Invalid free() / delete / delete[] / realloc()` at `double_free.c:18`; 1 error | No invalid-free diagnostic; 0 errors |

### AddressSanitizer

| Defect | Buggy result | Fixed result |
|---|---|---|
| Uninitialised read | No diagnostic; exit `0`. ASan does not track ordinary uninitialised scalar reads. | No diagnostic; exit `0`. |
| Memory leak | `ERROR: LeakSanitizer: detected memory leaks`; `40 byte(s) leaked in 1 allocation(s)`; exit `1` | No leak; exit `0`. |
| Double-free | `ERROR: AddressSanitizer: attempting double-free`; exit `1` | No invalid free; exit `0`. |

LeakSanitizer was available in this Ubuntu/WSL environment, so leak detection was enabled. MemorySanitizer was not installed; Memcheck was the primary tool for the uninitialised value.

## Before-and-after leak summary

| Program | Valgrind in use at exit | Valgrind definitely lost | ASan result |
|---|---|---|---|
| `leak` (buggy) | 40 bytes in 1 blocks | 40 bytes in 1 blocks | 40 byte(s) leaked in 1 allocation(s) |
| `leak_fixed` | 0 bytes in 0 blocks | 0 bytes in 0 blocks | No leak |

## Interpretation

- **Uninitialised read:** Memcheck tracks definedness bits, so it detected the conditional branch and `printf()` use of an undefined stack value. ASan tracks addressability, not definedness, so its clean run is expected and is not evidence that the bug is absent.
- **Memory leak:** Memcheck and LeakSanitizer both identified the same unreachable 40-byte allocation from `leak.c:13`. The fixed program's `free()` reduced lost bytes and blocks to zero.
- **Double-free:** Memcheck reported an invalid free of an address already released; ASan reported `attempting double-free`. The fixed program's guard prevented the second release.

## Reports

- `report/Lab3A_Report.md` — complete Markdown laboratory report.
- `report/Lab_3A_Exp3_Memory_Defect_Detection_Aditey_Mehra.docx` — populated editable academic report.

## GitHub repository

https://github.com/incognito-unlimited/Exp3-Memory-Defects
