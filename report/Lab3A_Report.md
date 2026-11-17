# Laboratory Report — Lab 3A

## Experiment 3: Memory Defect Detection and Remediation with Valgrind and ASan

| Field | Detail |
|---|---|
| Subject | Secure Coding and Vulnerabilities |
| Experiment | 3 |
| Lab designation | Lab 3A |
| Student | Aditey Mehra |
| Roll Number | 2301730266 |
| University | K.R. Mangalam University |
| Programme | B.Tech CSE (AI & ML) |
| Section | D |
| Semester | 7 |
| GitHub repository | https://github.com/incognito-unlimited/Exp3-Memory-Defects |

---

## 1. Aim

To create, detect, interpret and remediate three memory defects in C — an uninitialised read, a heap memory leak and a double-free — using Valgrind Memcheck and AddressSanitizer, and to preserve genuine before-and-after evidence.

## 2. Objectives

1. Create separate buggy C programs for an uninitialised read, a memory leak and a double-free.
2. Execute each buggy and fixed program under Valgrind Memcheck with origin tracking and full leak checking.
3. Build ASan versions and run every applicable program, capturing complete stdout and stderr.
4. Explain each diagnostic and distinguish Memcheck findings from ASan findings.
5. Correct each defect and verify the corrected programs with both tools.
6. Compare real before-and-after leak summaries with byte and block counts.
7. Publish all source files, diagnostic logs, screenshots and documentation on GitHub.

## 3. Introduction

Memory defects are dangerous because C does not automatically initialise stack variables, reclaim heap allocations or invalidate stale pointers. An uninitialised read can produce indeterminate values and undefined control flow. A memory leak consumes heap memory until the process fails or is terminated. A double-free corrupts allocator bookkeeping and may lead to arbitrary memory writes.

Valgrind Memcheck tracks value definedness and heap ownership, making it suitable for all three defects. AddressSanitizer instruments memory accesses and allocations; it detects leaks and double-frees, but it does not report ordinary uninitialised scalar reads. This difference is important: a clean ASan run for the uninitialised program is expected and must not be presented as detection of that defect.

No faculty-provided source snippets were available. The programs below were written from the laboratory specification; each buggy file isolates one defect.

## 4. Defect Classification

| No. | Defect | CWE | Description | Potential impact | Remediation |
|-----|--------|-----|-------------|------------------|-------------|
| 1 | Uninitialised read | CWE-457 | A local variable is read before a defined value is assigned. | Undefined/indeterminate behaviour, incorrect decisions, possible data leakage. | Initialise before every read; assign on all control paths. |
| 2 | Memory leak | CWE-401 | A heap allocation is not released and its pointer is discarded. | Resource exhaustion, degradation of long-running processes, denial of service. | Track ownership and release each allocation exactly once. |
| 3 | Double-free | CWE-415 | The same allocation is passed to `free()` twice. | Heap corruption, crash, possible exploitation. | Free once, set the pointer to `NULL`, and guard repeat releases. |

## 5. Buggy and Fixed Code Listings

### 5.1 Defect 1 — Uninitialised read

**Buggy — `buggy/uninitialised.c`**

```c
/*
 * Lab 3A - Buggy program 1
 * Defect : Uninitialised read (CWE-457)
 *
 * The local variable 'value' is read before a defined value is assigned.
 * Its contents are indeterminate, so the branch and the printed result are
 * not reliable.
 */
#include <stdio.h>

int main(void)
{
    int value; /* VULNERABILITY: never initialised before use. */

    printf("[*] Testing an uninitialised integer...\n");

    if (value > 0) {
        printf("[!] value is positive: %d\n", value);
    } else {
        printf("[!] value is not positive: %d\n", value);
    }

    return 0;
}
```

**Fixed — `fixed/uninitialised_fixed.c`**

```c
/*
 * Lab 3A - Corrected program 1
 * Remediation : Initialise the variable before every read.
 */
#include <stdio.h>

int main(void)
{
    int value = 0;

    printf("[*] Testing an initialised integer...\n");

    if (value > 0) {
        printf("[+] value is positive: %d\n", value);
    } else {
        printf("[+] value is not positive: %d\n", value);
    }

    return 0;
}
```

### 5.2 Defect 2 — Memory leak

**Buggy — `buggy/leak.c`**

```c
/*
 * Lab 3A - Buggy program 2
 * Defect : Memory leak (CWE-401)
 *
 * A 40-byte heap block is allocated but never released. The allocation is
 * still reachable when main() returns, so the process loses the block.
 */
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    int *volatile data = malloc(10 * sizeof(*data));
    if (data == NULL) {
        fprintf(stderr, "[!] malloc() failed.\n");
        return EXIT_FAILURE;
    }

    data[0] = 42;
    printf("[*] data[0] = %d\n", data[0]);

    /* VULNERABILITY: the only pointer is discarded without free(), so the
       40-byte block becomes unreachable and is leaked. */
    data = NULL;
    return 0;
}
```

**Fixed — `fixed/leak_fixed.c`**

```c
/*
 * Lab 3A - Corrected program 2
 * Remediation : Check the allocation, use it, then release it exactly once
 *               and set the pointer to NULL.
 */
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    int *data = malloc(10 * sizeof(*data));
    if (data == NULL) {
        fprintf(stderr, "[!] malloc() failed.\n");
        return EXIT_FAILURE;
    }

    data[0] = 42;
    printf("[*] data[0] = %d\n", data[0]);

    free(data);
    data = NULL;

    printf("[+] Allocation released; pointer set to NULL.\n");
    return EXIT_SUCCESS;
}
```

### 5.3 Defect 3 — Double-free

**Buggy — `buggy/double_free.c`**

```c
/*
 * Lab 3A - Buggy program 3
 * Defect : Double-free (CWE-415)
 *
 * The same allocation is released twice because the pointer is not
 * invalidated after the first free().
 */
#include <stdio.h>
#include <stdlib.h>

/*
 * Kept non-inlined so the deliberately undefined second release is not
 * removed by the optimiser in the ASan build. The defect is the second
 * free(), not the helper.
 */
__attribute__((noinline)) static void release_again(int *pointer)
{
    free(pointer);
}

int main(void)
{
    int *value = malloc(sizeof(*value));
    if (value == NULL) {
        fprintf(stderr, "[!] malloc() failed.\n");
        return EXIT_FAILURE;
    }

    *value = 7;
    printf("[*] *value = %d\n", *value);

    free(value);
    printf("[+] First free completed.\n");

    /* VULNERABILITY: second free of the same address. */
    release_again(value);
    printf("[!] Second free attempted.\n");

    return 0;
}
```

**Fixed — `fixed/double_free_fixed.c`**

```c
/*
 * Lab 3A - Corrected program 3
 * Remediation : Release the allocation through a guarded helper that sets
 *               the caller's pointer to NULL, making repeat calls harmless.
 */
#include <stdio.h>
#include <stdlib.h>

static void release_once(int **pointer)
{
    if (pointer != NULL && *pointer != NULL) {
        free(*pointer);
        *pointer = NULL;
        printf("[+] Allocation freed once; pointer set to NULL.\n");
    } else {
        printf("[*] Pointer already NULL; duplicate free skipped.\n");
    }
}

int main(void)
{
    int *value = malloc(sizeof(*value));
    if (value == NULL) {
        fprintf(stderr, "[!] malloc() failed.\n");
        return EXIT_FAILURE;
    }

    *value = 7;
    printf("[*] *value = %d\n", *value);

    release_once(&value);
    release_once(&value);

    return EXIT_SUCCESS;
}
```

## 6. Compilation and Tool Execution

### Tool versions

```text
gcc (Ubuntu 15.2.0-16ubuntu1) 15.2.0
valgrind-3.26.0
Linux 6.18.54.1-microsoft-standard-WSL2 x86_64
```

### Valgrind build commands

```bash
gcc -Wall -Wextra -g -O0 buggy/uninitialised.c -o build/valgrind/uninitialised
gcc -Wall -Wextra -g -O0 buggy/leak.c -o build/valgrind/leak
gcc -Wall -Wextra -g -O0 buggy/double_free.c -o build/valgrind/double_free
gcc -Wall -Wextra -g -O0 fixed/uninitialised_fixed.c -o build/valgrind/uninitialised_fixed
gcc -Wall -Wextra -g -O0 fixed/leak_fixed.c -o build/valgrind/leak_fixed
gcc -Wall -Wextra -g -O0 fixed/double_free_fixed.c -o build/valgrind/double_free_fixed
```

### Valgrind execution command

```bash
valgrind --tool=memcheck --track-origins=yes --leak-check=full \
  --show-leak-kinds=all --errors-for-leak-kinds=all ./build/valgrind/PROGRAM
```

### ASan build commands

```bash
gcc -g -O1 -fsanitize=address -fno-omit-frame-pointer buggy/uninitialised.c -o build/asan/uninitialised_asan
gcc -g -O1 -fsanitize=address -fno-omit-frame-pointer buggy/leak.c -o build/asan/leak_asan
gcc -g -O1 -fsanitize=address -fno-omit-frame-pointer buggy/double_free.c -o build/asan/double_free_asan
gcc -g -O1 -fsanitize=address -fno-omit-frame-pointer fixed/uninitialised_fixed.c -o build/asan/uninitialised_fixed_asan
gcc -g -O1 -fsanitize=address -fno-omit-frame-pointer fixed/leak_fixed.c -o build/asan/leak_fixed_asan
gcc -g -O1 -fsanitize=address -fno-omit-frame-pointer fixed/double_free_fixed.c -o build/asan/double_free_fixed_asan
```

### ASan execution command

```bash
export ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:print_stacktrace=1
./build/asan/PROGRAM_asan
```

All compilation commands completed with exit code `0`. Full output is in `evidence/compilation_results.txt`.

## 7. Before-and-After Diagnostic Comparison

| Defect | Buggy output | Fixed output |
|---|---|---|
| Uninitialised read | Valgrind: 5 errors from 5 contexts; first diagnostic `Conditional jump or move depends on uninitialised value(s)` at `uninitialised.c:17`; origin stack allocation at `uninitialised.c:12`. ASan: no diagnostic, exit `0`. | Valgrind: 0 errors from 0 contexts. ASan: no diagnostic, exit `0`. |
| Memory leak | Valgrind: `in use at exit: 40 bytes in 1 blocks`; `definitely lost: 40 bytes in 1 blocks`. ASan: `40 byte(s) leaked in 1 allocation(s)`, exit `1`. | Valgrind: `in use at exit: 0 bytes in 0 blocks`; 0 errors. ASan: no leak, exit `0`. |
| Double-free | Valgrind: `Invalid free()` at `double_free.c:18`; block freed at line 32 and allocated at line 23. ASan: `attempting double-free`, exit `1`. | Valgrind: no invalid free, 0 errors. ASan: no diagnostic, exit `0`. |

### Leak summary comparison

| Program | In use at exit | Definitely lost | ASan |
|---|---|---|---|
| `leak` | 40 bytes in 1 blocks | 40 bytes in 1 blocks | 40 byte(s) leaked in 1 allocation(s) |
| `leak_fixed` | 0 bytes in 0 blocks | 0 bytes in 0 blocks | No leak |

## 8. Interpretation of Diagnostics

### Uninitialised read

Memcheck reported a conditional jump depending on an uninitialised value at line 17 and a use of an uninitialised value inside `printf()` at line 20. With `--track-origins=yes`, it traced the value back to the stack allocation at line 12. This means the program made a decision using undefined stack contents. The corrected program assigns `value = 0` first, so Memcheck reports zero errors.

ASan reported nothing for this program. That is expected: AddressSanitizer checks addressability and allocator misuse, not whether a scalar variable has been assigned. Therefore Memcheck is the primary evidence for this defect. MemorySanitizer was not installed, so no MSan result is claimed.

### Memory leak

Memcheck reported 40 bytes in one block still in use at exit and classified them as definitely lost. The allocation stack points to `leak.c:13`. ASan's LeakSanitizer independently reported the same 40-byte allocation. The pointer was declared `volatile` and set to `NULL` to ensure the discarded-pointer state was observable at runtime rather than optimised away.

The corrected program frees the block and clears the pointer. Both tools then report zero lost bytes and zero lost blocks.

### Double-free

Memcheck reported an invalid free at `double_free.c:18`, identified the earlier free at line 32 and the original allocation at line 23. ASan reported `attempting double-free` at the same helper and also showed both the first release and the allocation stack. The second release was kept in a non-inlined helper so an optimising compiler would not remove the deliberate undefined operation before ASan could observe it.

The corrected helper frees once, sets the pointer to `NULL` and skips later releases, so both tools report clean runs.

## 9. GitHub Repository

Repository URL: https://github.com/incognito-unlimited/Exp3-Memory-Defects

The repository contains all buggy and fixed sources, complete Valgrind and ASan logs, genuine screenshots, this report and the README.

## 10. Result

All three defects were demonstrated and analysed. Valgrind detected the uninitialised read, the 40-byte leak and the invalid double-free. ASan detected the leak and double-free and produced no diagnostic for the uninitialised scalar read, consistent with its documented scope. Every corrected program compiled successfully and produced clean Valgrind and ASan runs. The before-and-after leak summary changed from 40 bytes in 1 blocks lost to 0 bytes in 0 blocks lost.

## 11. Conclusion

The experiment shows that different tools detect different classes of memory defects. Valgrind Memcheck is essential for undefined values and provides detailed origin tracking; AddressSanitizer and LeakSanitizer are highly effective for allocator misuse and leaks but do not detect ordinary uninitialised scalar reads. Initialising variables, checking allocation results, defining clear ownership and setting freed pointers to `NULL` eliminate the demonstrated defects. The complete evidence has been preserved and published for reproducibility.
