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
