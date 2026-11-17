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
