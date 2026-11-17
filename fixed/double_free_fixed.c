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
