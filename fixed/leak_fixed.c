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
