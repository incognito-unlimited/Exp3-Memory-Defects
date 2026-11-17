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
