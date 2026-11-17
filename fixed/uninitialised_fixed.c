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
