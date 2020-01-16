#include <stdio.h>

int main() {
    printf("Hello, world! \n");

    __asm {
    xor ax, ax
    mov cs, ax
    }

    return 0;
}