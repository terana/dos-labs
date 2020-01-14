#include <stdio.h>

int main() {
    char *hello_msg = "Hello, DOS!\n\r$";

    _asm{
        mov  ah, 09h
        mov edx, hello_msg
        int 21h
    }

    return 0;
}
