#include <stdio.h>
#include "syscalls.h"

int main() {
    template_getpid();
    template_fork();
    template_write();

    return 0;
}
