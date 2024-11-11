#include <stdio.h>
#include "syscalls.h"

int main() {
    template_open();
    template_close();
    template_fork();

    return 0;
}
