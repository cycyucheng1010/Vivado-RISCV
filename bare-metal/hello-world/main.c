#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "common.h"
#include "kprintf.h"

static void usleep(unsigned us) {
    uintptr_t cycles0;
    uintptr_t cycles1;
    asm volatile ("csrr %0, 0xB00" : "=r" (cycles0));
    for (;;) {
        asm volatile ("csrr %0, 0xB00" : "=r" (cycles1));
        if (cycles1 - cycles0 >= us * 100) break;
    }
}

int main(void) {
    kprintf("\n");
    for (;;) {
    	int a[0] = {1},b[0];;
        kprintf("Hello World!%d\n",b[0]);
        usleep(1000);
    }
    return 0;
}
