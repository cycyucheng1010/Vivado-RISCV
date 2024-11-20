#include <stdio.h>
#include <stdint.h>
#include "include/sha3/sha3.h"
#include "include/sha3/shake.h"
#include "include/sha3/encoding.h"
#include "include/sha3/compiler.h"


int main() {
    unsigned long start, end;

    // SHAKE128 测试
    do {
        printf("Start SHAKE128 test.\n");

        // 设置测试数据
        static unsigned char input[150] __aligned(8) = { '\0' };  // 输入 150 个字节
        unsigned char shake_output[64] __aligned(8);              // SHAKE 输出 64 字节
        shake_state sctx;

        start = rdcycle();

        // 初始化并计算 SHAKE128
        shake128_init(&sctx);
        shake_update(&sctx, input, sizeof(input));
        shake_xof(&sctx);               // 进入吸收模式
        shake_out(&sctx, shake_output, 64);  // 输出 64 字节

        end = rdcycle();

        printf("SHAKE128 output:\n");
        for (int i = 0; i < 64; i++) {
            printf("%02x", shake_output[i]);
        }
        printf("\n");
        printf("SHAKE128 execution took %lu cycles\n", end - start);

    } while (0);
    return 0;
}
