#include <stdio.h>
#include <stdint.h>
//#include "include/sha3/sha3.h"
#include "include/sha3/shake-v1.h"
#include "include/sha3/encoding.h"
#include "include/sha3/compiler.h"

//確認每個階段狀態

void print_state(const shake_state *sctx) {
    printf("Partial: %u\n", sctx->partial);
    printf("State: ");
    for (int i = 0; i < 25; i++) {
        printf("%016lx ", sctx->st[i]);
        if ((i + 1) % 5 == 0) printf("\n");
    }
    printf("\n");
}



// 打印缓冲区函数
void print_buffer(const uint8_t *buf, size_t len) {
    printf("Buffer:\n");
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", buf[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
}


int main() {
    unsigned long start, end;

    // SHAKE256 测试
    do {
        printf("Start SHAKE256 test.\n");

        // 设置输入数据为 0 到 149 的连续整数
        static unsigned char input[150] __aligned(8)={ '\0' };
        /*
        for (int i = 0; i < 150; i++) {
            input[i] = 0;
            printf("%d\t",input[i]);
        }
        */
        printf("\n");
        unsigned char shake_output[64] __aligned(8);  // SHAKE 输出 64 字节
        shake_state sctx;

        start = rdcycle();

        printf("Initializing SHAKE256...\n");
        shake256_init(&sctx);

        print_state(&sctx);

        printf("Updating SHAKE256 state...\n");
        shake_update(&sctx, input, sizeof(input));
        print_state(&sctx);

        printf("Entering SHAKE256 XOF mode...\n");
        shake_xof(&sctx);
         sctx.buf[sctx.partial++] = 0x1F;  // 填充 SHAKE 的 Pad 值
         memset(sctx.buf + sctx.partial, 0, sctx.rsiz - sctx.partial);
         sctx.buf[sctx.rsiz - 1] |= 0x80;  // 填充结束位
        print_buffer(sctx.buf, sctx.rsiz);
        //print_state(&sctx);

        printf("Generating SHAKE256 output...\n");
        shake_out(&sctx, shake_output, 64);
        print_state(&sctx);

        end = rdcycle();

        static const unsigned char expected[64] = {
            211, 249, 118, 142, 221, 94, 103, 158, 
            208, 75, 72, 129, 47, 14, 178, 138, 
            81, 90, 200, 235, 53, 184, 224, 102, 
            220, 73, 195, 12, 103, 154, 23, 15, 
            106, 140, 70, 104, 178, 200, 101, 100, 
            47, 23, 84, 74, 15, 61, 148, 184, 
            52, 26, 50, 122, 81, 243, 138, 208, 
            90, 91, 25, 126, 141, 27, 188, 52
        };

        for (int i = 0; i < 64; i++) {
            printf("shake_output[%d]: %d ==? expected[%d]: %d \n", i, shake_output[i], i, expected[i]);
            /*
            if (shake_output[i] != expected[i]) {
                printf("Failed: Outputs don't match!\n");
                printf("SHAKE256 execution took %lu cycles\n", end - start);
                return 1;
            }
            */
        }

        //printf("SHAKE256 test passed!\n");
        printf("SHAKE256 execution took %lu cycles\n", end - start);

    } while (0);

    return 0;
}
