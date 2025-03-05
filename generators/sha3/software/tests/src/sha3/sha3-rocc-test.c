// this one is for rdtime()

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>


#include "include/sha3/rocc.h"
#include "include/sha3/encoding.h"
#include "include/sha3/compiler.h"

#include <stdarg.h>
#include "include/sha3/sha3.h"

int main() {
    unsigned long start1, end1, start2, end2, cycles_single = 0, cycles_parallel = 0;

#ifdef __linux
    #include <sys/mman.h>
    // 確保所有頁面常駐，避免加速器頁錯
    if (mlockall(MCL_CURRENT | MCL_FUTURE)) {
        perror("mlockall");
        return 1;
    }
#endif

    // 測試數據（設為 0）
    static unsigned char input1[150] __aligned(8) = { '\0' };
    static unsigned char input2[150] __aligned(8) = { '\0' };
    unsigned char output1[SHA3_256_DIGEST_SIZE] __aligned(8);
    unsigned char output2[SHA3_256_DIGEST_SIZE] __aligned(8);

    // 預期輸出
    static const unsigned char expected[SHA3_256_DIGEST_SIZE] = {
        203, 52, 27, 85, 46, 79, 152, 228, 86, 138, 201, 206, 253, 168, 255, 107,
        122, 177, 65, 68, 231, 19, 70, 198, 64, 90, 192, 80, 206, 234, 168, 159
    };

    // **情況 1**: 單加速器執行 10 次
    printf("Testing single accelerator (10 times)...\n");
    start1 = rdcycle();
    for (int i = 0; i < 10; i++) {
        ROCC_INSTRUCTION(2,2);
        ROCC_INSTRUCTION_SS(2, &input1, &output1, 0); // 加速器 1
        ROCC_INSTRUCTION_S(2, sizeof(input1), 1);    // 開始加速器 1
    }
    end1 = rdcycle();
    cycles_single = end1 - start1;

    // **情況 2**: 雙加速器並行執行，各執行 5 次
    printf("Testing two accelerators (5 times each)...\n");
    start2 = rdcycle();
    for (int i = 0; i < 5; i++) {
        ROCC_INSTRUCTION(2,2);
        ROCC_INSTRUCTION_SS(2, &input1, &output1, 0); // 加速器 1
        ROCC_INSTRUCTION_S(2, sizeof(input1), 1);    // 開始加速器 1
        ROCC_INSTRUCTION(3,2);
        ROCC_INSTRUCTION_SS(3, &input2, &output2, 0); // 加速器 2
        ROCC_INSTRUCTION_S(3, sizeof(input2), 1);    // 開始加速器 2
    }
    end2 = rdcycle();
    cycles_parallel = end2 - start2;

    // 輸出結果
    printf("Single accelerator (10 times) took %lu cycles\n", cycles_single);
    printf("Two accelerators (5 times each) took %lu cycles\n", cycles_parallel);

    // 驗證輸出
    printf("Verifying Accelerator 1 output...\n");
    for (int i = 0; i < SHA3_256_DIGEST_SIZE; i++) {
        if (output1[i] != expected[i]) {
            printf("Failed: Accelerator 1 outputs don't match!\n");
            return 1;
        }
    }

    printf("Verifying Accelerator 2 output...\n");
    for (int i = 0; i < SHA3_256_DIGEST_SIZE; i++) {
        if (output2[i] != expected[i]) {
            printf("Failed: Accelerator 2 outputs don't match!\n");
            return 1;
        }
    }

    printf("Success! Outputs match for both accelerators.\n");
    return 0;
}