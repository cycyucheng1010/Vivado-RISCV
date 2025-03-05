//see LICENSE for license
// The following is a RISC-V program to test the functionality of the
// sha3 RoCC accelerator.
// Compile with riscv-gcc sha3-rocc.c
// Run with spike --extension=sha3 pk a.out

#include <stdio.h>
#include <stdint.h>
#include "../include/sha3/rocc.h"
#include "../include/sha3/sha3-output64.h"
#include "../include/sha3/encoding.h"
#include "../include/sha3/compiler.h"

#ifdef __linux
#include <sys/mman.h>
#endif

int main() {
  unsigned long start, end;
  int j;

#ifdef __linux
  // Ensure all pages are resident to avoid accelerator page faults
  if (mlockall(MCL_CURRENT | MCL_FUTURE)) {
    perror("mlockall");
    return 1;
  }
#endif

  for (j = 0; j < 100; j++) { // 執行 100 次
    printf("Start basic test %d.\n", j + 1);

    // BASIC TEST 1 - 150 zero bytes
    static unsigned char input[150] __aligned(8) = { '\0' };
    unsigned char output[64] __aligned(8);
    start = rdcycle();
    ROCC_INSTRUCTION(2,2);
    // Compute hash with accelerator
    asm volatile ("fence");

    // 設定加速器輸入和輸出地址
    ROCC_INSTRUCTION_SS(2, &input, &output, 0);

    // 設定長度並執行雜湊計算
    ROCC_INSTRUCTION_S(2, sizeof(input), 1);
    asm volatile ("fence" ::: "memory");

    end = rdcycle();

    // 檢查結果
    int i;
    static const unsigned char result[64] = {
#ifdef KECCAK
      221,204,157,217,67,211,86,31,54,168,44,245,97,194,193,26,
      234,42,135,166,66,134,39,174,184,61,3,149,137,42,57,238
#else /* FIPS 202 */
      211, 249, 118, 142, 221, 94, 103, 158, 208, 75, 72, 129, 47, 14, 178, 138,
      81, 90, 200, 235, 53, 184, 224, 102, 220, 73, 195, 12, 103, 154, 23, 15,
      106, 140, 70, 104, 178, 200, 101, 100, 47, 23, 84, 74, 15, 61, 148, 184,
      52, 26, 50, 122, 81, 243, 138, 208, 90, 91, 25, 126, 141, 27, 188, 52
#endif
    };

    for (i = 0; i < 64; i++) {
      printf("output[%d]:%d ==? results[%d]:%d \n", i, output[i], i, result[i]);
      if (output[i] != result[i]) {
        printf("Failed: Outputs don't match!\n");
        printf("SHA execution took %lu cycles\n", end - start);
        return 1;
      }
    }
  }

  printf("Success!\n");
  printf("SHA execution took %lu cycles\n", end - start);
  
  return 0;
}

