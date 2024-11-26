//see LICENSE for license
// The following is a RISC-V program to test the functionality of the
// SHAKE256 implementation.
// Compile with riscv-gcc shake256-test.c
// Run with spike --extension=sha3 pk a.out

#include <stdio.h>
#include <stdint.h>
#include "include/sha3/shake.h"
#include "include/sha3/encoding.h"
#include "include/sha3/compiler.h"

int main() {
    unsigned long start, end;

    do {
        printf("Start SHAKE256 test.\n");

        // Test input: 150 zero bytes
        static unsigned char input[150] __aligned(8) = { '\0' };
        unsigned char output[64] __aligned(8);

        // Expected output for SHAKE256
        static const unsigned char expected_output[64] = {
            211, 249, 118, 142, 221, 94, 103, 158, 208, 75, 72, 129, 47, 14, 178, 138,
            81, 90, 200, 235, 53, 184, 224, 102, 220, 73, 195, 12, 103, 154, 23, 15,
            106, 140, 70, 104, 178, 200, 101, 100, 47, 23, 84, 74, 15, 61, 148, 184,
            52, 26, 50, 122, 81, 243, 138, 208, 90, 91, 25, 126, 141, 27, 188, 52
        };

        // Start cycle count
        start = rdcycle();

        // Perform SHAKE256 computation
        sha3_state sctx;
        shake_init(&sctx, 256);
        shake_update(&sctx, input, sizeof(input));
        shake_out(&sctx, output, sizeof(output));

        // End cycle count
        end = rdcycle();

        // Compare output with expected result
        printf("Checking SHAKE256 output...\n");
        int i;
        for (i = 0; i < 64; i++) {
            printf("output[%d]: %d ==? expected[%d]: %d\n", i, output[i], i, expected_output[i]);
            if (output[i] != expected_output[i]) {
                printf("Failed: Outputs don't match!\n");
                printf("SHAKE256 execution took %lu cycles\n", end - start);
                return 1;
            }
        }

        printf("Success: SHAKE256 output matches the expected result.\n");
        printf("SHAKE256 execution took %lu cycles\n", end - start);

    } while (0);

    return 0;
}