#include <stdio.h>
#include <inttypes.h>
#include <math.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#define MEM_ADDR_BASE 0x2000
#define MEM_SIZE 4096

#define FFT_WRITE_LANE  0x2000
#define FFT_RD_LANE_BASE 0x2008

// addr of read lane i is FFT_RD_LANE_BASE + i * 8

// 64 位元輸入 (32 位實數 + 32 位虛數)
const uint64_t points[8] = {
    0x000D090000000000,  // 實數: 3337, 虛數: 0
    0x000E7F0000000000,  // 實數: 3711, 虛數: 0
    0x0002080000000000,  // 實數: 520, 虛數: 0
    0x000E9E0000000000,  // 實數: 3742, 虛數: 0
    0x000A1E0000000000,  // 實數: 2590, 虛數: 0
    0x00018F0000000000,  // 實數: 399, 虛數: 0
    0x0004750000000000,  // 實數: 1141, 虛數: 0
    0x0008C00000000000   // 實數: 2240, 虛數: 0
};

int32_t signExtend(uint32_t value) {
    if (value & (1 << 31)) {
        return (int32_t)(value | 0xFFFFFFFF00000000);  // 符號擴展
    } else {
        return (int32_t)value;
    }
}

void printFixedPoint(int32_t fixed_point, int fractional_bits) {
    int32_t integer_part = fixed_point >> fractional_bits;
    int32_t fractional_part = fixed_point & ((1 << fractional_bits) - 1);
    printf("%d.%04d", integer_part, (fractional_part * 10000) >> fractional_bits);
}

int main(void) {
    int num_points = 8;
    int fd = open("/dev/mem", O_RDWR | O_SYNC);

    if (fd < 0) {
        perror("open");
        return -1;
    }

    // 映射物理内存
    void *map_base = mmap(NULL, MEM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, MEM_ADDR_BASE);
    if (map_base == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return -1;
    }

    volatile uint64_t *fft_write_ptr = (volatile uint64_t *) (map_base + (FFT_WRITE_LANE - MEM_ADDR_BASE));
    volatile uint64_t *fft_rd_ptr_base = (volatile uint64_t *) (map_base + (FFT_RD_LANE_BASE - MEM_ADDR_BASE));

    // // print all input values
    // printf("Input points:\n");
    // for (int i = 0; i < num_points; i++) {
    //     printf("Point %d: 0x%016" PRIx64 "\n", i, points[i]);
    // }

    // write points to FFT
    for (int i = 0; i < num_points; i++) {
        *fft_write_ptr = points[i];
    }

    // read back and check values
    printf("\nFFT Output:\n");
    for (int i = 0; i < num_points; i++) {
        uint64_t read_val = *(fft_rd_ptr_base + i);  // FFT_RD_LANE_BASE + i * 8
        uint32_t real_part = (uint32_t)(read_val >> 32);
        uint32_t imag_part = (uint32_t)(read_val & 0xFFFFFFFF);

        int32_t real_signed = signExtend(real_part);
        int32_t imag_signed = signExtend(imag_part);

        printf("Output %d: Real: ", i + 1);
        printFixedPoint(real_signed, 8);  // 假設小數部分佔 8 位
        printf(", Imaginary: ");
        printFixedPoint(imag_signed, 8);
        printf("\n");
    }

    // printf("PASS: FFT Test Passed\n");

    // 取消映射並關閉文件
    munmap(map_base, MEM_SIZE);
    close(fd);

    return 0;
}