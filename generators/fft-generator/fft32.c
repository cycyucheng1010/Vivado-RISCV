/* This Test should be used with the fft generator config -- FFTRocketConfig. */

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

// from generators/fft-generator/test_pts.py (in the fft-generator repo)
// point size (and therefore integer width/uint32_t) determined by IOWidth from Tail.scala
// point size is 2 * IOWidth since both real and imaginary components get IOWidth bits

const uint32_t points[8] = {
  
  0b00000000101101011111111101001011, // 00B5FF4B
  0b00000000000000001111111100000000, // 0000FF00
  0b11111111010010111111111101001011, // FF4BFF4B
  0b11111111000000000000000000000000, // FF000000
  0b11111111010010110000000010110101, // FF4B00B5
  0b00000000000000000000000100000000, // 00000100
  0b00000000101101010000000010110101, // 00B500B5
  0b00000001000000000000000000000000  // 01000000
};

const uint32_t expected_outputs[8] = {
  0x00000000, // read 0
  0x00000000, // read 1
  0x00000000, // read 2
  0xffff0000, // read 3 -- real portion is 0xff (very small negative number)
  0x00000000, // read 4
  0x00000000, // read 5
  0x00000000, // read 6
  0x05a8fa57, // read 7 -- real: ~5.656 imaginary: ~-5.656
};

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

  volatile uint32_t *fft_write_ptr = (volatile uint32_t *) (map_base + (FFT_WRITE_LANE - MEM_ADDR_BASE));
  volatile uint32_t *fft_rd_ptr_base = (volatile uint32_t *) (map_base + (FFT_RD_LANE_BASE - MEM_ADDR_BASE));

  // print all input values
  printf("Input points:\n");
  for (int i = 0; i < num_points; i++) {
    printf("Point %d: 0x%08x\n", i, points[i]);
  }

  // write points to FFT
  for (int i = 0; i < num_points; i++) {
    *fft_write_ptr = points[i];
  }

  // read back and check values
  for (int i = 0; i < num_points; i++) {
    uint32_t read_val = *(fft_rd_ptr_base + (i * 2));  // FFT_RD_LANE_BASE + i * 8
    printf("Output %d: 0x%08x, Expected: 0x%08x\n", i, read_val, expected_outputs[i]);
     if (read_val != expected_outputs[i]) {
       printf("Value Error: Output %d: 0x%08x, Expected: 0x%08x\n", i, read_val, expected_outputs[i]);
       munmap(map_base, MEM_SIZE);
       close(fd);
       return -1;
     }
  }

  printf("PASS: FFT Test Passed\n");

  // 取消映射并关闭文件
  munmap(map_base, MEM_SIZE);
  close(fd);

  return 0;
}
