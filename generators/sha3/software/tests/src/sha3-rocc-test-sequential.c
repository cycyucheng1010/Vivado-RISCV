#define _GNU_SOURCE 
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sched.h>  // for CPU_ZERO, CPU_SET, pthread_setaffinity_np()
#include <pthread.h>
#include <sys/mman.h>
#include "include/sha3/rocc.h"
#include "include/sha3/sha3.h"
#include "include/sha3/encoding.h"
#include "include/sha3/compiler.h"

#define SHA3_256_DIGEST_SIZE (256 / 8)

// Input and output buffers for the accelerators
unsigned char input1[150] __aligned(8) = { '\0' };
unsigned char output1[SHA3_256_DIGEST_SIZE] __aligned(8);
unsigned char input2[150] __aligned(8) = { '\0' };
unsigned char output2[SHA3_256_DIGEST_SIZE] __aligned(8);

/*   speed test   */ //sample as rdcycle()
static inline uint64_t cpucycles(void) {
  uint64_t result;

  __asm__ volatile ("rdcycle %0" : "=r" (result));

  return result;
}


void* sha3_accelerator1(void* arg) {
  int cpu = sched_getcpu();
  printf("Accelerator 1: Starting on CPU %d\n", cpu);

  unsigned long start1, end1;
  start1 = rdcycle();
  // Using accelerator 1 (opcode: 2)
  ROCC_INSTRUCTION(2,2);
  asm volatile("fence rw,rw" ::: "memory");
  ROCC_INSTRUCTION_SS(2, &input1, &output1, 0); // Set input and output
  ROCC_INSTRUCTION_S(2, sizeof(input1), 1);     // Set length and start computation
  asm volatile("fence" ::: "memory");
  end1 = rdcycle();
  printf("Accelerator 1: Finished. Cycles taken: %lu\n", end1 - start1);
  printf("Thread 1 execution: Start cycle: %lu, End cycle: %lu\n", start1, end1);
  return NULL;
}

void* sha3_accelerator2(void* arg) {
  int cpu = sched_getcpu();
  printf("Accelerator 2: Starting on CPU %d\n", cpu);

  unsigned long start2, end2;
  start2 = rdcycle();
  // Using accelerator 2 (opcode: 3)
  ROCC_INSTRUCTION(3,2);
  asm volatile("fence rw,rw" ::: "memory");
  ROCC_INSTRUCTION_SS(3, &input2, &output2, 0); // Set input and output
  ROCC_INSTRUCTION_S(3, sizeof(input2), 1);     // Set length and start computation
  asm volatile("fence" ::: "memory");
  end2 = rdcycle();
  printf("Accelerator 2: Finished. Cycles taken: %lu\n", end2 - start2);
  printf("Thread 2 execution: Start cycle: %lu, End cycle: %lu\n", start2, end2);
  return NULL;
}

int main() {

  unsigned long start, end;
  sha3_accelerator1(NULL);
  sha3_accelerator2(NULL);

  // Print results
  printf("Main: Accelerator results:\n");
  for (int i = 0; i < SHA3_256_DIGEST_SIZE; i++) {
    printf("output1[%d]:%d ==? output2[%d]:%d \n", i, output1[i], i, output2[i]);
  }
  printf("\n");
  //printf("Total Accelerator Cycles taken: %lu\n", end - start);
  return 0;
}
