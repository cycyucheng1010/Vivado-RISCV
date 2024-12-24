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

pthread_barrier_t barrier;

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

struct sha3_params {
  unsigned char* input;
  size_t input_size;
  unsigned char* output;
  int accelerator_id; // 2 for Accelerator 1, 3 for Accelerator 2
};

void* sha3_accelerator(void* arg) {
  struct sha3_params* params = (struct sha3_params*)arg;

  int cpu = sched_getcpu();
  printf("Accelerator %d: Starting on CPU %d\n", params->accelerator_id, cpu);

  pthread_barrier_wait(&barrier); // Wait for both threads to be ready
  uint64_t start = rdtime();//cpucycles();
  // Use the appropriate accelerator
  if(params->accelerator_id==2){
    sha3ONE(params->input, params->input_size, params->output);
  }
  else if(params->accelerator_id==3){
    sha3ONE(params->input, params->input_size, params->output);
  }
  else{
    perror("opcode error");
  }
  uint64_t end = rdtime();//cpucycles();
  printf("Accelerator %d: Finished. Cycles taken: %lu\n", params->accelerator_id, end - start);
  printf("Thread %d execution: Start cycle: %lu, End cycle: %lu\n", params->accelerator_id, start, end);
  return NULL;
}

int main() {
  pthread_t thread1, thread2;
  cpu_set_t cpuset1, cpuset2;

  if (pthread_barrier_init(&barrier, NULL, 2) != 0) {
    perror("Failed to initialize barrier");
    return EXIT_FAILURE;
  }

  // Configure CPU affinity for thread1 to CPU 0
  CPU_ZERO(&cpuset1);
  CPU_SET(0, &cpuset1);

  // Configure CPU affinity for thread2 to CPU 1
  CPU_ZERO(&cpuset2);
  CPU_SET(1, &cpuset2);

  struct sha3_params params1 = {input1, sizeof(input1), output1, 2};
  struct sha3_params params2 = {input2, sizeof(input2), output2, 3};

  // Start thread1 and bind to CPU 0
  if (pthread_create(&thread1, NULL, sha3_accelerator, &params1) != 0) {
    perror("Failed to create thread 1");
    return EXIT_FAILURE;
  }
  if (pthread_setaffinity_np(thread1, sizeof(cpu_set_t), &cpuset1) != 0) {
    perror("Failed to set thread 1 affinity");
    return EXIT_FAILURE;
  }

  // Start thread2 and bind to CPU 1
  if (pthread_create(&thread2, NULL, sha3_accelerator, &params2) != 0) {
    perror("Failed to create thread 2");
    return EXIT_FAILURE;
  }
  if (pthread_setaffinity_np(thread2, sizeof(cpu_set_t), &cpuset2) != 0) {
    perror("Failed to set thread 2 affinity");
    return EXIT_FAILURE;
  }

  // Wait for both threads to complete
  pthread_join(thread1, NULL);
  pthread_join(thread2, NULL);

  // Destroy the barrier
  pthread_barrier_destroy(&barrier);

  // Print results
  printf("Main: Accelerator results:\n");
  for (int i = 0; i < SHA3_256_DIGEST_SIZE; i++) {
    printf("output1[%d]:%d ==? output2[%d]:%d \n", i, params1.output[i], i, params2.output[i]);
  }
  printf("\n");
  return 0;
}
