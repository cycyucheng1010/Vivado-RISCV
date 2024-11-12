#include <stdio.h>
#include <stdint.h>
#include "include/sha3.h"
#include "include/rocc.h"
#include "include/encoding.h"
#include "include/compiler.h"

#define SPHINICS_HASH_SIZE SHA3_256_DIGEST_SIZE

// 公開金鑰
typedef struct {
    uint8_t root[SPHINCS_HASH_SIZE];
} spx_public_key;

// 私鑰
typedef struct {
    uint8_t sk_seed[SPHINCS_HASH_SIZE];
    uint8_t pk_seed[SPHINCS_HASH_SIZE];
} spx_private_key;

// SPHINCS 簽名
typedef struct {
    uint8_t random[SPHINCS_HASH_SIZE];
    uint8_t message_hash[SPHINCS_HASH_SIZE];
} spx_signature;


int main() {
  return 0;
}