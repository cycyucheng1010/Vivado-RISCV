// Define reference (software) sha3 

#ifndef __SHAKE_H
#define __SHAKE_H
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
//#include "sha3.h"


// 定義 SHAKE128 和 SHAKE256 的參數
#define SHAKE128_RATE (200 - 2 * (128 / 8))  // r = 168 bytes
#define SHAKE256_RATE (200 - (2 * (256 / 8)))  // r = 136 bytes

#define KECCAK_ROUNDS 24 //Keccak algorithm will run 24 rounds

//left-handed, rotate y bits
#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))

//shake state structure
typedef struct {
  uint64_t st[25]; // states: 25 64-bit integer  --> 1600bits(r+c) , in sloth is uint8_t d
  unsigned int md_len; //hash length, e.g. 256-bit -> 32 words , in sloth is uint8_t b 
  unsigned int rsiz; // absorb block size (process size)
  unsigned int rsizw; //absorb block size per 64-bit
  
  unsigned int partial; //record partial data size
  uint8_t buf[SHAKE256_RATE];   //unsaved data
} shake_state;

static const uint64_t keccakf_rndc[24] = 
  {
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
    0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 
    0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008
  };
//rotate-value in Rho
static const int keccakf_rotc[24] = 
  {
    1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14, 
    27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
  };
//rotate-value in Pi
static const int keccakf_piln[24] = 
  {
    10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4, 
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1 
  };

static void keccakf(uint64_t st[25], int rounds)
{
  int i, j, round_num;
  uint64_t t, bc[5];

  for (round_num = 0; round_num < rounds; round_num++) 
  {
    // Theta  bc[i]=st[i]⊕st[i+5]⊕st[i+10]⊕st[i+15]⊕st[i+20]
    for (i = 0; i < 5; i++) 
      bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
    
    for (i = 0; i < 5; i++) 
    {
      t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
      for (j = 0; j < 25; j += 5)
  st[j + i] ^= t;
      }

    // Rho  st[i]=ROTL64(st[i],keccakf_rotc[i])
    //Pi  st[j]=st[keccakf_piln[i]]
    t = st[1];
    for (i = 0; i < 24; i++) 
    {
      j = keccakf_piln[i];
      bc[0] = st[j];
      st[j] = ROTL64(t, keccakf_rotc[i]);
      t = bc[0];
    }

    //  Chi st[j+i]=st[j+i]⊕(¬st[j+(i+1)%5])&st[j+(i+2)%5]
    for (j = 0; j < 25; j += 5) 
    {
      for (i = 0; i < 5; i++)
  bc[i] = st[j + i];
      for (i = 0; i < 5; i++)
  st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
    }

    //  Iota st[0]=st[0]⊕keccakf_rndc[round_num]
    st[0] ^= keccakf_rndc[round_num];
    
  }
}

void shake128_init(shake_state *sctx) {
    memset(sctx, 0, sizeof(*sctx));
    sctx->md_len = 16;//0,16.32        // SHAKE 可變長度輸出
    sctx->rsiz = SHAKE128_RATE; // 設定吸收率
    sctx->rsizw = sctx->rsiz / 8;
}

// 初始化 SHAKE256 狀態
void shake256_init(shake_state *sctx) {
    memset(sctx, 0, sizeof(*sctx));
    sctx->md_len = 32;//0,32,64        // SHAKE 可變長度輸出
    sctx->rsiz = SHAKE256_RATE; // 設定吸收率
    sctx->rsizw = sctx->rsiz / 8;
}


void shake_update(shake_state *sctx, const uint8_t *data, unsigned int len) {
    unsigned int done;
  const uint8_t *src;

  done = 0;
  src = data;

  if ((sctx->partial + len) > (sctx->rsiz - 1)) 
  {
    if (sctx->partial) 
    {
      done = -sctx->partial;
      memcpy(sctx->buf + sctx->partial, data,
       done + sctx->rsiz);
      src = sctx->buf;
    }

    do {
      unsigned int i;

      for (i = 0; i < sctx->rsizw; i++)
  sctx->st[i] ^= ((uint64_t *) src)[i];
      keccakf(sctx->st, KECCAK_ROUNDS);

      done += sctx->rsiz;
      src = data + done;
    } while (done + (sctx->rsiz - 1) < len);

    sctx->partial = 0;
  }
  memcpy(sctx->buf + sctx->partial, src, len - done);
  sctx->partial += (len - done);
}

void shake_xof(shake_state *sctx) {
    unsigned int inlen = sctx->partial;

    // 填充邏輯
    
    sctx->buf[inlen++] = 0x1F;  // 定义SHAKE的pad值
    memset(sctx->buf + inlen, 0, sctx->rsiz - inlen); // 清零剩餘部分
    sctx->buf[sctx->rsiz - 1] |= 0x80;  // 設置終止位

    // 調試打印填充後的緩衝區
    printf("Buffer after padding:\n");
    for (unsigned int i = 0; i < sctx->rsiz; i++) {
        printf("%02x ", sctx->buf[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }

    // 吸收填充值
    for (unsigned int i = 0; i < sctx->rsizw; i++) {
        sctx->st[i] ^= ((uint64_t *)sctx->buf)[i];
    }

    // 更新 Keccak 狀態
    keccakf(sctx->st, KECCAK_ROUNDS);

    // 調試打印狀態
    printf("State after absorb:\n");
    for (int i = 0; i < 25; i++) {
        printf("%016lx ", sctx->st[i]);
        if ((i + 1) % 5 == 0) printf("\n");
    }

    // 重置部分數據
    sctx->partial = 0;
}


void shake_out(shake_state *sctx, uint8_t *out, unsigned int outlen) {
    unsigned int i, idx = 0;

    while (outlen > 0) {
        //printf("Generating output: idx=%u, outlen=%u, partial=%u\n", idx, outlen, sctx->partial);

        // 如果部分数据已填满缓冲区，则挤出一轮
        if (sctx->partial == 0) {
            keccakf(sctx->st, KECCAK_ROUNDS);  // 状态更新
            sctx->partial = sctx->rsiz;        // 重置缓冲区大小
        }

        // 计算当前可挤出的字节数
        i = (outlen < sctx->partial) ? outlen : sctx->partial;

        // 将状态中的数据复制到输出缓冲区
        memcpy(out + idx, sctx->st, i);
        //memcpy(out + idx, (uint8_t *)sctx->st + (sctx->rsiz - sctx->partial), i);


        idx += i;           // 更新输出索引
        outlen -= i;        // 减少待输出的字节数
        sctx->partial -= i; // 减少缓冲区的剩余字节数
    }

    printf("Output generation complete. Total bytes generated: %u\n", idx);
}




#endif
