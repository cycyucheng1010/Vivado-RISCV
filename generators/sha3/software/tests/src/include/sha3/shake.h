#ifndef __SHAKE_H
#define __SHAKE_H
#include "sha3.h"
#include <stdio.h>
#include <string.h>

// Initialize SHAKE context
void shake_init(sha3_state *sctx, int security_level) {
    memset(sctx, 0, sizeof(*sctx));

    if (security_level == 128) {
        sctx->rsiz = 200 - 2 * (128 / 8);
    } else if (security_level == 256) {
        sctx->rsiz = 200 - 2 * (256 / 8);
    } 
    else {
        fprintf(stderr, "Invalid security level for SHAKE: %d\n", security_level);
        return;
    }
    sctx->md_len = 0; // No fixed digest size for XOF
    sctx->rsizw = sctx->rsiz / 8;
}

// Absorb data into SHAKE state
#define shake_update sha3_update


// Extract output from SHAKE state
void shake_out(sha3_state *sctx, uint8_t *out, size_t len) {
    size_t i;
    unsigned int j;

    if (sctx->partial != 0) {
        sctx->buf[sctx->partial] ^= 0x1F; // Padding for SHAKE
        sctx->buf[sctx->rsiz - 1] |= 0x80;

        //printf("Buffer after padding:\n");
        
        for (i = 0; i < sctx->rsizw; i++) {
            sctx->st[i] ^= ((uint64_t *)sctx->buf)[i];
        }

        // printf("State before Keccak-f:\n");
        // printState(sctx->st);

        keccakf(sctx->st, KECCAK_ROUNDS);

        // printf("State after Keccak-f:\n");
        // printState(sctx->st);

        sctx->partial = 0;
    }

    j = sctx->partial;

    for (i = 0; i < len; i++) {
        if (j >= sctx->rsiz) {
            // printf("State before next squeeze (Keccak-f):\n");
            // printState(sctx->st);

            keccakf(sctx->st, KECCAK_ROUNDS);
            j = 0;

            // printf("State after next squeeze (Keccak-f):\n");
            // printState(sctx->st);
        }
        out[i] = ((uint8_t *)sctx->st)[j++];
    }
    sctx->partial = j;
}

#endif // __SHAKE_H