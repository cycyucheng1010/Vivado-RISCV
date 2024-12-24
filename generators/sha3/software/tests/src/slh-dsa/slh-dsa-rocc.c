#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "plat_local.h"
#include "sha3_api.h"
#include "slh_dsa.h"
#include "slh_ctx.h"
#include "slh_adrs.h"
#include "kat_drbg.h"
#include "rocc.h"
#include "encoding.h"




//slh_dsa.c
//  === Internal
//  helper functions to compute "len = len1 + len2"
static inline uint32_t get_len1(const slh_param_t *prm)
{
    return ((8 * prm->n + prm->lg_w - 1) / prm->lg_w);
}

static inline uint32_t get_len2(const slh_param_t *prm)
{
#ifdef NDEBUG
    (void) prm;
#endif
    //  Appedix B:
    //  "When lg_w = 4 and 9 <= n <= 136, the value of len2 will be 3."
    assert(prm->lg_w == 4 && prm->n >= 9 && prm->n <= 136);
    return 3;
}
static inline uint32_t get_len(const slh_param_t *prm)
{
    return  get_len1(prm) + get_len2(prm);
}

//  Return signature size in bytes for parameter set *prm.
size_t slh_sig_sz(const slh_param_t *prm)
{
    return  (1 + prm->k*(1 + prm->a) + prm->h + prm->d * get_len(prm)) * prm->n;
}

//  === Compute the base 2**b representation of X.
//  Algorithm 3: base_2b(X, b, out_len)

static inline size_t base_2b(   uint32_t *v, const uint8_t *x,
                                uint32_t b, size_t v_len)
{
    size_t i, j;
    uint32_t l, t, m;

    j = 0;
    l = 0;
    t = 0;
    m = (1 << b) - 1;
    for (i = 0; i < v_len; i++) {
        while (l < b) {
            t = (t << 8) + x[j++];
            l += 8;
        }
        l -= b;
        v[i] = (t >> l) & m;
    }
    return j;
}

//  little bit faster version for b = 4

static inline size_t base_16(   uint32_t *v, const uint8_t *x, int v_len)
{
    int i, j, l, t;

    j = 0;
    for (i = 0; i < v_len - 2; i += 2) {
        t = x[j++];
        v[i]     = t >> 4;
        v[i + 1] = t & 0xF;
    }

    l = 0;
    t = 0;
    for (; i < v_len; i++) {
        while (l < 4) {
            t = (t << 8) + x[j++];
            l += 8;
        }
        l -= 4;
        v[i] = (t >> l) & 0xF;
    }
    return j;
}

//  === Chaining function used in WOTS+
//  Algorithm 4: chain(X, i, s, PK.seed, ADRS)
//  (see prm->chain)

//  === Generate a WOTS+ public key.
//  Algorithm 5: wots_PKgen(SK.seed, PK.seed, ADRS)
//  (see xmms_node)

//  === Generate a WOTS+ signature on an n-byte message.
//  Algorithm 6: wots_sign(M, SK.seed, PK.seed, ADRS)

//  (wots_csum is a shared helper function for algorithms 6 and 7)
static void wots_csum(uint32_t *vm, const uint8_t *m, const slh_param_t *prm)
{
    uint32_t csum, i, t;
    uint32_t len1, len2;
    uint8_t buf[4];

    len1 = get_len1(prm);
    len2 = get_len2(prm);

    //base_2b(vm, m, prm->lg_w, len1);
    base_16(vm, m, len1);

    csum = 0;
    t = (1 << prm->lg_w) - 1;
    for (i = 0; i < len1; i++) {
        csum += t - vm[i];
    }
    csum <<= (8 - ((len2 * prm->lg_w) & 7)) & 7;

    t = (len2 * prm->lg_w + 7) / 8;
    memset(buf, 0, sizeof(buf));
    slh_tobyte(buf, csum, t);

    //base_2b(&vm[len1], buf, prm->lg_w, len2);
    base_16(&vm[len1], buf, len2);
}

static size_t wots_sign(slh_ctx_t *ctx, uint8_t *sig, const uint8_t *m)
{
    const slh_param_t *prm = ctx->prm;
    uint32_t i, len;
    uint32_t vm[SLH_MAX_LEN];
    size_t n = prm->n;

    len = get_len(prm);
    wots_csum(vm, m, prm);

    for (i = 0; i < len; i++) {
        adrs_set_chain_address(ctx, i);
        prm->wots_chain(ctx, sig, vm[i]);
        sig += n;
    }
    return n * len;
}

//  === Compute a WOTS+ public key from a message and its signature.
//  Algorithm 7: wots_PKFromSig(sig, M, PK.seed, ADRS)

static void wots_pk_from_sig(   slh_ctx_t *ctx, uint8_t *pk,
                                const uint8_t *sig,
                                const uint8_t *m)
{
    const slh_param_t *prm = ctx->prm;
    uint32_t i, t, len;
    uint32_t vm[SLH_MAX_LEN];
    uint8_t tmp[SLH_MAX_LEN * SLH_MAX_N];
    size_t n = prm->n;
    size_t tmp_sz;

    wots_csum(vm, m, prm);

    len = get_len(prm);
    t = 15; // (1 << prm->lg_w) - 1;
    tmp_sz = 0;
    for (i = 0; i < len; i++) {
        adrs_set_chain_address(ctx, i);
        prm->chain( ctx, tmp + tmp_sz, sig + tmp_sz, vm[i], t - vm[i]);
        tmp_sz += n;
    }

    adrs_set_type_and_clear_not_kp(ctx, ADRS_WOTS_PK);
    prm->h_t(ctx, pk, tmp, tmp_sz);
}

//  === Compute the root of a Merkle subtree of WOTS+ public keys.
//  Algorithm 8: xmss_node(SK.seed, i, z, PK.seed, ADRS)

static void xmss_node(  slh_ctx_t *ctx, uint8_t *node,
                        uint32_t i, uint32_t z)
{
    const slh_param_t *prm = ctx->prm;
    uint32_t j, k;
    int p;
    uint8_t *h0, h[SLH_MAX_HP][SLH_MAX_N];
    uint8_t tmp[SLH_MAX_LEN * SLH_MAX_N];
    uint8_t *sk;
    size_t n = prm->n;
    size_t len = get_len(prm);

    p = -1;
    i <<= z;
    for (j = 0; j < (1u << z); j++) {

        adrs_set_key_pair_address(ctx, i);

        //  === Generate a WOTS+ public key.
        //  Algorithm 5: wots_PKgen(SK.seed, PK.seed, ADRS)
        sk  = tmp;
        for (k = 0; k < len; k++) {
            adrs_set_chain_address(ctx, k);
            prm->wots_chain(ctx, sk, 15);   //  w-1 =  (1 << prm->lg_w) - 1;
            sk += n;
        }
        adrs_set_type_and_clear_not_kp(ctx, ADRS_WOTS_PK);
        h0 = p >= 0 ? h[p] : node;
        p++;
        prm->h_t(ctx, h0, tmp, len * n);

        //  this xmss_node() implementation is non-recursive
        for (k = 0; (j >> k) & 1; k++) {
            adrs_set_type_and_clear(ctx, ADRS_TREE);
            adrs_set_tree_height(ctx, k + 1);
            adrs_set_tree_index(ctx, i >> (k + 1));
            p--;
            h0 = p >= 1 ? h[p - 1] : node;
            prm->h_h(ctx, h0, h0, h[p]);
        }
        i++;        //  advance index
    }
}

//  === Generate an XMSS signature.
//  Algorithm 9: xmss_sign(M, SK.seed, idx, PK.seed, ADRS)

static size_t xmss_sign(slh_ctx_t *ctx, uint8_t *sx, const uint8_t *m,
                        uint32_t idx)
{

    const slh_param_t *prm = ctx->prm;
    uint32_t j, k;
    uint8_t *auth;
    size_t sx_sz = 0;
    size_t n = prm->n;

    sx_sz = get_len(prm) * n;
    auth = sx + sx_sz;

    for (j = 0; j < prm->hp; j++) {
        k = (idx >> j) ^ 1;
        xmss_node(ctx, auth, k, j);
        auth += n;
    }
    sx_sz += prm->hp * n;

    adrs_set_type_and_clear_not_kp(ctx, ADRS_WOTS_HASH);
    adrs_set_key_pair_address(ctx, idx);
    wots_sign(ctx, sx, m);

    return sx_sz;
}

//  === Compute an XMSS public key from an XMSS signature.
//  Algorithm 10: xmss_PKFromSig(idx, SIGXMSS, M, PK.seed, ADRS)

static void xmss_pk_from_sig(   slh_ctx_t *ctx, uint8_t *root, uint32_t idx,
                                const uint8_t *sig, const uint8_t *m)
{

    const slh_param_t *prm = ctx->prm;
    uint32_t k;
    const uint8_t *auth;
    size_t n = prm->n;

    adrs_set_type_and_clear_not_kp(ctx, ADRS_WOTS_HASH);
    adrs_set_key_pair_address(ctx, idx);

    wots_pk_from_sig(ctx, root, sig, m);
    adrs_set_type_and_clear(ctx, ADRS_TREE);

    auth = sig + (get_len(prm) * n);

    for (k = 0; k < prm->hp; k++) {

        adrs_set_tree_height(ctx, k + 1);
        adrs_set_tree_index(ctx, idx >> (k + 1));

        if (((idx >> k) & 1) == 0) {
            prm->h_h(ctx, root, root, auth);
        } else {
            prm->h_h(ctx, root, auth, root);
        }
        auth += n;
    }
}


//  === Generate a hypertree signature.
//  Algorithm 11: ht_sign(M, SK.seed, PK.seed, idx_tree, idx_leaf )

static size_t ht_sign(  slh_ctx_t *ctx, uint8_t *sh, uint8_t *m,
                        uint64_t i_tree, uint32_t i_leaf)
{

    const slh_param_t *prm = ctx->prm;
    uint32_t j;
    size_t sx_sz;

    adrs_zero(ctx);
    adrs_set_tree_address(ctx, i_tree);
    sx_sz = xmss_sign(ctx, sh, m, i_leaf);

    for (j = 1; j < prm->d; j++) {
        xmss_pk_from_sig(ctx, m, i_leaf, sh, m);
        sh += sx_sz;

        i_leaf = i_tree & ((1 << prm->hp) - 1);
        i_tree >>= prm->hp;
        adrs_set_layer_address(ctx, j);
        adrs_set_tree_address(ctx, i_tree);
        xmss_sign( ctx, sh, m, i_leaf);
    }

    return sx_sz * prm->d;
}


//  === Verify a hypertree signature.
//  Algorithm 12: ht_verify(M, SIG_HT, PK.seed, idx_tree, idx_leaf, PK.root)

static bool ht_verify(  slh_ctx_t *ctx, const uint8_t *m,
                        const uint8_t *sig_ht,
                        uint64_t i_tree, uint32_t i_leaf)
{
    const slh_param_t *prm = ctx->prm;
    uint32_t i, j;
    uint8_t node[SLH_MAX_N];
    size_t st_sz;

    adrs_zero(ctx);
    adrs_set_tree_address(ctx, i_tree);

    xmss_pk_from_sig(ctx, node, i_leaf, sig_ht, m);

    st_sz = (prm->hp + get_len(prm)) * prm->n;
    for (j = 1; j < prm->d; j++) {
        i_leaf = i_tree & ((1 << prm->hp) - 1);
        i_tree >>= prm->hp;
        adrs_set_layer_address(ctx, j);
        adrs_set_tree_address(ctx, i_tree);
        sig_ht += st_sz;
        xmss_pk_from_sig(ctx, node, i_leaf, sig_ht, node);
    }

    uint8_t t;
    t = 0;
    for (i = 0; i < prm->n; i++) {
        t |= node[i] ^ ctx->pk_root[i];
    }
    return t == 0;
}

//  === Generate a FORS private-key value.
//  Algorithm 13: fors_SKgen(SK.seed, PK.seed, ADRS, idx)

//  ( see prm->fors_hash() )

//  === Compute the root of a Merkle subtree of FORS public values.
//  Algorithm 14: fors_node(SK.seed, i, z, PK.seed, ADRS)

static void fors_node(  slh_ctx_t *ctx, uint8_t *node,
                        uint32_t i, uint32_t z)
{
    const slh_param_t *prm = ctx->prm;
    uint8_t h[SLH_MAX_A][SLH_MAX_N], *h0;
    uint32_t j, k;
    int p;

    p = -1;
    i <<= z;
    for (j = 0; j < (1u << z); j++) {


        //  fors_SKgen() + hash
        adrs_set_tree_index(ctx, i);
        h0 = p >= 0 ? h[p] : node;
        p++;
        prm->fors_hash(ctx, h0, 1);

        //  this fors_node() implementation is non-recursive
        for (k = 0; (j >> k) & 1; k++) {
            adrs_set_tree_height(ctx, k + 1);
            adrs_set_tree_index(ctx, i >> (k + 1));
            p--;
            h0 = p > 0 ? h[p - 1] : node;
            prm->h_h(ctx, h0, h0, h[p]);
        }
        i++;        //  advance index
    }
}


//  === Generate a FORS signature.
//  Algorithm 15: fors_sign(md, SK.seed, PK.seed, ADRS)

static size_t fors_sign(slh_ctx_t *ctx, uint8_t *sf, const uint8_t *md)
{
    const slh_param_t *prm = ctx->prm;
    uint32_t i, j, s;
    uint32_t vi[SLH_MAX_K];
    size_t  n = prm->n;

    assert(SLH_MAX_K >= prm->k);
    base_2b(vi, md, prm->a, prm->k);

    for (i = 0; i < prm->k; i++) {

        //  fors_SKgen()
        adrs_set_tree_index(ctx, (i << prm->a) + vi[i]);
        prm->fors_hash(ctx, sf, 0);
        sf += n;

        for (j = 0; j < prm->a; j++) {
            s = (vi[i] >> j) ^ 1;
            fors_node(  ctx, sf, (i << (prm->a - j)) + s, j);
            sf += n;
        }
    }
    return n * prm->k * (1 + prm->a);
}

//  === Compute a FORS public key from a FORS signature.
//  Algorithm 16: fors_pkFromSig(SIGFORS , md, PK.seed, ADRS)

static void fors_pk_from_sig(   slh_ctx_t *ctx, uint8_t *pk,
                                const uint8_t *sf, const uint8_t *md)
{

    const slh_param_t *prm = ctx->prm;
    uint32_t i, j, idx;
    uint32_t vi[SLH_MAX_K];
    uint8_t root[SLH_MAX_K * SLH_MAX_N];
    uint8_t *node;
    size_t  n = prm->n;

    base_2b(vi, md, prm->a, prm->k);

    node = root;
    for (i = 0; i < prm->k; i++) {

        adrs_set_tree_height(ctx, 0);

        idx = (i << prm->a) + vi[i];
        adrs_set_tree_index(ctx, idx);

        prm->h_f(ctx, node, sf);
        sf += n;

        for (j = 0; j < prm->a; j++) {

            adrs_set_tree_height(ctx, j + 1);
            adrs_set_tree_index(ctx, idx >> (j + 1));

            if (((vi[i] >> j) & 1) == 0) {
                prm->h_h(ctx, node, node, sf);
            } else {
                prm->h_h(ctx, node, sf, node);
            }
            sf += n;
        }
        node += n;
    }

    adrs_set_type_and_clear_not_kp(ctx, ADRS_FORS_ROOTS);
    prm->h_t(ctx, pk, root, prm->k * n);
}

//  === Public API

//  Return standard identifier string for parameter set *prm, or NULL.
const char *slh_alg_id(const slh_param_t *prm)
{
    return prm->alg_id;
}

//  Return public (verification) key size in bytes for parameter set *prm.
size_t slh_pk_sz(const slh_param_t *prm)
{
    return 2 * prm->n;
}

//  Return private (signing) key size in bytes for parameter set *prm.
size_t slh_sk_sz(const slh_param_t *prm)
{
    return 4 * prm->n;
}

//  === Generate an SLH-DSA key pair.
//  Algorithm 17: slh_keygen()

int slh_keygen(uint8_t *pk, uint8_t *sk,
               int (*rbg)(uint8_t *x, size_t xlen), const slh_param_t *prm)
{

    slh_ctx_t   ctx;
    uint8_t     pk_root[SLH_MAX_N];
    size_t      n = prm->n;

    rbg(sk, 3 * n);    
                     //  SK.seed || SK.prf || PK.seed
    memcpy(pk, sk + 2 * n, n);          //  PK.seed
    memset(sk + 3 * n, 0x00, n);        //  PK.root not generated yet
    prm->mk_ctx(&ctx, NULL, sk, prm);   //  fill in partial

    adrs_zero(&ctx);
    adrs_set_layer_address(&ctx, prm->d - 1);
    xmss_node(&ctx, pk_root, 0, prm->hp);

    printf("\n");
    //  fill pk_root
    memcpy(sk + 3 * n, pk_root, n);
    memcpy(pk + n, pk_root, n);
    return 0;
}

//  === Generate an SLH-DSA signature.
//  Algorithm 18: slh_sign(M, SK)

//  (Shared helper function for algorithms 18 and 19.)

static void split_digest(uint64_t *i_tree, uint32_t *i_leaf,
                         const uint8_t *digest, const slh_param_t *prm)
{
    size_t      md_sz       = (prm->k * prm->a + 7) / 8;
    const uint8_t *pi_tree  = digest + md_sz;
    size_t      i_tree_sz   = (prm->h - prm->hp + 7) / 8;
    *i_tree     = slh_toint(pi_tree, i_tree_sz);
    size_t      i_leaf_sz   = (prm->hp + 7) / 8;
    const uint8_t *pi_leaf  = pi_tree + i_tree_sz;
    *i_leaf     = slh_toint(pi_leaf, i_leaf_sz);
    if ((prm->h - prm->hp) != 64) {
        *i_tree     &= (UINT64_C(1) << (prm->h - prm->hp)) - UINT64_C(1);
    }
    *i_leaf     &= (1 << prm->hp) - 1;
}

//  Core signing function that just takes in "digest" and an already
//  initialized secret key context. *sig points to signature after randomizer.
//  Returns the length of |SIG_FORS + SIG_HT| written at *sig.

size_t slh_do_sign( slh_ctx_t *ctx, uint8_t *sig, const uint8_t *digest)
{
    const uint8_t   *md = digest;
    uint64_t i_tree = 0;
    uint32_t i_leaf = 0;
    uint8_t pk_fors[SLH_MAX_N];
    size_t sig_sz;

    split_digest(&i_tree, &i_leaf, digest, ctx->prm);

    adrs_zero(ctx);
    adrs_set_tree_address(ctx, i_tree);
    adrs_set_type_and_clear_not_kp(ctx, ADRS_FORS_TREE);
    adrs_set_key_pair_address(ctx, i_leaf);

    //  SIG_FORS
    sig_sz  = fors_sign(ctx, sig, md);
    fors_pk_from_sig(ctx, pk_fors, sig, md);

    //  SIG_HT
    sig +=  sig_sz;
    sig_sz  += ht_sign(ctx, sig, pk_fors, i_tree, i_leaf);

    return sig_sz;
}

size_t slh_sign(uint8_t *sig, const uint8_t *m, size_t m_sz,
                const uint8_t *sk, int (*rbg)(uint8_t *x, size_t xlen),
                const slh_param_t *prm)
{
    slh_ctx_t   ctx;
    uint8_t opt_rand[SLH_MAX_N];
    uint8_t digest[SLH_MAX_M];

    //  set up secret key etc
    prm->mk_ctx(&ctx, NULL, sk, prm);

#ifdef SLH_DETERMINISTIC
    memcpy(opt_rand, ctx.pk_seed, prm->n);
#else
    rbg(opt_rand, prm->n);
#endif

    //  randomized hashing; R
    uint8_t *r  = sig;
    size_t  sig_sz = prm->n;
    prm->prf_msg(&ctx, r, opt_rand, m, m_sz);
    prm->h_msg(&ctx, digest, r, m, m_sz);

    //  create FORS and HT signature parts
    sig_sz += slh_do_sign(&ctx, sig + sig_sz, digest);

    return sig_sz;
}

//  === Verify an SLH-DSA signature.
//  Algorithm 19: slh_verify(M, SIG, PK)

bool slh_verify(const uint8_t *m, size_t m_sz,
                const uint8_t *sig, const uint8_t *pk,
                const slh_param_t *prm)
{

    slh_ctx_t   ctx;
    uint8_t digest[SLH_MAX_M];
    uint8_t pk_fors[SLH_MAX_N];

    const uint8_t   *r          = sig;
    const uint8_t   *sig_fors   = sig + prm->n;
    const uint8_t   *sig_ht     = sig + ((1 + prm->k*(1 + prm->a)) * prm->n);

    prm->mk_ctx(&ctx, pk, NULL, prm);
    prm->h_msg(&ctx, digest, r, m, m_sz);

    const uint8_t   *md = digest;
    uint64_t        i_tree = 0;
    uint32_t        i_leaf = 0;
    split_digest(&i_tree, &i_leaf, digest, prm);

    adrs_zero(&ctx);
    adrs_set_tree_address(&ctx, i_tree);
    adrs_set_type_and_clear_not_kp(&ctx, ADRS_FORS_TREE);
    adrs_set_key_pair_address(&ctx, i_leaf);

    fors_pk_from_sig(&ctx, pk_fors, sig_fors, md);

    bool sig_ok = ht_verify(&ctx, pk_fors, sig_ht, i_tree, i_leaf);
    return sig_ok;
}

//  kat_drbg.c
//  Markku-Juhani O. Saarinen <mjos@iki.fi>.  See LICENSE.

//  === Provides a randombytes() compatible "fake" AES-based NIST DRBG.
//  Only for KAT testing use; Non-constant time.

/*
 *  AES derived from optimised ANSI C code for the Rijndael cipher.
 *  Vincent Rijmen <vincent.rijmen@esat.kuleuven.ac.be>
 *  Antoon Bosselaers <antoon.bosselaers@esat.kuleuven.ac.be>
 *  Paulo Barreto <paulo.barreto@terra.com.br>
 */

static const uint32_t ttab[256] = {
    0xA56363C6, 0x847C7CF8, 0x997777EE, 0x8D7B7BF6, 0x0DF2F2FF, 0xBD6B6BD6,
    0xB16F6FDE, 0x54C5C591, 0x50303060, 0x03010102, 0xA96767CE, 0x7D2B2B56,
    0x19FEFEE7, 0x62D7D7B5, 0xE6ABAB4D, 0x9A7676EC, 0x45CACA8F, 0x9D82821F,
    0x40C9C989, 0x877D7DFA, 0x15FAFAEF, 0xEB5959B2, 0xC947478E, 0x0BF0F0FB,
    0xECADAD41, 0x67D4D4B3, 0xFDA2A25F, 0xEAAFAF45, 0xBF9C9C23, 0xF7A4A453,
    0x967272E4, 0x5BC0C09B, 0xC2B7B775, 0x1CFDFDE1, 0xAE93933D, 0x6A26264C,
    0x5A36366C, 0x413F3F7E, 0x02F7F7F5, 0x4FCCCC83, 0x5C343468, 0xF4A5A551,
    0x34E5E5D1, 0x08F1F1F9, 0x937171E2, 0x73D8D8AB, 0x53313162, 0x3F15152A,
    0x0C040408, 0x52C7C795, 0x65232346, 0x5EC3C39D, 0x28181830, 0xA1969637,
    0x0F05050A, 0xB59A9A2F, 0x0907070E, 0x36121224, 0x9B80801B, 0x3DE2E2DF,
    0x26EBEBCD, 0x6927274E, 0xCDB2B27F, 0x9F7575EA, 0x1B090912, 0x9E83831D,
    0x742C2C58, 0x2E1A1A34, 0x2D1B1B36, 0xB26E6EDC, 0xEE5A5AB4, 0xFBA0A05B,
    0xF65252A4, 0x4D3B3B76, 0x61D6D6B7, 0xCEB3B37D, 0x7B292952, 0x3EE3E3DD,
    0x712F2F5E, 0x97848413, 0xF55353A6, 0x68D1D1B9, 0x00000000, 0x2CEDEDC1,
    0x60202040, 0x1FFCFCE3, 0xC8B1B179, 0xED5B5BB6, 0xBE6A6AD4, 0x46CBCB8D,
    0xD9BEBE67, 0x4B393972, 0xDE4A4A94, 0xD44C4C98, 0xE85858B0, 0x4ACFCF85,
    0x6BD0D0BB, 0x2AEFEFC5, 0xE5AAAA4F, 0x16FBFBED, 0xC5434386, 0xD74D4D9A,
    0x55333366, 0x94858511, 0xCF45458A, 0x10F9F9E9, 0x06020204, 0x817F7FFE,
    0xF05050A0, 0x443C3C78, 0xBA9F9F25, 0xE3A8A84B, 0xF35151A2, 0xFEA3A35D,
    0xC0404080, 0x8A8F8F05, 0xAD92923F, 0xBC9D9D21, 0x48383870, 0x04F5F5F1,
    0xDFBCBC63, 0xC1B6B677, 0x75DADAAF, 0x63212142, 0x30101020, 0x1AFFFFE5,
    0x0EF3F3FD, 0x6DD2D2BF, 0x4CCDCD81, 0x140C0C18, 0x35131326, 0x2FECECC3,
    0xE15F5FBE, 0xA2979735, 0xCC444488, 0x3917172E, 0x57C4C493, 0xF2A7A755,
    0x827E7EFC, 0x473D3D7A, 0xAC6464C8, 0xE75D5DBA, 0x2B191932, 0x957373E6,
    0xA06060C0, 0x98818119, 0xD14F4F9E, 0x7FDCDCA3, 0x66222244, 0x7E2A2A54,
    0xAB90903B, 0x8388880B, 0xCA46468C, 0x29EEEEC7, 0xD3B8B86B, 0x3C141428,
    0x79DEDEA7, 0xE25E5EBC, 0x1D0B0B16, 0x76DBDBAD, 0x3BE0E0DB, 0x56323264,
    0x4E3A3A74, 0x1E0A0A14, 0xDB494992, 0x0A06060C, 0x6C242448, 0xE45C5CB8,
    0x5DC2C29F, 0x6ED3D3BD, 0xEFACAC43, 0xA66262C4, 0xA8919139, 0xA4959531,
    0x37E4E4D3, 0x8B7979F2, 0x32E7E7D5, 0x43C8C88B, 0x5937376E, 0xB76D6DDA,
    0x8C8D8D01, 0x64D5D5B1, 0xD24E4E9C, 0xE0A9A949, 0xB46C6CD8, 0xFA5656AC,
    0x07F4F4F3, 0x25EAEACF, 0xAF6565CA, 0x8E7A7AF4, 0xE9AEAE47, 0x18080810,
    0xD5BABA6F, 0x887878F0, 0x6F25254A, 0x722E2E5C, 0x241C1C38, 0xF1A6A657,
    0xC7B4B473, 0x51C6C697, 0x23E8E8CB, 0x7CDDDDA1, 0x9C7474E8, 0x211F1F3E,
    0xDD4B4B96, 0xDCBDBD61, 0x868B8B0D, 0x858A8A0F, 0x907070E0, 0x423E3E7C,
    0xC4B5B571, 0xAA6666CC, 0xD8484890, 0x05030306, 0x01F6F6F7, 0x120E0E1C,
    0xA36161C2, 0x5F35356A, 0xF95757AE, 0xD0B9B969, 0x91868617, 0x58C1C199,
    0x271D1D3A, 0xB99E9E27, 0x38E1E1D9, 0x13F8F8EB, 0xB398982B, 0x33111122,
    0xBB6969D2, 0x70D9D9A9, 0x898E8E07, 0xA7949433, 0xB69B9B2D, 0x221E1E3C,
    0x92878715, 0x20E9E9C9, 0x49CECE87, 0xFF5555AA, 0x78282850, 0x7ADFDFA5,
    0x8F8C8C03, 0xF8A1A159, 0x80898909, 0x170D0D1A, 0xDABFBF65, 0x31E6E6D7,
    0xC6424284, 0xB86868D0, 0xC3414182, 0xB0999929, 0x772D2D5A, 0x110F0F1E,
    0xCBB0B07B, 0xFC5454A8, 0xD6BBBB6D, 0x3A16162C};

static const uint8_t sbox[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B,
    0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26,
    0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2,
    0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED,
    0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F,
    0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC,
    0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14,
    0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
    0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F,
    0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11,
    0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F,
    0xB0, 0x54, 0xBB, 0x16};


static void aes256_enc_ecb( uint8_t ct[16], const uint8_t pt[16],
                            const uint32_t rk[])
{
    uint32_t s0, s1, s2, s3, t0, t1, t2, t3;
    int r;

    // get bytes -- use initial key
    s0 = get32u_le(pt) ^ rk[0];
    s1 = get32u_le(pt + 4) ^ rk[1];
    s2 = get32u_le(pt + 8) ^ rk[2];
    s3 = get32u_le(pt + 12) ^ rk[3];

    // nr - 1 full rounds:
    r = 14 >> 1;
    for (;;) {
        t0 =    rk[4] ^ ttab[s0 & 0xFF] ^
                ror32(ttab[(s1 >> 8) & 0xFF], 24) ^
                ror32(ttab[(s2 >> 16) & 0xFF], 16) ^
                ror32(ttab[s3 >> 24], 8);
        t1 =    rk[5] ^ ttab[s1 & 0xFF] ^
                ror32(ttab[(s2 >> 8) & 0xFF], 24) ^
                ror32(ttab[(s3 >> 16) & 0xFF], 16) ^
                ror32(ttab[s0 >> 24], 8);
        t2 =    rk[6] ^ ttab[s2 & 0xFF] ^
                ror32(ttab[(s3 >> 8) & 0xFF], 24) ^
                ror32(ttab[(s0 >> 16) & 0xFF], 16) ^
                ror32(ttab[s1 >> 24], 8);
        t3 =    rk[7] ^ ttab[s3 & 0xFF] ^
                ror32(ttab[(s0 >> 8) & 0xFF], 24) ^
                ror32(ttab[(s1 >> 16) & 0xFF], 16) ^
                ror32(ttab[s2 >> 24], 8);

        rk += 8;
        if (--r == 0) {
            break;
        }
        s0 =    rk[0] ^ ttab[t0 & 0xFF] ^
                ror32(ttab[(t1 >> 8) & 0xFF], 24) ^
                ror32(ttab[(t2 >> 16) & 0xFF], 16) ^
                ror32(ttab[t3 >> 24], 8);
        s1 =    rk[1] ^ ttab[t1 & 0xFF] ^
                ror32(ttab[(t2 >> 8) & 0xFF], 24) ^
                ror32(ttab[(t3 >> 16) & 0xFF], 16) ^
                ror32(ttab[t0 >> 24], 8);
        s2 =    rk[2] ^ ttab[t2 & 0xFF] ^
                ror32(ttab[(t3 >> 8) & 0xFF], 24) ^
                ror32(ttab[(t0 >> 16) & 0xFF], 16) ^
                ror32(ttab[t1 >> 24], 8);
        s3 =    rk[3] ^ ttab[t3 & 0xFF] ^
                ror32(ttab[(t0 >> 8) & 0xFF], 24) ^
                ror32(ttab[(t1 >> 16) & 0xFF], 16) ^
                ror32(ttab[t2 >> 24], 8);
    }

    // last round, write it back

    s0 = rk[0] ^ (((uint32_t)sbox[t0 & 0xFF])) ^
         (((uint32_t)sbox[(t1 >> 8) & 0xFF]) << 8) ^
         (((uint32_t)sbox[(t2 >> 16) & 0xFF]) << 16) ^
         (((uint32_t)sbox[t3 >> 24]) << 24);

    s1 = rk[1] ^ (((uint32_t)sbox[t1 & 0xFF])) ^
         (((uint32_t)sbox[(t2 >> 8) & 0xFF]) << 8) ^
         (((uint32_t)sbox[(t3 >> 16) & 0xFF]) << 16) ^
         (((uint32_t)sbox[t0 >> 24]) << 24);

    s2 = rk[2] ^ (((uint32_t)sbox[t2 & 0xFF])) ^
         (((uint32_t)sbox[(t3 >> 8) & 0xFF]) << 8) ^
         (((uint32_t)sbox[(t0 >> 16) & 0xFF]) << 16) ^
         (((uint32_t)sbox[t1 >> 24]) << 24);

    s3 = rk[3] ^ (((uint32_t)sbox[t3 & 0xFF])) ^
         (((uint32_t)sbox[(t0 >> 8) & 0xFF]) << 8) ^
         (((uint32_t)sbox[(t1 >> 16) & 0xFF]) << 16) ^
         (((uint32_t)sbox[t2 >> 24]) << 24);

    put32u_le(ct, s0);
    put32u_le(ct + 4, s1);
    put32u_le(ct + 8, s2);
    put32u_le(ct + 12, s3);
}

//  set up an AES-256 key

static void aes256_enc_key(uint32_t rk[60], const uint8_t key[32])
{
    static const uint8_t rcon[] = {0x01, 0x02, 0x04, 0x08, 0x10,
                                   0x20, 0x40, 0x80, 0x1B, 0x36};
    int i;
    uint32_t temp;

    rk[0] = get32u_le(key);
    rk[1] = get32u_le(key + 4);
    rk[2] = get32u_le(key + 8);
    rk[3] = get32u_le(key + 12);
    rk[4] = get32u_le(key + 16);
    rk[5] = get32u_le(key + 20);
    rk[6] = get32u_le(key + 24);
    rk[7] = get32u_le(key + 28);

    for (i = 0;;) {
        temp = rk[7];
        rk[8] = ((uint32_t)rcon[i]) ^ rk[0] ^
                (((uint32_t)sbox[(temp >> 8) & 0xFF])) ^
                (((uint32_t)sbox[(temp >> 16) & 0xFF]) << 8) ^
                (((uint32_t)sbox[(temp >> 24) & 0xFF]) << 16) ^
                (((uint32_t)sbox[temp & 0xFF]) << 24);
        rk[9] = rk[1] ^ rk[8];
        rk[10] = rk[2] ^ rk[9];
        rk[11] = rk[3] ^ rk[10];
        if (++i == 7)
            break;
        temp = rk[11];
        rk[12] = rk[4] ^ (((uint32_t)sbox[temp & 0xFF])) ^
                 (((uint32_t)sbox[(temp >> 8) & 0xFF]) << 8) ^
                 (((uint32_t)sbox[(temp >> 16) & 0xFF]) << 16) ^
                 (((uint32_t)sbox[(temp >> 24) & 0xFF]) << 24);
        rk[13] = rk[5] ^ rk[12];
        rk[14] = rk[6] ^ rk[13];
        rk[15] = rk[7] ^ rk[14];
        rk += 8;
    }
}

static inline void aesdrbg_inc_ctr(uint8_t ctr[16])
{
    int i;
    uint32_t x;

    x = 1;

    for (i = 15; i >= 0; i--) {
        x += (uint32_t)ctr[i];
        ctr[i] = (uint8_t)x;
        x >>= 8;
    }
}

static void aesdrbg_update(aes256_ctr_drbg_t *ctx, const uint8_t *input48)
{
    size_t i;
    uint8_t tmp[48];

    for (i = 0; i < 48; i += 16) {
        aesdrbg_inc_ctr(ctx->ctr);
        aes256_enc_ecb(tmp + i, ctx->ctr, ctx->rk);
    }

    if (input48 != NULL) {
        for (i = 0; i < 48; i++)
            tmp[i] ^= input48[i];
    }
    memcpy(ctx->key, tmp, 32);
    memcpy(ctx->ctr, tmp + 32, 16);
    aes256_enc_key(ctx->rk, ctx->key);
}

void aes256ctr_xof_init(aes256_ctr_drbg_t *ctx, const uint8_t input48[48])
{
    memset(ctx->key, 0x00, 32);
    memset(ctx->ctr, 0x00, 16);
    aes256_enc_key(ctx->rk, ctx->key);

    aesdrbg_update(ctx, input48);
}

void aes256ctr_xof(aes256_ctr_drbg_t *ctx, uint8_t *x, size_t xlen)
{
    uint8_t tmp[16];

    while (xlen > 0) {
        // increment ctr
        aesdrbg_inc_ctr(ctx->ctr);
        aes256_enc_ecb(tmp, ctx->ctr, ctx->rk);

        if (xlen > 15) {
            memcpy(x, tmp, 16);
            x += 16;
            xlen -= 16;
        } else {
            memcpy(x, tmp, xlen);
            xlen = 0;
        }
    }
    aesdrbg_update(ctx, NULL);
}


//  slh_shake.c
//  Markku-Juhani O. Saarinen <mjos@iki.fi>.  See LICENSE.

//  === Portable C code: Functions for instantiation of SLH-DSA with SHAKE

#ifndef SLOTH_KECCAK


// 替換原本的 Shake256 xof輸出函数
void sha3_256_xof(const uint8_t *input, size_t input_len, uint8_t *output, size_t output_len) {
    uint8_t counter[4] = {0};  // 計數器
    uint8_t hash[32];          // 單次 SHA3-256 的輸出
    size_t generated = 0;      // 已生成的輸出長度
    size_t i;

    while (generated < output_len) {
        // 拼接輸入和計數器
        uint8_t *full_input = malloc(input_len + sizeof(counter));
        if (!full_input) {
            fprintf(stderr, "Memory allocation failed\n");
            return;
        }
        memcpy(full_input, input, input_len);
        memcpy(full_input + input_len, counter, sizeof(counter));

        // 一次性計算 SHA3-256
        sha3(hash, 32, full_input, input_len + sizeof(counter));
        free(full_input);

        // 複製輸出
        size_t to_copy = (output_len - generated < 32) ? (output_len - generated) : 32;
        memcpy(output + generated, hash, to_copy);
        generated += to_copy;

        // 增加計數器
        for (i = 0; i < sizeof(counter); i++) {
            if (++counter[i] != 0) break;
        }
    }
}





//  === 10.1.   SLH-DSA Using SHAKE

//  Hmsg(R, PK.seed, PK.root, M) = SHAKE256(R || PK.seed || PK.root || M, 8m)
static void sha3_256_h_msg(slh_ctx_t *ctx, uint8_t *h,
                           const uint8_t *r, const uint8_t *m, size_t m_sz) {
    size_t n = ctx->prm->n;
    size_t mgf_sz = 2 * n + 32 + 4;
    uint8_t mgf[mgf_sz];  // 符合計算需求的緩衝區
    uint8_t digest[32];   // 暫存計算結果
    uint8_t *ctr = mgf + mgf_sz - 4;  // 指向計數器位置

    // 拼接 R 和 PK.seed
    memcpy(mgf, r, n);
    memcpy(mgf + n, ctx->pk_seed, n);

    // 計算 SHA3-256(R || PK.seed || PK.root || M)
    uint8_t input[3 * n + m_sz];  // 拼接 r, pk_seed, pk_root, 和 m
    memcpy(input, r, n);
    memcpy(input + n, ctx->pk_seed, n);
    memcpy(input + 2 * n, ctx->pk_root, n);
    memcpy(input + 3 * n, m, m_sz);
    sha3(digest, 32, input, 3 * n + m_sz);

    // 將 digest 寫入 mgf 中
    memcpy(mgf + 2 * n, digest, 32);

    // MGF1 計數模式
    for (size_t i = 0; i < ctx->prm->m; i += 32) {
        uint32_t c = i / 32;
        ctr[0] = c >> 24;
        ctr[1] = (c >> 16) & 0xFF;
        ctr[2] = (c >> 8) & 0xFF;
        ctr[3] = c & 0xFF;

        uint8_t mgf_input[mgf_sz];
        memcpy(mgf_input, mgf, mgf_sz);

        if ((ctx->prm->m - i) >= 32) {
            sha3(h + i, 32, mgf_input, mgf_sz);
        } else {
            sha3(digest, 32, mgf_input, mgf_sz);
            memcpy(h + i, digest, ctx->prm->m - i);
        }
    }
}









//  F(PK.seed, ADRS, M1 ) = SHAKE256(PK.seed || ADRS || M1, 8n)


static void sha3_256_f(slh_ctx_t *ctx, uint8_t *h, const uint8_t *m1) {
    size_t n = ctx->prm->n;
    uint8_t input[n + 32 + n]; // PK.seed + ADRS + m1
    memcpy(input, ctx->pk_seed, n);
    memcpy(input + n, (const uint8_t *)ctx->adrs->u8, 32);
    memcpy(input + n + 32, m1, n);

    sha3_256_xof(input, n + 32 + n, h, n);
}





//  PRF(PK.seed, SK.seed, ADRS) = SHAKE256(PK.seed || ADRS || SK.seed, 8n)

static void sha3_256_prf(slh_ctx_t *ctx, uint8_t *h) {
    size_t n = ctx->prm->n;
    uint8_t input[n + 32]; // PK.seed + ADRS
    memcpy(input, ctx->pk_seed, n);
    memcpy(input + n, (const uint8_t *)ctx->adrs->u8, 32);

    sha3_256_xof(input, n + 32, h, n);
}



//  PRFmsg (SK.prf, opt_rand, M) = SHAKE256(SK.prf || opt_rand || M, 8n)
static void sha3_256_prf_msg(slh_ctx_t *ctx, uint8_t *h,
                             const uint8_t *opt_rand,
                             const uint8_t *m, size_t m_sz) {
    uint8_t pad[32], buf[32];
    size_t n = ctx->prm->n;

    // ipad
    memcpy(pad, ctx->sk_prf, n);
    for (size_t i = 0; i < n; i++) {
        pad[i] ^= 0x36;
    }
    memset(pad + n, 0x36, 32 - n);

    uint8_t input1[32 + n + m_sz]; // ipad + opt_rand + m
    memcpy(input1, pad, 32);
    memcpy(input1 + 32, opt_rand, n);
    memcpy(input1 + 32 + n, m, m_sz);
    sha3(buf, 32, input1, 32 + n + m_sz);

    // 2. 計算 HMAC 的外部雜湊（opad 部分）
    for (size_t i = 0; i < n; i++) {
        pad[i] ^= 0x36 ^ 0x5C; // 反轉 ipad，切換到 opad
    }
    memset(pad + n, 0x5C, 32 - n);

    uint8_t input2[32 + 32]; // opad + buf
    memcpy(input2, pad, 32);
    memcpy(input2 + 32, buf, 32);
    sha3(h, 32, input2, 64);
}







//  T_l(PK.seed, ADRS, M ) = SHAKE256(PK.seed || ADRS || Ml, 8n)
static void sha3_256_t(slh_ctx_t *ctx, uint8_t *h, const uint8_t *m, size_t m_sz) {
    size_t n = ctx->prm->n;
    uint8_t input[n + 32 + m_sz]; // PK.seed + ADRS + m
    memcpy(input, ctx->pk_seed, n);
    memcpy(input + n, (const uint8_t *)ctx->adrs->u8, 32);
    memcpy(input + n + 32, m, m_sz);

    sha3_256_xof(input, n + 32 + m_sz, h, n);
}



//  H(PK.seed, ADRS, M2 ) = SHAKE256(PK.seed || ADRS || M2, 8n)
static void sha3_256_h(slh_ctx_t *ctx, uint8_t *h, const uint8_t *m1, const uint8_t *m2) {
    size_t n = ctx->prm->n;
    uint8_t input[n + 32 + n + n]; // PK.seed + ADRS + m1 + m2
    memcpy(input, ctx->pk_seed, n);
    memcpy(input + n, (const uint8_t *)ctx->adrs->u8, 32);
    memcpy(input + n + 32, m1, n);
    memcpy(input + n + 32 + n, m2, n);

    sha3_256_xof(input, n + 32 + n + n, h, n);
}



//  create a context

static void sha3_256_mk_ctx(slh_ctx_t *ctx, const uint8_t *pk, const uint8_t *sk, const slh_param_t *prm) {
    size_t n = prm->n;

    // 初始化上下文
    memset(ctx, 0, sizeof(slh_ctx_t));
    ctx->prm = prm;

    // 確保至少有一個密鑰輸入
    if (sk == NULL && pk == NULL) {
        fprintf(stderr, "Error: Both pk and sk are NULL in sha3_256_mk_ctx\n");
        return;
    }

    if (sk != NULL) {
        memcpy(ctx->sk_seed, sk, n);
        memcpy(ctx->sk_prf, sk + n, n);
        memcpy(ctx->pk_seed, sk + 2 * n, n);
        memcpy(ctx->pk_root, sk + 3 * n, n);
    } else if (pk != NULL) {
        memcpy(ctx->pk_seed, pk, n);
        memcpy(ctx->pk_root, pk + n, n);
    }

    // 初始化本地 ADRS 緩衝區
    ctx->adrs = &ctx->t_adrs;
    memset(ctx->adrs, 0, sizeof(adrs_t));
}




//  === Chaining function used in WOTS+
//  Algorithm 4: chain(X, i, s, PK.seed, ADRS)

//  chaining by processor (some optimizations)

static void sha3_256_chain(slh_ctx_t *ctx, uint8_t *tmp, const uint8_t *x,
                           uint32_t i, uint32_t s) {
    size_t n = ctx->prm->n;
    uint8_t input[n + 32];  // 定義輸入緩衝區
    uint8_t output[32];     // 定義輸出緩衝區

    if (s == 0) {
        memcpy(tmp, x, n);
        return;
    }

    for (uint32_t j = 0; j < s; j++) {
        adrs_set_hash_address(ctx, i + j);
        memcpy(input, x, n); // 將 `x` 複製到輸入緩衝區
        memcpy(input + n, ctx->adrs->u8, 32); // 將地址附加到輸入緩衝區

        sha3(output, 32, input, n + 32); // 一次性計算 SHA3-256
        memcpy(tmp, output, n);         // 將輸出保存到 `tmp`
        x = tmp;                        // 更新鏈接輸入
    }
}

//  Combination WOTS PRF + Chain
static void sha3_256_wots_chain(slh_ctx_t *ctx, uint8_t *tmp, uint32_t s) {
    // PRF secret key
    adrs_set_type(ctx, ADRS_WOTS_PRF);
    adrs_set_tree_index(ctx, 0);

    // Use PRF with SHA3-256
    sha3_256_prf(ctx, tmp);

    // Apply chain function
    adrs_set_type(ctx, ADRS_WOTS_HASH);
    sha3_256_chain(ctx, tmp, tmp, 0, s);
}


// //  Combination FORS PRF + F (if s == 1)
static void sha3_256_fors_hash(slh_ctx_t *ctx, uint8_t *tmp, uint32_t s) {
    // PRF secret key
    adrs_set_type(ctx, ADRS_FORS_PRF);
    adrs_set_tree_height(ctx, 0);

    // Use PRF with SHA3-256
    sha3_256_prf(ctx, tmp);

    // Additional hash if s == 1
    if (s == 1) {
        adrs_set_type(ctx, ADRS_FORS_TREE);
        // 假設第二個輸入資料塊是 tmp 本身的副本，可根據實際情況替換
        sha3_256_h(ctx, tmp, tmp, tmp);
    }
}

//  parameter sets
const slh_param_t slh_dsa_sha3_256s = {
    .alg_id = "SLH-DSA-SHA3-256s",
    .n = 32,
    .h = 64,
    .d = 8,
    .hp = 8,
    .a = 14,
    .k = 22,
    .lg_w = 4,
    .m = 47,
    .mk_ctx = sha3_256_mk_ctx,      // 替換
    .chain = sha3_256_chain,        // 替換
    .wots_chain = sha3_256_wots_chain, // 替換
    .fors_hash = sha3_256_fors_hash,   // 替換
    .h_msg = sha3_256_h_msg,        // 替換
    .prf = sha3_256_prf,            // 替換
    .prf_msg = sha3_256_prf_msg,    // 替換
    .h_f = sha3_256_f,              // 替換
    .h_h = sha3_256_h,              // 替換
    .h_t = sha3_256_t               // 替換
};

//  no SLOTH_KECCAK
#endif

//  sha3_api.c
//  Markku-Juhani O. Saarinen <mjos@iki.fi>.  See LICENSE.

//  === FIPS 202: SHA-3 hash and SHAKE eXtensible Output Functions (XOF)
//      Hash padding mode code for testing permutation implementations.

#ifndef SLOTH_NO_SHA3


//  These functions have not been optimized for performance -- they are
//  here just to facilitate testing of the permutation code implementations.

//  initialize the context for SHA3

void sha3_init(sha3_ctx_t *c, int mdlen)
{
    int i;

    for (i = 0; i < 25; i++)
        c->st.d[i] = 0;
    c->mdlen = mdlen;           //  in SHAKE; if 0, padding done
    c->rsiz = 200 - 2 * mdlen;
    c->pt = 0;
}

//  update state with more data

void sha3_update(sha3_ctx_t *c, const void *data, size_t len)
{
    size_t i;
    int j;

    j = c->pt;
    for (i = 0; i < len; i++) {
        c->st.b[j++] ^= ((const uint8_t *) data)[i];
        if (j >= c->rsiz) {
            keccak_f1600(c->st.d);
            j = 0;
        }
    }
    c->pt = j;
}

//  finalize and output a hash

void sha3_final(sha3_ctx_t *c, uint8_t *md)
{
    int i;

    c->st.b[c->pt] ^= 0x06;
    c->st.b[c->rsiz - 1] ^= 0x80;
    keccak_f1600(c->st.d);

    for (i = 0; i < c->mdlen; i++) {
        md[i] = c->st.b[i];
    }
}

//  compute a SHA-3 hash "md" of "mdlen" bytes from data in "in"

void *sha3(uint8_t *md, int mdlen, const void *in, size_t inlen)
{
    // sha3_ctx_t sha3;

    // sha3_init(&sha3, mdlen);
    // sha3_update(&sha3, in, inlen);
    // sha3_final(&sha3, md);

    // return md;
    // 確保硬體加速器能夠正常運行，使用 `fence` 指令來防止指令重排
    asm volatile ("fence");

    // 設定加速器的輸入和輸出地址
    // 使用ROCC_INSTRUCTION_SS 來設定 input 和 output 指標給加速器
    ROCC_INSTRUCTION_SS(2, in, md, 0);

    // 指定要處理的輸入長度，並開始計算
    // 使用ROCC_INSTRUCTION_S 來傳入數據長度
    ROCC_INSTRUCTION_S(2, inlen, 1);

    // 再次使用 fence 確保計算完成後再讀取數據
    asm volatile ("fence" ::: "memory");

    // 確保輸出結果與原來的軟體接口保持一致
    return md;
}

//  SHAKE128 and SHAKE256 extensible-output functionality
//  squeeze output

void shake_out(sha3_ctx_t *c, uint8_t *out, size_t len)
{
    size_t  i;
    int j;

    //  add padding on the first call
    if (c->mdlen != 0) {
        c->st.b[c->pt] ^= 0x1F;
        c->st.b[c->rsiz - 1] ^= 0x80;
        keccak_f1600(c->st.d);
        c->pt = 0;
        c->mdlen = 0;
    }

    j = c->pt;
    for (i = 0; i < len; i++) {
        if (j >= c->rsiz) {
            keccak_f1600(c->st.d);
            j = 0;
        }
        out[i] = c->st.b[j++];
    }
    c->pt = j;
}

//  SLOTH_NO_SHA3
#endif

//  sha3_f1600.c
//  Markku-Juhani O. Saarinen <mjos@iki.fi>.  See LICENSE.

//  === FIPS 202 Keccak permutation implementation for a 64-bit target.

#ifndef SLOTH_KECCAK


//  forward permutation

void keccak_f1600(void *st)
{
    //  round constants
    static const uint64_t keccak_rc[24] = {
        UINT64_C(0x0000000000000001), UINT64_C(0x0000000000008082),
        UINT64_C(0x800000000000808A), UINT64_C(0x8000000080008000),
        UINT64_C(0x000000000000808B), UINT64_C(0x0000000080000001),
        UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008009),
        UINT64_C(0x000000000000008A), UINT64_C(0x0000000000000088),
        UINT64_C(0x0000000080008009), UINT64_C(0x000000008000000A),
        UINT64_C(0x000000008000808B), UINT64_C(0x800000000000008B),
        UINT64_C(0x8000000000008089), UINT64_C(0x8000000000008003),
        UINT64_C(0x8000000000008002), UINT64_C(0x8000000000000080),
        UINT64_C(0x000000000000800A), UINT64_C(0x800000008000000A),
        UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008080),
        UINT64_C(0x0000000080000001), UINT64_C(0x8000000080008008)
    };

    int i;
    uint64_t *x = (uint64_t *) st;
    uint64_t t, y0, y1, y2, y3, y4;

    //  iteration

    for (i = 0; i < 24; i++) {

        //  Theta

        y4 = x[ 4] ^ x[ 9] ^ x[14] ^ x[19] ^ x[24];
        y1 = x[ 1] ^ x[ 6] ^ x[11] ^ x[16] ^ x[21];
        y3 = x[ 3] ^ x[ 8] ^ x[13] ^ x[18] ^ x[23];
        y0 = x[ 0] ^ x[ 5] ^ x[10] ^ x[15] ^ x[20];
        y2 = x[ 2] ^ x[ 7] ^ x[12] ^ x[17] ^ x[22];

        t   = ror64(y4, 63);
        y4 ^= ror64(y1, 63);
        y1 ^= ror64(y3, 63);
        y3 ^= ror64(y0, 63);
        y0 ^= ror64(y2, 63);
        y2 ^= t;

        x[ 0] ^= y4;
        x[ 1] ^= y0;
        x[ 2] ^= y1;
        x[ 3] ^= y2;
        x[ 4] ^= y3;
        x[ 5] ^= y4;
        x[ 6] ^= y0;
        x[ 7] ^= y1;
        x[ 8] ^= y2;
        x[ 9] ^= y3;
        x[10] ^= y4;
        x[11] ^= y0;
        x[12] ^= y1;
        x[13] ^= y2;
        x[14] ^= y3;
        x[15] ^= y4;
        x[16] ^= y0;
        x[17] ^= y1;
        x[18] ^= y2;
        x[19] ^= y3;
        x[20] ^= y4;
        x[21] ^= y0;
        x[22] ^= y1;
        x[23] ^= y2;
        x[24] ^= y3;

        //  Rho Pi

        t     = ror64(x[ 1], 63);
        x[ 1] = ror64(x[ 6], 20);
        x[ 6] = ror64(x[ 9], 44);
        x[ 9] = ror64(x[22],  3);
        x[22] = ror64(x[14], 25);
        x[14] = ror64(x[20], 46);
        x[20] = ror64(x[ 2],  2);
        x[ 2] = ror64(x[12], 21);
        x[12] = ror64(x[13], 39);
        x[13] = ror64(x[19], 56);
        x[19] = ror64(x[23],  8);
        x[23] = ror64(x[15], 23);
        x[15] = ror64(x[ 4], 37);
        x[ 4] = ror64(x[24], 50);
        x[24] = ror64(x[21], 62);
        x[21] = ror64(x[ 8],  9);
        x[ 8] = ror64(x[16], 19);
        x[16] = ror64(x[ 5], 28);
        x[ 5] = ror64(x[ 3], 36);
        x[ 3] = ror64(x[18], 43);
        x[18] = ror64(x[17], 49);
        x[17] = ror64(x[11], 54);
        x[11] = ror64(x[ 7], 58);
        x[ 7] = ror64(x[10], 61);
        x[10] = t;

        //  Chi

        t =      x[ 4] & ~x[ 3];
        x[ 4] ^= x[ 1] & ~x[ 0];
        x[ 1] ^= x[ 3] & ~x[ 2];
        x[ 3] ^= x[ 0] & ~x[ 4];
        x[ 0] ^= x[ 2] & ~x[ 1];
        x[ 2] ^= t;

        t =      x[ 9] & ~x[8];
        x[ 9] ^= x[ 6] & ~x[5];
        x[ 6] ^= x[ 8] & ~x[7];
        x[ 8] ^= x[ 5] & ~x[9];
        x[ 5] ^= x[ 7] & ~x[6];
        x[ 7] ^= t;

        t =      x[14] & ~x[13];
        x[14] ^= x[11] & ~x[10];
        x[11] ^= x[13] & ~x[12];
        x[13] ^= x[10] & ~x[14];
        x[10] ^= x[12] & ~x[11];
        x[12] ^= t;

        t =      x[19] & ~x[18];
        x[19] ^= x[16] & ~x[15];
        x[16] ^= x[18] & ~x[17];
        x[18] ^= x[15] & ~x[19];
        x[15] ^= x[17] & ~x[16];
        x[17] ^= t;

        t =      x[24] & ~x[23];
        x[24] ^= x[21] & ~x[20];
        x[21] ^= x[23] & ~x[22];
        x[23] ^= x[20] & ~x[24];
        x[20] ^= x[22] & ~x[21];
        x[22] ^= t;

        //  Iota

        x[0] = x[0] ^ keccak_rc[i];
    }
}

//  SLOTH_KECCAK
#endif


// 獲取硬體 cycle 計數器 (假設 RISC-V 環境)
static inline uint64_t get_cycle() {
    uint64_t cycle;
    asm volatile("rdcycle %0" : "=r" (cycle)); // 使用 RISC-V 的 rdcycle 指令
    return cycle;
}

// 適配隨機數生成器的函數
int my_randombytes(uint8_t *x, size_t xlen) {
    aes256_ctr_drbg_t drbg;
    uint8_t seed[48] = {0};  // 固定種子
    aes256ctr_xof_init(&drbg, seed);
    aes256ctr_xof(&drbg, x, xlen);
    return 0;  // 返回 0 表示成功
}

// 將 uint8_t 陣列轉換為十六進位字串
void bytes_to_hex(const uint8_t *bytes, size_t len, char **hex_out) {
    *hex_out = malloc(2 * len + 1);
    for (size_t i = 0; i < len; i++) {
        sprintf(&(*hex_out)[2 * i], "%02x", bytes[i]);
    }
    (*hex_out)[2 * len] = '\0';
}

int main() {
    uint64_t t0, t1, t2, t3;
    int ret;

    // 測試訊息
    const char *message = "Hello!";
    const uint8_t *msg = (const uint8_t *)message;
    size_t msglen = strlen(message); // 計算訊息長度

    printf("Hex message of '%s': ", message);
    for (size_t n = 0; n < msglen; n++) {
        printf("%02x", msg[n]);
    }
    printf("\n");

    // 配置參數集
    const slh_param_t *param = &slh_dsa_sha3_256s;
    uint8_t pk[2 * param->n]; // 公鑰
    uint8_t sk[4 * param->n]; // 私鑰
    uint8_t sig[50000];       // 簽名緩衝區
    uint8_t hash[param->m];   // 雜湊值
    uint8_t randomizer[param->n]; // 隨機數列
    size_t siglen;

    printf("Public Key Size (Bytes): %zu\n", 2 * param->n);
    printf("Private Key Size (Bytes): %zu\n", 4 * param->n);
    size_t sig_size = slh_sig_sz(param);
    printf("Signature Size (Bytes): %zu\n", sig_size);

    // 1. 金鑰生成
    printf("\n========== 1. Key Generation ==========\n");
    t0 = get_cycle();
    slh_keygen(pk, sk, my_randombytes, param);
    t1 = get_cycle();
    printf("Key Generation Cycles: %lu\n", (unsigned long)(t1 - t0));


    // 顯示公鑰
    char *hex_pk = NULL;
    bytes_to_hex(pk, 2 * param->n, &hex_pk);
    printf("Public Key (Hex): %s\n", hex_pk);
    free(hex_pk);

    // 顯示私鑰
    char *hex_sk = NULL;
    bytes_to_hex(sk, 4 * param->n, &hex_sk);
    printf("Private Key (Hex): %s\n", hex_sk);
    free(hex_sk);

    // 2. 訊息雜湊
    printf("\n========== 2. Message Hashing ==========\n");
    // 初始化 SLH-DSA 上下文
    slh_ctx_t ctx;
    param->mk_ctx(&ctx, pk, sk, param);

    // 使用安全隨機數生成器初始化隨機數列
    my_randombytes(randomizer, param->n);


    printf("Randomizer (Hex): ");
    for (size_t i = 0; i < param->n; i++) {
        printf("%02x", randomizer[i]);
    }
    printf("\n");

    t1 = get_cycle();
    param->h_msg(&ctx, hash, randomizer, msg, msglen); // 傳入有效 ctx
    t2 = get_cycle();

    printf("Message Hashing Cycles: %lu\n", (unsigned long)(t2 - t1));

    // 將計算結果轉為十六進位輸出
    char *hex_hash = NULL;
    bytes_to_hex(hash, param->m, &hex_hash);
    printf("Message Hash (Hex): %s\n", hex_hash);
    free(hex_hash);

    // 3. 訊息簽署
    printf("\n========== 3. Signing Message ==========\n");
    t2 = get_cycle();
    siglen = slh_sign(sig, msg, msglen, sk, my_randombytes, param);
    t3 = get_cycle();
    printf("Signing Cycles: %lu\n", (unsigned long)(t3 - t2));

    char *hex_sig = NULL;
    bytes_to_hex(sig, siglen, &hex_sig);
    printf("Signature (Hex): %s\n", hex_sig);
    free(hex_sig);

    // 4. 驗證簽名
    printf("\n========== 4. Verifying Signature ==========\n");
    t3 = get_cycle();
    ret = slh_verify(msg, msglen, sig, pk, param);
    t0 = get_cycle();
    printf("Verification Cycles: %lu\n", (unsigned long)(t0 - t3));
    if(ret) {
        printf("verify valid\n");
        
      }else{
        printf("verify invalid\n");
        return 0;
      }    

    // 5. 篡改簽名並重新驗證
    printf("\n========== 5. redo slh_verify (Increment the last byte of 'sig' by 1 to set it as the error byte.) ==========\n");
    sig[siglen - 1] += 1; // 修改簽名的最後一個位元組
    ret = slh_verify(msg, msglen, sig, pk, param);
    if(ret) {
        printf("verify valid\n");
      }else{
        printf("verify invalid\n");

      }

    return 0;
}
