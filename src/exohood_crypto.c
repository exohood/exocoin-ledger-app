// Copyright (c) Exohood Protocol 2021-2022
/* Copyright 2017 Cedric Mesnil <cslashm@gmail.com>, Ledger SAS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "os.h" 
#include "cx.h"
#include "exohood_types.h"
#include "exohood_api.h"
#include "exohood_vars.h"


/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
static unsigned char const WIDE  C_ED25519_G[] = {
    //uncompressed
    0x04,
    //x
    0x21, 0x69, 0x36, 0xd3, 0xcd, 0x6e, 0x53, 0xfe, 0xc0, 0xa4, 0xe2, 0x31, 0xfd, 0xd6, 0xdc, 0x5c,
    0x69, 0x2c, 0xc7, 0x60, 0x95, 0x25, 0xa7, 0xb2, 0xc9, 0x56, 0x2d, 0x60, 0x8f, 0x25, 0xd5, 0x1a,
    //y
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x58};

static unsigned char const WIDE  C_ED25519_Hy[] = {
    0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf, 0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea,
    0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9, 0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94
};

unsigned char const C_ED25519_ORDER[32] = {
    //l: 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x14, 0xDE, 0xF9, 0xDE, 0xA2, 0xF7, 0x9C, 0xD6, 0x58, 0x12, 0x63, 0x1A, 0x5C, 0xF5, 0xD3, 0xED};

unsigned char const C_ED25519_FIELD[32] = {
   //q:  0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xed};

unsigned char const C_EIGHT[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08};

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void exohood_aes_derive(cx_aes_key_t *sk, unsigned char* seed32, unsigned char *a, unsigned char *b) {
    unsigned char  h1[32];

    exohood_keccak_init_H();
    exohood_keccak_update_H(seed32, 32);
    exohood_keccak_update_H(a, 32);
    exohood_keccak_update_H(b, 32);
    exohood_keccak_final_H(h1);

    exohood_keccak_H(h1,32,h1);

    cx_aes_init_key(h1,16,sk);
}

void exohood_aes_generate(cx_aes_key_t *sk) {
    unsigned char  h1[16];
    cx_rng(h1,16);
    cx_aes_init_key(h1,16,sk);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
unsigned int exohood_encode_varint(uint8_t* varint, uint64_t out_idx) {

    if (out_idx > UINT64_MAX / 2)
        return 0;
        
    unsigned int len;
    len = 0;
    while(out_idx >= 0x80) {
        varint[len] = ((uint8_t)(out_idx & 0x7F)) | 0x80;
        out_idx = out_idx>>7;
        len++;
    }
    varint[len] = ((uint8_t)out_idx) & 0x7F;
    len++;
    return len;
}

size_t exohood_encode_varint_portable_binary_archive(uint8_t buf[static 9], uint64_t num) {

    if (num > UINT64_MAX / 2)
        return 0;

    size_t i = 0;

    while (num >= 0x80) {
        buf[i++] = (uint8_t)(num) | 0x80;
        num >>= 7;
    }

    buf[i++] = (uint8_t)(num);

    return i;
}

size_t exohood_decode_varint_portable_binary_archive(const uint8_t buf[], size_t size_max, uint64_t *num) {
    if (size_max == 0)
        return 0;

    if (size_max > 9)
        size_max = 9;

    *num = buf[0] & 0x7F;
    size_t i = 0;

    while (buf[i++] & 0x80) {
        if (i >= size_max || buf[i] == 0x00)
            return 0;

        *num |= (uint64_t)(buf[i] & 0x7F) << (i * 7);
    }

    return i;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void exohood_reverse32(unsigned char *rscal, unsigned char *scal) {
    unsigned char x;
    unsigned int i;
    for (i = 0; i<16; i++) {
        x           = scal[i];
        rscal[i]    = scal [31-i];
        rscal[31-i] = x;
    }
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void exohood_hash_init_sha256(cx_hash_t * hasher) {
    cx_sha256_init((cx_sha256_t *)hasher);
}

void exohood_hash_init_keccak(cx_hash_t * hasher) {
    cx_keccak_init((cx_sha3_t *)hasher, 256);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void exohood_hash_update(cx_hash_t * hasher, unsigned char* buf, unsigned int len) {
    cx_hash(hasher, 0, buf, len, NULL, 0);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int exohood_hash_final(cx_hash_t * hasher, unsigned char* out) {
    return cx_hash(hasher, CX_LAST, NULL, 0, out, 32);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int exohood_hash(unsigned int algo, cx_hash_t * hasher, unsigned char* buf, unsigned int len, unsigned char* out) {
    hasher->algo = algo;
    if (algo == CX_SHA256) {
         cx_sha256_init((cx_sha256_t *)hasher);
    } else {
        cx_keccak_init((cx_sha3_t *)hasher, 256);
    }
    return cx_hash(hasher, CX_LAST|CX_NO_REINIT, buf, len, out, 32);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
/* thanks to knaccc and exohoodmoo help on IRC #exohood-research-lab */
/* From exohood code
 *
 *  fe_sq2(v, u);            // 2 * u^2
 *  fe_1(w);
 *  fe_add(w, v, w);         // w = 2 * u^2 + 1
 *  fe_sq(x, w);             // w^2
 *  fe_mul(y, fe_ma2, v);    // -2 * A^2 * u^2
 *  fe_add(x, x, y);         // x = w^2 - 2 * A^2 * u^2
 *  fe_divpowm1(r->X, w, x); // (w / x)^(m + 1)
 *  fe_sq(y, r->X);
 *  fe_mul(x, y, x);
 *  fe_sub(y, w, x);
 *  fe_copy(z, fe_ma);
 *  if (fe_isnonzero(y)) {
 *    fe_add(y, w, x);
 *    if (fe_isnonzero(y)) {
 *      goto negative;
 *    } else {
 *      fe_mul(r->X, r->X, fe_fffb1);
 *    }
 *  } else {
 *    fe_mul(r->X, r->X, fe_fffb2);
 *  }
 *  fe_mul(r->X, r->X, u);  // u * sqrt(2 * A * (A + 2) * w / x)
 *  fe_mul(z, z, v);        // -2 * A * u^2
 *  sign = 0;
 *  goto setsign;
 *negative:
 *  fe_mul(x, x, fe_sqrtm1);
 *  fe_sub(y, w, x);
 *  if (fe_isnonzero(y)) {
 *    assert((fe_add(y, w, x), !fe_isnonzero(y)));
 *    fe_mul(r->X, r->X, fe_fffb3);
 *  } else {
 *    fe_mul(r->X, r->X, fe_fffb4);
 *  }
 *  // r->X = sqrt(A * (A + 2) * w / x)
 *  // z = -A
 *  sign = 1;
 *setsign:
 *  if (fe_isnegative(r->X) != sign) {
 *    assert(fe_isnonzero(r->X));
 *    fe_neg(r->X, r->X);
 *  }
 *  fe_add(r->Z, z, w);
 *  fe_sub(r->Y, z, w);
 *  fe_mul(r->X, r->X, r->Z);
 */

// A = 486662
const unsigned char C_fe_ma2[] = {
    /* -A^2
     *  0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffc8db3de3c9
     */
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc8, 0xdb, 0x3d, 0xe3, 0xc9
};

const unsigned char C_fe_ma[] = {
    /* -A
     *  0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff892e7
     */
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf8, 0x92, 0xe7
};
const unsigned char C_fe_fffb1[] = {

    /* sqrt(-2 * A * (A + 2))
     * 0x7e71fbefdad61b1720a9c53741fb19e3d19404a8b92a738d22a76975321c41ee
     */
    0x7e, 0x71, 0xfb, 0xef, 0xda, 0xd6, 0x1b, 0x17, 0x20, 0xa9, 0xc5, 0x37, 0x41, 0xfb, 0x19, 0xe3,
    0xd1, 0x94, 0x04, 0xa8, 0xb9, 0x2a, 0x73, 0x8d, 0x22, 0xa7, 0x69, 0x75, 0x32, 0x1c, 0x41, 0xee
};
const unsigned char C_fe_fffb2[] = {
    /* sqrt(2 * A * (A + 2))
     * 0x4d061e0a045a2cf691d451b7c0165fbe51de03460456f7dfd2de6483607c9ae0
     */
    0x4d, 0x06, 0x1e, 0x0a, 0x04, 0x5a, 0x2c, 0xf6, 0x91, 0xd4, 0x51, 0xb7, 0xc0, 0x16, 0x5f, 0xbe,
    0x51, 0xde, 0x03, 0x46, 0x04, 0x56, 0xf7, 0xdf, 0xd2, 0xde, 0x64, 0x83, 0x60, 0x7c, 0x9a, 0xe0
};
const unsigned char C_fe_fffb3[] = {
    /* sqrt(-sqrt(-1) * A * (A + 2))
     * 674a110d14c208efb89546403f0da2ed4024ff4ea5964229581b7d8717302c66
     */
    0x67, 0x4a, 0x11, 0x0d, 0x14, 0xc2, 0x08, 0xef, 0xb8, 0x95, 0x46, 0x40, 0x3f, 0x0d, 0xa2, 0xed,
    0x40, 0x24, 0xff, 0x4e, 0xa5, 0x96, 0x42, 0x29, 0x58, 0x1b, 0x7d, 0x87, 0x17, 0x30, 0x2c, 0x66

};
const unsigned char C_fe_fffb4[] = {
    /* sqrt(sqrt(-1) * A * (A + 2))
     * 1a43f3031067dbf926c0f4887ef7432eee46fc08a13f4a49853d1903b6b39186
     */
   0x1a, 0x43, 0xf3, 0x03, 0x10, 0x67, 0xdb, 0xf9, 0x26, 0xc0, 0xf4, 0x88, 0x7e, 0xf7, 0x43, 0x2e,
   0xee, 0x46, 0xfc, 0x08, 0xa1, 0x3f, 0x4a, 0x49, 0x85, 0x3d, 0x19, 0x03, 0xb6, 0xb3, 0x91, 0x86

};
const unsigned char C_fe_sqrtm1[] = {
    /* sqrt(2 * A * (A + 2))
     * 0x2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0
     */
    0x2b, 0x83, 0x24, 0x80, 0x4f, 0xc1, 0xdf, 0x0b, 0x2b, 0x4d, 0x00, 0x99, 0x3d, 0xfb, 0xd7, 0xa7,
    0x2f, 0x43, 0x18, 0x06, 0xad, 0x2f, 0xe4, 0x78, 0xc4, 0xee, 0x1b, 0x27, 0x4a, 0x0e, 0xa0, 0xb0
};
const unsigned char C_fe_qm5div8[] = {
    0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfd
};

static void exohood_ge_fromfe_frombytes(unsigned char *ge , unsigned char *bytes) {

    #define  MOD (unsigned char *)C_ED25519_FIELD,32
    #define fe_isnegative(f)      (f[31]&1)
#if 0
    unsigned char u[32], v[32], w[32], x[32], y[32], z[32];
    unsigned char rX[32], rY[32], rZ[32];
    union {
        struct {
            unsigned char _uv7[32];
            unsigned char  _v3[32];
        };
        unsigned char _Pxy[65];

    } uv;

    #define uv7 uv._uv7
    #define v3 uv._v3

    #define Pxy   uv._Pxy
#else
    #define u   (G_exohood_vstate.io_buffer+0*32)
    #define v   (G_exohood_vstate.io_buffer+1*32)
    #define w   (G_exohood_vstate.io_buffer+2*32)
    #define x   (G_exohood_vstate.io_buffer+3*32)
    #define y   (G_exohood_vstate.io_buffer+4*32)
    #define z   (G_exohood_vstate.io_buffer+5*32)
    #define rX  (G_exohood_vstate.io_buffer+6*32)
    #define rY  (G_exohood_vstate.io_buffer+7*32)
    #define rZ  (G_exohood_vstate.io_buffer+8*32)

    //#define uv7 (G_exohood_vstate.io_buffer+9*32)
    //#define v3  (G_exohood_vstate.io_buffer+10*32)
    union {
        unsigned char _Pxy[65];
        struct {
            unsigned char _uv7[32];
            unsigned char  _v3[32];
        };


    } uv;

    #define uv7 uv._uv7
    #define v3 uv._v3

    #define Pxy   uv._Pxy

#if exohood_IO_BUFFER_LENGTH < (9*32)
#error  exohood_IO_BUFFER_LENGTH is too small
#endif
#endif

    unsigned char sign;

    //cx works in BE
    exohood_reverse32(u,bytes);
    cx_math_modm(u, 32, (unsigned char *)C_ED25519_FIELD, 32);

    //go on
    cx_math_multm(v, u, u, MOD);                           /* 2 * u^2 */
    cx_math_addm (v,  v, v, MOD);

    os_memset    (w, 0, 32); w[31] = 1;                   /* w = 1 */
    cx_math_addm (w, v, w,MOD );                          /* w = 2 * u^2 + 1 */
    cx_math_multm(x, w, w, MOD);                          /* w^2 */
    cx_math_multm(y, (unsigned char *)C_fe_ma2, v, MOD);  /* -2 * A^2 * u^2 */
    cx_math_addm (x, x, y, MOD);                          /* x = w^2 - 2 * A^2 * u^2 */

    //inline fe_divpowm1(r->X, w, x);     // (w / x)^(m + 1) => fe_divpowm1(r,u,v)
    #define _u w
    #define _v x
    cx_math_multm(v3, _v,   _v, MOD);
    cx_math_multm(v3,  v3,  _v, MOD);                       /* v3 = v^3 */
    cx_math_multm(uv7, v3,  v3, MOD);
    cx_math_multm(uv7, uv7, _v, MOD);
    cx_math_multm(uv7, uv7, _u, MOD);                     /* uv7 = uv^7 */
    cx_math_powm (uv7, uv7, (unsigned char *)C_fe_qm5div8, 32, MOD); /* (uv^7)^((q-5)/8)*/
    cx_math_multm(uv7, uv7, v3, MOD);
    cx_math_multm(rX,  uv7, w, MOD);                      /* u^(m+1)v^(-(m+1)) */
    #undef _u
    #undef _v

    cx_math_multm(y, rX,rX, MOD);
    cx_math_multm(x, y, x, MOD);
    cx_math_subm(y, w, x, MOD);
    os_memmove(z, C_fe_ma, 32);

    if (!cx_math_is_zero(y,32)) {
     cx_math_addm(y, w, x, MOD);
     if (!cx_math_is_zero(y,32)) {
       goto negative;
     } else {
      cx_math_multm(rX, rX, (unsigned char *)C_fe_fffb1, MOD);
     }
   } else {
     cx_math_multm(rX, rX, (unsigned char *)C_fe_fffb2, MOD);
   }
   cx_math_multm(rX, rX, u, MOD);  // u * sqrt(2 * A * (A + 2) * w / x)
   cx_math_multm(z, z, v, MOD);        // -2 * A * u^2
   sign = 0;

   goto setsign;

  negative:
   cx_math_multm(x, x, (unsigned char *)C_fe_sqrtm1, MOD);
   cx_math_subm(y, w, x, MOD);
   if (!cx_math_is_zero(y,32)) {
     cx_math_addm(y, w, x, MOD);
     cx_math_multm(rX, rX, (unsigned char *)C_fe_fffb3, MOD);
   } else {
     cx_math_multm(rX, rX, (unsigned char *)C_fe_fffb4, MOD);
   }
   // r->X = sqrt(A * (A + 2) * w / x)
   // z = -A
   sign = 1;

 setsign:
   if (fe_isnegative(rX) != sign) {
     //fe_neg(r->X, r->X);
    cx_math_sub(rX, (unsigned char *)C_ED25519_FIELD, rX, 32);
   }
   cx_math_addm(rZ, z, w, MOD);
   cx_math_subm(rY, z, w, MOD);
   cx_math_multm(rX, rX, rZ, MOD);

   //back to exohood y-affine
   cx_math_invprimem(u, rZ, MOD);
   Pxy[0] = 0x04;
   cx_math_multm(&Pxy[1],    rX, u, MOD);
   cx_math_multm(&Pxy[1+32], rY, u, MOD);
   cx_edward_compress_point(CX_CURVE_Ed25519, Pxy, sizeof(Pxy));
   os_memmove(ge, &Pxy[1], 32);

    #undef u
    #undef v
    #undef w
    #undef x
    #undef y
    #undef z
    #undef rX
    #undef rY
    #undef rZ

    #undef uv7
    #undef v3

    #undef Pxy
}

/* ======================================================================= */
/*                            DERIVATION & KEY                             */
/* ======================================================================= */

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void exohood_hash_to_scalar(unsigned char *scalar, unsigned char *raw, unsigned int raw_len) {
    exohood_keccak_F(raw,raw_len,scalar);
    exohood_reduce(scalar, scalar);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void exohood_hash_to_ec(unsigned char *ec, unsigned char *ec_pub) {
    exohood_keccak_F(ec_pub, 32, ec);
    exohood_ge_fromfe_frombytes(ec, ec);
    exohood_ecmul_8(ec, ec);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void exohood_generate_keypair(unsigned char *ec_pub, unsigned char *ec_priv) {
    exohood_rng_mod_order(ec_priv);
    exohood_ecmul_G(ec_pub, ec_priv);
}

/* ----------------------------------------------------------------------- */
/* --- ok                                                              --- */
/* ----------------------------------------------------------------------- */
void exohood_generate_key_derivation(unsigned char *drv_data, unsigned char *P, unsigned char *scalar) {
    exohood_ecmul_8k(drv_data,P,scalar);
}

/* ----------------------------------------------------------------------- */
/* ---  ok                                                             --- */
/* ----------------------------------------------------------------------- */
void exohood_derivation_to_scalar(unsigned char *scalar, unsigned char *drv_data, unsigned int out_idx) {
    unsigned char varint[32+8];
    unsigned int len_varint;

    os_memmove(varint, drv_data, 32);
    len_varint = exohood_encode_varint(varint+32, out_idx);
    len_varint += 32;
    exohood_keccak_F(varint,len_varint,varint);
    exohood_reduce(scalar, varint);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void exohood_derive_secret_key(unsigned char *x,
                              unsigned char *drv_data, unsigned int out_idx, unsigned char *ec_priv) {
    unsigned char tmp[32];

    //derivation to scalar
    exohood_derivation_to_scalar(tmp,drv_data,out_idx);

    //generate
    exohood_addm(x, tmp, ec_priv);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void exohood_derive_public_key(unsigned char *x,
                              unsigned char* drv_data, unsigned int out_idx, unsigned char *ec_pub) {
    unsigned char tmp[32];

    //derivation to scalar
    exohood_derivation_to_scalar(tmp,drv_data,out_idx);
    //generate
    exohood_ecmul_G(tmp,tmp);
    exohood_ecadd(x,tmp,ec_pub);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void exohood_secret_key_to_public_key(unsigned char *ec_pub, unsigned char *ec_priv) {
    exohood_ecmul_G(ec_pub, ec_priv);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void exohood_generate_key_image(unsigned char *img, unsigned char *P, unsigned char* x) {
    unsigned char I[32];
    exohood_hash_to_ec(I,P);
    exohood_ecmul_k(img, I,x);
}

/* ======================================================================= */
/*                               SUB ADDRESS                               */
/* ======================================================================= */

/* ----------------------------------------------------------------------- */
/* --- ok                                                              --- */
/* ----------------------------------------------------------------------- */
void exohood_derive_subaddress_public_key(unsigned char *x,
                                         unsigned char *pub, unsigned char* drv_data, unsigned int index) {
  unsigned char scalarG[32];

  exohood_derivation_to_scalar(scalarG , drv_data, index);
  exohood_ecmul_G(scalarG, scalarG);
  exohood_ecsub(x, pub, scalarG);
}

/* ----------------------------------------------------------------------- */
/* --- ok                                                              --- */
/* ----------------------------------------------------------------------- */
void exohood_get_subaddress_spend_public_key(unsigned char *x,unsigned char *index) {
    // m = Hs(a || index_major || index_minor)
    exohood_get_subaddress_secret_key(x, G_exohood_vstate.a, index);
    // M = m*G
    exohood_secret_key_to_public_key(x,x);
    // D = B + M
    exohood_ecadd(x,x,G_exohood_vstate.B);
 }

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void exohood_get_subaddress(unsigned char *C, unsigned char *D, unsigned char *index) {
    //retrieve D
    exohood_get_subaddress_spend_public_key(D, index);
    // C = a*D
    exohood_ecmul_k(C,D,G_exohood_vstate.a);
}

/* ----------------------------------------------------------------------- */
/* --- ok                                                              --- */
/* ----------------------------------------------------------------------- */
static const  char C_sub_address_prefix[] = {'S','u','b','A','d','d','r', 0};

void exohood_get_subaddress_secret_key(unsigned char *sub_s, unsigned char *s, unsigned char *index) {
    unsigned char in[sizeof(C_sub_address_prefix)+32+8];

    os_memmove(in,                               C_sub_address_prefix, sizeof(C_sub_address_prefix)),
    os_memmove(in+sizeof(C_sub_address_prefix),    s,                  32);
    os_memmove(in+sizeof(C_sub_address_prefix)+32, index,              8);
    //hash_to_scalar with more that 32bytes:
    exohood_keccak_F(in, sizeof(in), sub_s);
    exohood_reduce(sub_s, sub_s);
}

/* ======================================================================= */
/*                                  MATH                                   */
/* ======================================================================= */

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void exohood_ecmul_G(unsigned char *W,  unsigned char *scalar32) {
    unsigned char Pxy[65];
    unsigned char s[32];
    exohood_reverse32(s, scalar32);
    os_memmove(Pxy, C_ED25519_G, 65);
    cx_ecfp_scalar_mult(CX_CURVE_Ed25519, Pxy, sizeof(Pxy), s, 32);
    cx_edward_compress_point(CX_CURVE_Ed25519, Pxy, sizeof(Pxy));
    os_memmove(W, &Pxy[1], 32);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void exohood_ecmul_H(unsigned char *W,  unsigned char *scalar32) {
    unsigned char Pxy[65];
    unsigned char s[32];

    exohood_reverse32(s, scalar32);

    Pxy[0] = 0x02;
    os_memmove(&Pxy[1], C_ED25519_Hy, 32);
    cx_edward_decompress_point(CX_CURVE_Ed25519, Pxy, sizeof(Pxy));

    cx_ecfp_scalar_mult(CX_CURVE_Ed25519, Pxy, sizeof(Pxy), s, 32);
    cx_edward_compress_point(CX_CURVE_Ed25519, Pxy, sizeof(Pxy));

    os_memmove(W, &Pxy[1], 32);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void exohood_ecmul_k(unsigned char *W, unsigned char *P, unsigned char *scalar32) {
    unsigned char Pxy[65];
    unsigned char s[32];

    exohood_reverse32(s, scalar32);

    Pxy[0] = 0x02;
    os_memmove(&Pxy[1], P, 32);
    cx_edward_decompress_point(CX_CURVE_Ed25519, Pxy, sizeof(Pxy));

    cx_ecfp_scalar_mult(CX_CURVE_Ed25519, Pxy, sizeof(Pxy), s, 32);
    cx_edward_compress_point(CX_CURVE_Ed25519, Pxy, sizeof(Pxy));

    os_memmove(W, &Pxy[1], 32);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void exohood_ecmul_8k(unsigned char *W, unsigned char *P, unsigned char *scalar32) {
    unsigned char s[32];
    exohood_multm_8(s, scalar32);
    exohood_ecmul_k(W, P, s);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void exohood_ecmul_8(unsigned char *W, unsigned char *P) {
    unsigned char Pxy[65];

    Pxy[0] = 0x02;
    os_memmove(&Pxy[1], P, 32);
    cx_edward_decompress_point(CX_CURVE_Ed25519, Pxy, sizeof(Pxy));
    cx_ecfp_add_point(CX_CURVE_Ed25519, Pxy, Pxy, Pxy, sizeof(Pxy));
    cx_ecfp_add_point(CX_CURVE_Ed25519, Pxy, Pxy, Pxy, sizeof(Pxy));
    cx_ecfp_add_point(CX_CURVE_Ed25519, Pxy, Pxy, Pxy, sizeof(Pxy));
    cx_edward_compress_point(CX_CURVE_Ed25519, Pxy, sizeof(Pxy));
    os_memmove(W, &Pxy[1], 32);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void exohood_ecadd(unsigned char *W, unsigned char *P, unsigned char *Q) {
    unsigned char Pxy[65];
    unsigned char Qxy[65];

    Pxy[0] = 0x02;
    os_memmove(&Pxy[1], P, 32);
    cx_edward_decompress_point(CX_CURVE_Ed25519, Pxy, sizeof(Pxy));

    Qxy[0] = 0x02;
    os_memmove(&Qxy[1], Q, 32);
    cx_edward_decompress_point(CX_CURVE_Ed25519, Qxy, sizeof(Qxy));

    cx_ecfp_add_point(CX_CURVE_Ed25519, Pxy, Pxy, Qxy, sizeof(Pxy));

    cx_edward_compress_point(CX_CURVE_Ed25519, Pxy, sizeof(Pxy));
    os_memmove(W, &Pxy[1], 32);
}


/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void exohood_ecsub(unsigned char *W, unsigned char *P, unsigned char *Q) {
    unsigned char Pxy[65];
    unsigned char Qxy[65];

    Pxy[0] = 0x02;
    os_memmove(&Pxy[1], P, 32);
    cx_edward_decompress_point(CX_CURVE_Ed25519, Pxy, sizeof(Pxy));

    Qxy[0] = 0x02;
    os_memmove(&Qxy[1], Q, 32);
    cx_edward_decompress_point(CX_CURVE_Ed25519, Qxy, sizeof(Qxy));

    cx_math_sub(Qxy+1, (unsigned char *)C_ED25519_FIELD,  Qxy+1, 32);
    cx_ecfp_add_point(CX_CURVE_Ed25519, Pxy, Pxy, Qxy, sizeof(Pxy));

    cx_edward_compress_point(CX_CURVE_Ed25519, Pxy, sizeof(Pxy));
    os_memmove(W, &Pxy[1], 32);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
/*
    static key ecdhHash(const key &k)
    {
        char data[38];
        rct::key hash;
        memcpy(data, "amount", 6);
        memcpy(data + 6, &k, sizeof(k));
        cn_fast_hash(hash, data, sizeof(data));
        return hash;
    }
*/
void exohood_ecdhHash(unsigned char *x, unsigned char *k) {
  unsigned char data[38];
  os_memmove(data, "amount", 6);
  os_memmove(data + 6, k, 32);
  exohood_keccak_F(data, 38, x);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
/*
    key genCommitmentMask(const key &sk)
    {
        char data[15 + sizeof(key)];
        memcpy(data, "commitment_mask", 15);
        memcpy(data + 15, &sk, sizeof(sk));
        key scalar;
        hash_to_scalar(scalar, data, sizeof(data));
        return scalar;
    }
*/
void exohood_genCommitmentMask(unsigned char *c,  unsigned char *sk) {
    unsigned char data[15 + 32];
    os_memmove(data, "commitment_mask", 15);
    os_memmove(data + 15, sk, 32);
    exohood_hash_to_scalar(c, data, 15+32);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void exohood_addm(unsigned char *r, unsigned char *a, unsigned char *b) {
    unsigned char ra[32];
    unsigned char rb[32];

    exohood_reverse32(ra,a);
    exohood_reverse32(rb,b);
    cx_math_addm(r, ra,  rb, (unsigned char *)C_ED25519_ORDER, 32);
    exohood_reverse32(r,r);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void exohood_subm(unsigned char *r, unsigned char *a, unsigned char *b) {
    unsigned char ra[32];
    unsigned char rb[32];

    exohood_reverse32(ra,a);
    exohood_reverse32(rb,b);
    cx_math_subm(r, ra,  rb, (unsigned char *)C_ED25519_ORDER, 32);
    exohood_reverse32(r,r);
}
/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void exohood_multm(unsigned char *r, unsigned char *a, unsigned char *b) {
    unsigned char ra[32];
    unsigned char rb[32];

    exohood_reverse32(ra,a);
    exohood_reverse32(rb,b);
    cx_math_multm(r, ra,  rb, (unsigned char *)C_ED25519_ORDER, 32);
    exohood_reverse32(r,r);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void exohood_multm_8(unsigned char *r, unsigned char *a) {
    unsigned char ra[32];
    unsigned char rb[32];

    exohood_reverse32(ra,a);
    os_memset(rb,0,32);
    rb[31] = 8;
    cx_math_multm(r, ra,  rb, (unsigned char *)C_ED25519_ORDER, 32);
    exohood_reverse32(r,r);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void exohood_reduce(unsigned char *r, unsigned char *a) {
    unsigned char ra[32];
    exohood_reverse32(ra,a);
    cx_math_modm(ra, 32, (unsigned char *)C_ED25519_ORDER, 32);
    exohood_reverse32(r,ra);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void exohood_rng_mod_order(unsigned char *r) {
    unsigned char rnd[32+8];
    cx_rng(rnd,32+8);
    cx_math_modm(rnd, 32+8, (unsigned char *)C_ED25519_ORDER, 32);
    exohood_reverse32(r,rnd+8);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
/* return 0 if ok, 1 if missing decimal */
int exohood_amount2str(uint64_t ETN,  char *str, unsigned int str_len) {
    //max uint64 is 18446744073709551616, aka 20 char, plus dot
    char stramount[22];
    unsigned int offset,len,ov;

    os_memset(str,0,str_len);

    os_memset(stramount,'0',sizeof(stramount));
    stramount[21] = 0;
    //special case
    if (ETN == 0) {
        str[0] = '0';
        return 1;
    }

    //uint64 units to str
    // offset: 0 | 1-20     | 21
    // ----------------------
    // value:  0 | ETNunits | 0

    offset = 20;
    while (ETN) {
        stramount[offset] = '0' + ETN % 10;
        ETN = ETN / 10;
        offset--;
    }
    // offset: 0-17 | 18 | 19-20 |21
    // ----------------------
    // value:  ETN  |  . | units| 0
    os_memmove(stramount, stramount+1, 18);
    stramount[18] = '.';
    offset = 0;
    while((stramount[offset]=='0') && (stramount[offset] != '.')) {
        offset++;
    }
    if (stramount[offset] == '.') {
        offset--;
    }
    len = 20;
    while((stramount[len]=='0') && (stramount[len] != '.')) {
        len--;
    }
    if(stramount[len] == '.') {
        len--;
    }
    len = len-offset+1;
    ov = 0;
    if (len>(str_len-1)) {
        len = str_len-1;
        ov = 1;
    }
    os_memmove(str, stramount+offset, len);
    return ov;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
uint64_t exohood_bamount2uint64(unsigned char *binary) {
    uint64_t ETN;
    int i;
    ETN = 0;
    for (i=7; i>=0; i--) {
        ETN = ETN*256 + binary[i];
    }
    return ETN;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int exohood_bamount2str(unsigned char *binary,  char *str, unsigned int str_len) {
    return exohood_amount2str(exohood_bamount2uint64(binary), str,str_len);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
uint64_t exohood_vamount2uint64(unsigned char *binary) {
   uint64_t ETN,x;
   int shift = 0;
   ETN = 0;
   while((*binary)&0x80) {
       if ( (unsigned int)shift > (8*sizeof(unsigned long long int)-7)) {
        return 0;
       }
       x = *(binary)&0x7f;
       ETN = ETN + (x<<shift);
       binary++;
       shift += 7;
   }
   x = *(binary)&0x7f;
   ETN = ETN + (x<<shift);
   return ETN;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
uint8_t* exohood_uint642vamount(unsigned int num) {
    uint8_t buf[9] = {0,0,0,0,0,0,0,0,0};
    size_t i = 0;

    while (num >= 0x80) {
        buf[i++] = (uint8_t)(num) | 0x80;
        num >>= 7;
    }

    buf[i++] = (uint8_t)(num);
    return buf;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int exohood_vamount2str(unsigned char *binary,  char *str, unsigned int str_len) {
   return exohood_amount2str(exohood_vamount2uint64(binary), str,str_len);
}
