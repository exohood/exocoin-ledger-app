// Copyright (c) The Exohood Project 2022
/* Copyright 2017 Cedric Mesnil, Ledger SAS
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

#ifndef Exohood_API_H
#define  Exohood_API_H

int Exohood_apdu_reset();

void Exohood_install(unsigned char netId);
void Exohood_init(void);
void Exohood_init_private_key(void);
void Exohood_wipe_private_key(void);

void Exohood_init_ux(void);
int Exohood_dispatch(void);

int Exohood_apdu_put_key(void);
int Exohood_apdu_get_key(void);
int Exohood_apdu_display_address(void);
int Exohood_apdu_manage_seedwords() ;
int Exohood_apdu_verify_key(void);
int Exohood_apdu_get_chacha8_prekey(void);
int Exohood_apdu_sc_add(void);
int Exohood_apdu_sc_sub(void);
int Exohood_apdu_scal_mul_key(void);
int Exohood_apdu_scal_mul_base(void);
int Exohood_apdu_hash_to_scalar(void);
int Exohood_apdu_hash_to_scalar_batch(void);
int Exohood_apdu_hash_to_scalar_init(void);
int Exohood_apdu_generate_keypair(void);
int Exohood_apdu_secret_key_to_public_key(void);
int Exohood_apdu_generate_key_derivation(void);
int Exohood_apdu_derivation_to_scalar(void);
int Exohood_apdu_derive_public_key(void);
int Exohood_apdu_derive_secret_key(void);
int Exohood_apdu_generate_key_image(void);
int Exohood_apdu_derive_subaddress_public_key(void);
int Exohood_apdu_get_subaddress(void);
int Exohood_apdu_get_subaddress_spend_public_key(void);
int Exohood_apdu_get_subaddress_secret_key(void);

int Exohood_apdu_get_tx_proof(void);

int Exohood_apdu_open_tx(void);
void Exohood_reset_tx(void);
int Exohood_apdu_open_subtx(void) ;
int Exohood_apdu_set_signature_mode(void) ;
int Exohood_apdu_stealth(void);
int Exohood_apdu_blind(void);
int Exohood_apdu_unblind(void);
int Exohood_apdu_gen_commitment_mask(void);

int Exohood_apdu_mlsag_prehash_init(void);
int Exohood_apdu_mlsag_prehash_update(void);
int Exohood_apdu_mlsag_prehash_finalize(void);
int Exohood_apu_generate_txout_keys(void);
int Exohood_apdu_tx_prompt_fee(void);
int Exohood_apdu_tx_prompt_amount(void);
int Exohood_apdu_tx_prefix_start(void);
int Exohood_apdu_tx_prefix_inputs(void);
int Exohood_apdu_tx_prefix_outputs(void);
int Exohood_apdu_tx_prefix_outputs_size(void);
int Exohood_apdu_tx_prefix_extra(void);

int Exohood_apdu_mlsag_prepare(void);
int Exohood_apdu_mlsag_hash(void);
int Exohood_apdu_mlsag_sign(void);
int Exohood_apdu_close_tx(void);

void ui_init(void);
void ui_main_display(unsigned int value);
void Exohood_ux_user_validation();
void ui_export_viewkey_display(unsigned int value);
void ui_menu_any_pubaddr_display(unsigned int value);
void ui_menu_pubaddr_display(unsigned int value);


/* ----------------------------------------------------------------------- */
/* ---                               MISC                             ---- */
/* ----------------------------------------------------------------------- */
#define OFFSETOF(type, field)    ((unsigned int)&(((type*)NULL)->field))

int Exohood_base58_public_key( char* str_b58, unsigned char *view, unsigned char *spend, unsigned char is_subbadress, unsigned char *paymanetID);

/** unsigned varint amount to uint64 */
uint64_t Exohood_vamount2uint64(unsigned char *binary);
/** binary little endian unsigned  int amount to uint64 */
uint64_t Exohood_bamount2uint64(unsigned char *binary);
/** unsigned varint amount to str */
int Exohood_vamount2str(unsigned char *binary,  char *str, unsigned int str_len);
/** binary little endian unsigned  int amount to str */
int Exohood_bamount2str(unsigned char *binary,  char *str, unsigned int str_len);
/** uint64  amount to str */
int Exohood_amount2str(uint64_t etn,  char *str, unsigned int str_len);

int Exohood_abort_tx() ;
int Exohood_unblind(unsigned char *v, unsigned char *k, unsigned char *AKout, unsigned int short_amount);
void ui_menu_validation_display(unsigned int value) ;
void ui_menu_validation_loopback_display(unsigned int value) ;
void ui_menu_fee_validation_display(unsigned int value) ;
void ui_menu_change_validation_display(unsigned int value) ;

/* ----------------------------------------------------------------------- */
/* ---                          KEYS & ADDRESS                        ---- */
/* ----------------------------------------------------------------------- */
extern const unsigned char C_FAKE_SEC_VIEW_KEY[32];
extern const unsigned char C_FAKE_SEC_SPEND_KEY[32];

int is_fake_view_key(unsigned char *s);
int is_fake_spend_key(unsigned char *s);

void Exohood_sc_add(unsigned char *r, unsigned char *s1, unsigned char *s2);
void Exohood_hash_to_scalar(unsigned char *scalar, unsigned char *raw, unsigned int len);
void Exohood_hash_to_ec(unsigned char *ec, unsigned char *ec_pub);
void Exohood_generate_keypair(unsigned char *ec_pub, unsigned char *ec_priv);
/*
 *  compute s = 8 * (k*P)
 *
 * s [out] 32 bytes derivation value
 * P [in]  point in 02 y or 04 x y format
 * k [in]  32 bytes scalar
 */
void Exohood_generate_key_derivation(unsigned char *drv_data, unsigned char *P, unsigned char *scalar);
void Exohood_derivation_to_scalar(unsigned char *scalar, unsigned char *drv_data, unsigned int out_idx);
/*
 *  compute x = Hps(drv_data,out_idx) + ec_pv
 *
 * x        [out] 32 bytes private key
 * drv_data [in]  32 bytes derivation data (point)
 * ec_pv    [in]  32 bytes private key
 */
void Exohood_derive_secret_key(unsigned char *x, unsigned char *drv_data, unsigned int out_idx, unsigned char *ec_priv);
/*
 *  compute x = Hps(drv_data,out_idx)*G + ec_pub
 *
 * x        [out] 32 bytes public key
 * drv_data [in]  32 bytes derivation data (point)
 * ec_pub   [in]  32 bytes public key
 */
void Exohood_derive_public_key(unsigned char *x, unsigned char* drv_data, unsigned int out_idx, unsigned char *ec_pub);
void Exohood_secret_key_to_public_key(unsigned char *ec_pub, unsigned char *ec_priv);
void Exohood_generate_key_image(unsigned char *img, unsigned char *P, unsigned char* x);

void Exohood_derive_subaddress_public_key(unsigned char *x, unsigned char *pub, unsigned char* drv_data, unsigned int index);
void Exohood_get_subaddress_spend_public_key(unsigned char *x,unsigned char *index);
void Exohood_get_subaddress(unsigned char *C, unsigned char *D, unsigned char *index);
void Exohood_get_subaddress_secret_key(unsigned char *sub_s, unsigned char *s, unsigned char *index);

void Exohood_clear_words();
/* ----------------------------------------------------------------------- */
/* ---                              CRYPTO                            ---- */
/* ----------------------------------------------------------------------- */
extern const unsigned char C_ED25519_ORDER[];


void Exohood_aes_derive(cx_aes_key_t *sk, unsigned char *seed32, unsigned char *a, unsigned char *b);
void Exohood_aes_generate(cx_aes_key_t *sk);

/* Compute Exohood-Hash of data*/
void Exohood_hash_init_keccak(cx_hash_t * hasher);
void Exohood_hash_init_sha256(cx_hash_t * hasher);
void Exohood_hash_update(cx_hash_t * hasher, unsigned char* buf, unsigned int len) ;
int  Exohood_hash_final(cx_hash_t * hasher, unsigned char* out);
int  Exohood_hash(unsigned int algo, cx_hash_t * hasher, unsigned char* buf, unsigned int len, unsigned char* out);

#define Exohood_keccak_init_F() \
    Exohood_hash_init_keccak((cx_hash_t *)&G_Exohood_vstate.keccakF)
#define Exohood_keccak_update_F(buf,len)  \
    Exohood_hash_update((cx_hash_t *)&G_Exohood_vstate.keccakF,(buf), (len))
#define Exohood_keccak_final_F(out) \
    Exohood_hash_final((cx_hash_t *)&G_Exohood_vstate.keccakF, (out))
#define Exohood_keccak_F(buf,len,out) \
    Exohood_hash(CX_KECCAK, (cx_hash_t *)&G_Exohood_vstate.keccakF, (buf),(len), (out))

#define Exohood_keccak_init_H() \
    Exohood_hash_init_keccak((cx_hash_t *)&G_Exohood_vstate.keccakH)
#define Exohood_keccak_update_H(buf,len)  \
    Exohood_hash_update((cx_hash_t *)&G_Exohood_vstate.keccakH,(buf), (len))
#define Exohood_keccak_final_H(out) \
    Exohood_hash_final((cx_hash_t *)&G_Exohood_vstate.keccakH, (out)?(out):G_Exohood_vstate.H)
#define Exohood_keccak_H(buf,len,out) \
    Exohood_hash(CX_KECCAK, (cx_hash_t *)&G_Exohood_vstate.keccakH, (buf),(len), (out)?(out):G_Exohood_vstate.H)

#define Exohood_sha256_commitment_init() \
    Exohood_hash_init_sha256((cx_hash_t *)&G_Exohood_vstate.sha256_commitment)
#define Exohood_sha256_commitment_update(buf,len) \
    Exohood_hash_update((cx_hash_t *)&G_Exohood_vstate.sha256_commitment,(buf), (len))
#define Exohood_sha256_commitment_final(out) \
    Exohood_hash_final((cx_hash_t *)&G_Exohood_vstate.sha256_commitment, (out)?(out):G_Exohood_vstate.C)

#define Exohood_sha256_outkeys_init() \
    Exohood_hash_init_sha256((cx_hash_t *)&G_Exohood_vstate.sha256_out_keys)
#define Exohood_sha256_outkeys_update(buf,len) \
    Exohood_hash_update((cx_hash_t *)&G_Exohood_vstate.sha256_out_keys, (buf), (len))
#define Exohood_sha256_outkeys_final(out) \
    Exohood_hash_final((cx_hash_t *)&G_Exohood_vstate.sha256_out_keys, (out)?(out):G_Exohood_vstate.OUTK)


/**
 * LE-7-bits encoding. High bit set says one more byte to decode.
 */
unsigned int Exohood_encode_varint(unsigned char* varint, uint64_t out_idx);
/** */
void Exohood_reverse32(unsigned char *rscal, unsigned char *scal);

/**
 * Hps: keccak(drv_data|varint(out_idx))
 */
void Exohood_derivation_to_scalar(unsigned char *scalar, unsigned char *drv_data, unsigned int out_idx);


/*
 * W = k.P
 */
void Exohood_ecmul_k(unsigned char *W, unsigned char *P, unsigned char *scalar32);
/*
 * W = 8k.P
 */
void Exohood_ecmul_8k(unsigned char *W, unsigned char *P, unsigned char *scalar32);

/*
 * W = 8.P
 */
void Exohood_ecmul_8(unsigned char *W, unsigned char *P);

/*
 * W = k.G
 */
void Exohood_ecmul_G(unsigned char *W, unsigned char *scalar32);

/*
 * W = k.H
 */
void Exohood_ecmul_H(unsigned char *W, unsigned char *scalar32);


/**
 *  keccak("amount"|sk)
 */
void Exohood_ecdhHash(unsigned char *x, unsigned char *k);

/**
 * keccak("commitment_mask"|sk) %order
 */
void Exohood_genCommitmentMask(unsigned char *c,  unsigned char *sk);

/*
 * W = P+Q
 */
void Exohood_ecadd(unsigned char *W, unsigned char *P, unsigned char *Q);
/*
 * W = P-Q
 */
void Exohood_ecsub(unsigned char *W, unsigned char *P, unsigned char *Q);

/* r = (a+b) %order */
void Exohood_addm(unsigned char *r, unsigned char *a, unsigned char *b);

/* r = (a-b) %order */
void Exohood_subm(unsigned char *r, unsigned char *a, unsigned char *b);

/* r = (a*b) %order */
void Exohood_multm(unsigned char *r, unsigned char *a, unsigned char *b);

/* r = (a*8) %order */
void Exohood_multm_8(unsigned char *r, unsigned char *a);

/* */
void Exohood_reduce(unsigned char *r, unsigned char *a);


void Exohood_rng_mod_order(unsigned char *r);
/* ----------------------------------------------------------------------- */
/* ---                                IO                              ---- */
/* ----------------------------------------------------------------------- */

void Exohood_io_discard(int clear) ;
void Exohood_io_clear(void);
void Exohood_io_set_offset(unsigned int offset) ;
void Exohood_io_mark(void) ;
void Exohood_io_rewind(void) ;
void Exohood_io_hole(unsigned int sz) ;
void Exohood_io_inserted(unsigned int len);
void Exohood_io_insert(unsigned char const * buffer, unsigned int len) ;
void Exohood_io_insert_encrypt(unsigned char* buffer, int len);
void Exohood_io_insert_hmac_for(unsigned char* buffer, int len);

void Exohood_io_insert_u32(unsigned  int v32) ;
void Exohood_io_insert_u24(unsigned  int v24) ;
void Exohood_io_insert_u16(unsigned  int v16) ;
void Exohood_io_insert_u8(unsigned int v8) ;
void Exohood_io_insert_t(unsigned int T) ;
void Exohood_io_insert_tl(unsigned int T, unsigned int L) ;
void Exohood_io_insert_tlv(unsigned int T, unsigned int L, unsigned char const *V) ;

void Exohood_io_fetch_buffer(unsigned char  * buffer, unsigned int len) ;
uint64_t     Exohood_io_fetch_u64(void) ;
unsigned int Exohood_io_fetch_u32(void) ;
unsigned int Exohood_io_fetch_u24(void) ;
unsigned int Exohood_io_fetch_u16(void) ;
unsigned int Exohood_io_fetch_u8(void) ;
int Exohood_io_fetch_t(unsigned int *T) ;
int Exohood_io_fetch_l(unsigned int *L) ;
int Exohood_io_fetch_tl(unsigned int *T, unsigned int *L) ;
int Exohood_io_fetch_nv(unsigned char* buffer, int len) ;
int Exohood_io_fetch(unsigned char* buffer, int len) ;
int Exohood_io_fetch_decrypt(unsigned char* buffer, int len);
int Exohood_io_fetch_decrypt_key(unsigned char* buffer);

int Exohood_io_do(unsigned int io_flags) ;
/* ----------------------------------------------------------------------- */
/* ---                                DEBUG                           ---- */
/* ----------------------------------------------------------------------- */
#ifdef Exohood_DEBUG

#include "Exohood_debug.h"

#else

#define Exohood_nvm_write   nvm_write
#define Exohood_io_exchange io_exchange

#endif

#endif
