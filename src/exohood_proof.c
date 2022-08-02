// Copyright (c) Exohood Protocol 2020-2022
/* Copyright 2019 Cedric Mesnil, Ledger SAS
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
/*
 * pick random k
 * if B:
 *   compute X = k*B
 * else:
 *   compute X = k*G
 * compute Y = k*A
 * sig.c = Hs(Msg || D || X || Y)
 * sig.r = k - sig.c*r
 */
int exohood_apdu_get_tx_proof() {
    unsigned char *msg;
    unsigned char *R;
    unsigned char *A;
    unsigned char *B; 
    unsigned char *D;
    unsigned char r[32];
    unsigned char XY[32];
    unsigned char sig_c[32];
    unsigned char sig_r[32];
    #define k (G_exohood_vstate.tmp+256)

    msg = G_exohood_vstate.io_buffer+G_exohood_vstate.io_offset; exohood_io_fetch(NULL,32);
    R = G_exohood_vstate.io_buffer+G_exohood_vstate.io_offset; exohood_io_fetch(NULL,32);
    A = G_exohood_vstate.io_buffer+G_exohood_vstate.io_offset; exohood_io_fetch(NULL,32);
    B = G_exohood_vstate.io_buffer+G_exohood_vstate.io_offset; exohood_io_fetch(NULL,32);
    D = G_exohood_vstate.io_buffer+G_exohood_vstate.io_offset; exohood_io_fetch(NULL,32);
    exohood_io_fetch_decrypt_key(r);

    exohood_io_discard(0);

    exohood_rng_mod_order(k);
    os_memmove(G_exohood_vstate.tmp+32*0, msg, 32);
    os_memmove(G_exohood_vstate.tmp+32*1, D, 32);

    if(G_exohood_vstate.options&1) {
        exohood_ecmul_k(XY,B,k);
    } else {
        exohood_ecmul_G(XY,k);
    }
    os_memmove(G_exohood_vstate.tmp+32*2,  XY, 32);

    exohood_ecmul_k(XY,A,k);
    os_memmove(G_exohood_vstate.tmp+32*3, XY, 32);

    exohood_hash_to_scalar(sig_c, &G_exohood_vstate.tmp[0],32*4);

    exohood_multm(XY, sig_c, r);
    exohood_subm(sig_r, k, XY);

    exohood_io_insert(sig_c, 32);
    exohood_io_insert(sig_r, 32);

    return SW_OK;
}
