/*
/***
*     ______           __                    __
*    / _____  ______  / /_  ____  ____  ____/ /
*   / __/ | |/_/ __ \/ __ \/ __ \/ __ \/ __  / 
*  / /____>  </ /_/ / / / / /_/ / /_/ / /_/ /  
* /_____/_/|_|\____/_/ /_/\____/\____/\__,_/   
*                                             
*   
*    
* https://www.exohood.com
*
* MIT License
* ===========
*
* Copyright (c) 2020 - 2022 Exohood Protocol
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include "os.h"
#include "cx.h"
#include "Exohood_types.h" 
#include "Exohood_api.h"
#include "Exohood_ux_nanos.h"
#include "Exohood_vars.h"

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int Exohood_apdu_mlsag_prepare() { 
    int options;
    unsigned char Hi[32];
    unsigned char xin[32];
    unsigned char alpha[32];
    unsigned char mul[32];


    if (G_Exohood_vstate.io_length>1) {
        Exohood_io_fetch(Hi,32);
        if(G_Exohood_vstate.options &0x40) {
            Exohood_io_fetch(xin,32);
        } else {
           Exohood_io_fetch_decrypt(xin,32);
        }
        options = 1;
    }  else {
        options = 0;
    }

    Exohood_io_discard(1);

    //ai
    Exohood_rng_mod_order(alpha);
    Exohood_reduce(alpha, alpha);
    Exohood_io_insert_encrypt(alpha, 32);

    //ai.G
    Exohood_ecmul_G(mul, alpha);
    Exohood_io_insert(mul,32);

    if (options) {
        //ai.Hi
        Exohood_ecmul_k(mul, Hi, alpha);
        Exohood_io_insert(mul,32);
        //IIi = xin.Hi
        Exohood_ecmul_k(mul, Hi, xin);
        Exohood_io_insert(mul,32);
    }

    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int Exohood_apdu_mlsag_hash() {
    unsigned char msg[32];
    unsigned char c[32];
    if (G_Exohood_vstate.io_p2 == 1) {
        Exohood_keccak_init_H();
        os_memmove(msg, G_Exohood_vstate.H, 32);
    } else {
        Exohood_io_fetch(msg, 32);
    }
    Exohood_io_discard(1);

    Exohood_keccak_update_H(msg, 32);
    if ((G_Exohood_vstate.options&0x80) == 0 ) {
        Exohood_keccak_final_H(c);
        Exohood_reduce(c,c);
        Exohood_io_insert(c,32);
        os_memmove(G_Exohood_vstate.c, c, 32);
    }
    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int Exohood_apdu_mlsag_sign() {
    unsigned char xin[32];
    unsigned char alpha[32];
    unsigned char ss[32];
    unsigned char ss2[32];

    if (G_Exohood_vstate.sig_mode == TRANSACTION_CREATE_FAKE) {
        Exohood_io_fetch(xin,32);
        Exohood_io_fetch(alpha,32);
    } else if (G_Exohood_vstate.sig_mode == TRANSACTION_CREATE_REAL) {
        Exohood_io_fetch_decrypt(xin,32);
        Exohood_io_fetch_decrypt(alpha,32);
    } else {
        THROW(SW_WRONG_DATA);
    }
    Exohood_io_discard(1);


    Exohood_reduce(ss, G_Exohood_vstate.c);
    Exohood_reduce(xin,xin);
    Exohood_multm(ss, ss, xin);

    Exohood_reduce(alpha, alpha);
    Exohood_subm(ss2, alpha, ss);

    Exohood_io_insert(ss2,32);
    Exohood_io_insert_u32(G_Exohood_vstate.sig_mode);
    return SW_OK;
}
