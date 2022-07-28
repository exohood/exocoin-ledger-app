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

/*
* Client: rctSigs.cpp.c -> get_pre_mlsag_hash
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
int Exohood_apdu_mlsag_prehash_init() {
    if (G_Exohood_vstate.sig_mode == TRANSACTION_CREATE_REAL) {
        if (G_Exohood_vstate.io_p2 == 1) {
            Exohood_sha256_outkeys_final(NULL);
            Exohood_sha256_outkeys_init();
            Exohood_sha256_commitment_init();
            Exohood_keccak_init_H();
        }
    }
    Exohood_keccak_update_H(G_Exohood_vstate.io_buffer+G_Exohood_vstate.io_offset,
                          G_Exohood_vstate.io_length-G_Exohood_vstate.io_offset);
    if ((G_Exohood_vstate.sig_mode == TRANSACTION_CREATE_REAL) &&(G_Exohood_vstate.io_p2==1)) {
        // skip type
        Exohood_io_fetch_u8();
        // fee str
        Exohood_vamount2str(G_Exohood_vstate.io_buffer+G_Exohood_vstate.io_offset, G_Exohood_vstate.ux_amount, 15);
         //ask user
        Exohood_io_discard(1);
        ui_menu_fee_validation_display(0);
        return 0;
    } else {
        Exohood_io_discard(1);
        return SW_OK;
    }
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int Exohood_apdu_mlsag_prehash_update() {
    unsigned char is_subaddress;
    unsigned char *Aout;
    unsigned char *Bout;
    unsigned char is_change;
    unsigned char AKout[32];
    unsigned char C[32];
    unsigned char v[32];
    unsigned char k[32];

    #define aH AKout
    unsigned char kG[32];

    //fetch destination
    is_subaddress = Exohood_io_fetch_u8();
    if (G_Exohood_vstate.io_protocol_version == 2) { 
        is_change =  Exohood_io_fetch_u8();
    } else {
        is_change = 0;
    }
    Aout = G_Exohood_vstate.io_buffer+G_Exohood_vstate.io_offset; Exohood_io_fetch(NULL,32);
    Bout = G_Exohood_vstate.io_buffer+G_Exohood_vstate.io_offset; Exohood_io_fetch(NULL,32);
    Exohood_io_fetch_decrypt(AKout,32);
    Exohood_io_fetch(C, 32);
    Exohood_io_fetch(k, 32);
    Exohood_io_fetch(v, 32);

    Exohood_io_discard(0);

    //update MLSAG prehash
    if ((G_Exohood_vstate.options&0x03) == 0x02) {
        Exohood_keccak_update_H(v,8);
    } else {
        Exohood_keccak_update_H(k,32);
        Exohood_keccak_update_H(v,32);
    }

    if (G_Exohood_vstate.sig_mode == TRANSACTION_CREATE_REAL) {
        if (is_change == 0) {
            //encode dest adress
            Exohood_base58_public_key(&G_Exohood_vstate.ux_address[0], Aout, Bout, is_subaddress, NULL);
        }
        //update destination hash control
        if (G_Exohood_vstate.io_protocol_version == 2) {
            Exohood_sha256_outkeys_update(Aout,32);
            Exohood_sha256_outkeys_update(Bout,32);
            Exohood_sha256_outkeys_update(&is_change,1);
            Exohood_sha256_outkeys_update(AKout,32);
        }

        //check C = aH+kG
        Exohood_unblind(v,k, AKout, G_Exohood_vstate.options&0x03);
        Exohood_ecmul_G(kG, k);
        if (!cx_math_is_zero(v, 32)) {
            Exohood_ecmul_H(aH, v);
            Exohood_ecadd(aH, kG, aH);
        } else {
            os_memmove(aH, kG, 32);
        }
        if (os_memcmp(C, aH, 32)) {
            THROW(SW_SECURITY_COMMITMENT_CONTROL);
        }
        //update commitment hash control
        Exohood_sha256_commitment_update(C,32);


        if ((G_Exohood_vstate.options & IN_OPTION_MORE_COMMAND)==0) {
            if (G_Exohood_vstate.io_protocol_version == 2) {
                //finalize and check destination hash_control
                Exohood_sha256_outkeys_final(k);
                if (os_memcmp(k, G_Exohood_vstate.OUTK, 32)) {
                    THROW(SW_SECURITY_OUTKEYS_CHAIN_CONTROL);
                }
            }
            //finalize commitment hash control
            Exohood_sha256_commitment_final(NULL);
            Exohood_sha256_commitment_init();
        }

        //ask user
        uint64_t amount;
        amount = Exohood_bamount2uint64(v);
        if (amount) {
            Exohood_amount2str(amount, G_Exohood_vstate.ux_amount, 15);
            if (!is_change) {
                ui_menu_validation_display(0);
            } else  {
                ui_menu_change_validation_display(0);
            }
            return 0;
        }
    }
    return SW_OK;

    #undef aH
}


/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int Exohood_apdu_mlsag_prehash_finalize() {
    unsigned char message[32];
    unsigned char proof[32];
    unsigned char H[32];

    if (G_Exohood_vstate.options & IN_OPTION_MORE_COMMAND) {
        //accumulate
        Exohood_io_fetch(H,32);
        Exohood_io_discard(1);
        Exohood_keccak_update_H(H,32);
        Exohood_sha256_commitment_update(H,32);
#ifdef DEBUG_HWDEVICE
        Exohood_io_insert(H, 32);
#endif

    } else {
        //Finalize and check commitment hash control
        if (G_Exohood_vstate.sig_mode == TRANSACTION_CREATE_REAL) {
            Exohood_sha256_commitment_final(H);
            if (os_memcmp(H,G_Exohood_vstate.C,32)) {
                THROW(SW_SECURITY_COMMITMENT_CHAIN_CONTROL);
            }
        }
        //compute last H
        Exohood_keccak_final_H(H);
        //compute last prehash
        Exohood_io_fetch(message,32);
        Exohood_io_fetch(proof,32);
        Exohood_io_discard(1);
        Exohood_keccak_init_H();
        Exohood_keccak_update_H(message,32);
        Exohood_keccak_update_H(H,32);
        Exohood_keccak_update_H(proof,32);
        Exohood_keccak_final_H(NULL);
#ifdef DEBUG_HWDEVICE
        Exohood_io_insert(G_Exohood_vstate.H, 32);
        Exohood_io_insert(H, 32);
#endif
    }

    return SW_OK;
}

int Exohood_apdu_tx_prompt_amount() {
    
    if (G_Exohood_vstate.sig_mode == TRANSACTION_CREATE_REAL) {
        uint64_t total = 0;

        if(G_Exohood_vstate.tx_total_amount > 0) {
            total = G_Exohood_vstate.tx_total_amount;

            Exohood_base58_public_key(&G_Exohood_vstate.ux_address[0], G_Exohood_vstate.dest_Aout, G_Exohood_vstate.dest_Bout, G_Exohood_vstate.dest_is_subaddress, NULL);
            Exohood_amount2str(total, G_Exohood_vstate.ux_amount, 15);

            Exohood_io_discard(1);
            ui_menu_validation_display(0);

        } else { //loopback tx
            total = G_Exohood_vstate.tx_outs_amount;
            Exohood_amount2str(total, G_Exohood_vstate.ux_amount, 15);
            Exohood_amount2str(G_Exohood_vstate.tx_ins_count*100, G_Exohood_vstate.ux_inputs, 15);

            Exohood_io_discard(1);
            ui_menu_validation_loopback_display(0);
        }

        return 0;
        

    }
    Exohood_io_discard(1);
    return SW_OK;
}

int Exohood_apdu_tx_prompt_fee() {
    if (G_Exohood_vstate.sig_mode == TRANSACTION_CREATE_REAL) {

        G_Exohood_vstate.tx_fee = G_Exohood_vstate.tx_ins_amount-G_Exohood_vstate.tx_outs_amount;
        Exohood_amount2str(G_Exohood_vstate.tx_fee, G_Exohood_vstate.ux_amount, 15);

        Exohood_io_discard(1);
        ui_menu_fee_validation_display(0);
        return 0;
    }
    Exohood_io_discard(1);
    return SW_OK;
}

void add_to_tx_prefix(uint64_t num) {
    unsigned char varint[10] = {0};
    unsigned int size = Exohood_encode_varint(varint, num);
    Exohood_keccak_update_H(varint, size);

    Exohood_io_insert(varint, size);
}

int Exohood_apdu_tx_prefix_start() {
    unsigned int version = Exohood_io_fetch_u32();
    unsigned int unlock_time = Exohood_io_fetch_u32();
    unsigned int vins_size = Exohood_io_fetch_u32();

    Exohood_io_discard(1);

    G_Exohood_vstate.tx_ins_count = 0;
    G_Exohood_vstate.tx_ins_amount = 0;
    G_Exohood_vstate.tx_outs_amount = 0;
    G_Exohood_vstate.tx_fee = 0;
    G_Exohood_vstate.tx_outs_current_index = 0;
    G_Exohood_vstate.tx_total_amount = 0;

    Exohood_keccak_init_H();

    add_to_tx_prefix(version);
    add_to_tx_prefix(unlock_time);
    add_to_tx_prefix(vins_size);
    
    return SW_OK;
}

int Exohood_apdu_tx_prefix_inputs() {
    uint64_t amount = Exohood_io_fetch_u64();

    //unsigned char buffer[sizeof(amount)];
    //memcpy(buffer, &amount, sizeof(amount));
    //PRINTF("64 Bit Amount:\n %.*H \n\n", sizeof(buffer), buffer);

    unsigned int key_offset = Exohood_io_fetch_u32();
    unsigned char k_image[32];
    
    Exohood_io_fetch(k_image,32);

    Exohood_io_discard(0);

    G_Exohood_vstate.tx_ins_amount += amount;
    G_Exohood_vstate.tx_ins_count++;

    add_to_tx_prefix(2);
    add_to_tx_prefix(amount);
    add_to_tx_prefix(1);
    add_to_tx_prefix(key_offset);

    Exohood_keccak_update_H(k_image, 32);
    Exohood_io_insert(k_image, 32);

    return SW_OK;
}

int Exohood_apdu_tx_prefix_outputs() {
    uint64_t amount = Exohood_io_fetch_u64();
    unsigned char key[32];
    Exohood_io_fetch(key,32);
    unsigned int output_index = Exohood_io_fetch_u32();

    Exohood_io_discard(0);

    //read tx_change_idx bit-by-bit
    unsigned int memblock = G_Exohood_vstate.tx_outs_current_index / 8;
    uint8_t shift = G_Exohood_vstate.tx_outs_current_index == 0 ? 0 : (G_Exohood_vstate.tx_outs_current_index - 8*memblock) % 8;

    bool is_change = G_Exohood_vstate.tx_change_idx[memblock] & (1 << shift);

    // To ensure the outputs are really going to their intended destination,
    // we need to check that the stealth addresses correspond to the destination A&B. So recompute P=H(rA)G+B.
    unsigned char drvpub[32]; // stealth address P to be computed
    unsigned char derivation[32]; // r*A
    if(!is_change) {
        Exohood_generate_key_derivation(derivation, G_Exohood_vstate.dest_Aout, G_Exohood_vstate.r);
        Exohood_derive_public_key(drvpub, derivation, output_index, G_Exohood_vstate.dest_Bout); // H(rA)+B
        if(!(memcmp(drvpub, key, sizeof(drvpub)))){
            //reset indexes
            os_memset(G_Exohood_vstate.tx_change_idx, 0, 50);
            return false;
        }
        G_Exohood_vstate.tx_total_amount += amount;
    }
    else{
        Exohood_generate_key_derivation(derivation, G_Exohood_vstate.A, G_Exohood_vstate.r);
        Exohood_derive_public_key(drvpub, derivation, output_index, G_Exohood_vstate.B);
        if(!(memcmp(drvpub, key, sizeof(drvpub)))){
            //reset indexes
            os_memset(G_Exohood_vstate.tx_change_idx, 0, 50);
            return false;
        }
    }
    G_Exohood_vstate.tx_outs_amount += amount;
    G_Exohood_vstate.tx_outs_current_index++;

    add_to_tx_prefix(amount);
    add_to_tx_prefix(2);

    Exohood_keccak_update_H(key, 32);
    Exohood_io_insert(key, 32);

    return SW_OK;
}

int Exohood_apdu_tx_prefix_outputs_size() {
    unsigned int vins_size = Exohood_io_fetch_u32();

    Exohood_io_discard(0);

    add_to_tx_prefix(vins_size);

    return SW_OK;
}

int Exohood_apdu_tx_prefix_extra() {
    unsigned int extra_size = Exohood_io_fetch_u32();
    unsigned char* extra = G_Exohood_vstate.io_buffer+G_Exohood_vstate.io_offset;
    Exohood_io_fetch(NULL,extra_size);

    Exohood_io_discard(0);

    add_to_tx_prefix(extra_size);

    Exohood_keccak_update_H(extra, extra_size);
    Exohood_io_insert(extra, extra_size);

    unsigned char  h[32];
    Exohood_keccak_final_H(h);

    os_memcpy(G_Exohood_vstate.tx_prefix_hash, h, 32);

    //reset indexes
    os_memset(G_Exohood_vstate.tx_change_idx, 0, 50);

    return SW_OK;
}
