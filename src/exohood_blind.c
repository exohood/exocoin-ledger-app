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

#include "os.h"
#include "cx.h"
#include "exohood_types.h"
#include "exohood_api.h"
#include "exohood_vars.h"

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int exohood_apdu_blind() {
    unsigned char v[32];
    unsigned char k[32];
    unsigned char AKout[32];

    exohood_io_fetch_decrypt(AKout,32);
    exohood_io_fetch(k,32);
    exohood_io_fetch(v,32);

    exohood_io_discard(1);

    if ((G_exohood_vstate.options&0x03)==2) {
        os_memset(k,0,32);
        exohood_ecdhHash(AKout, AKout);
        for (int i = 0; i<8; i++){
            v[i] = v[i] ^ AKout[i];
        }
    } else {
        //blind mask
        exohood_hash_to_scalar(AKout, AKout, 32);
        exohood_addm(k,k,AKout);
        //blind value
        exohood_hash_to_scalar(AKout, AKout, 32);
        exohood_addm(v,v,AKout);
    }
    //ret all
    exohood_io_insert(v,32);
    exohood_io_insert(k,32);

    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int exohood_unblind(unsigned char *v, unsigned char *k, unsigned char *AKout, unsigned int short_amount) {
    if (short_amount==2) {
        exohood_genCommitmentMask(k,AKout);
        exohood_ecdhHash(AKout, AKout);
        for (int i = 0; i<8; i++) {
            v[i] = v[i] ^ AKout[i];
        }
    } else {
        //unblind mask
        exohood_hash_to_scalar(AKout, AKout, 32);
        exohood_subm(k,k,AKout);
        //unblind value
        exohood_hash_to_scalar(AKout, AKout, 32);
        exohood_subm(v,v,AKout);
    }
    return 0;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int exohood_apdu_unblind() {
    unsigned char v[32];
    unsigned char k[32];
    unsigned char AKout[32];

    exohood_io_fetch_decrypt(AKout,32);
    exohood_io_fetch(k,32);
    exohood_io_fetch(v,32);

    exohood_io_discard(1);

    exohood_unblind(v, k, AKout, G_exohood_vstate.options&0x03);

    //ret all
    exohood_io_insert(v,32);
    exohood_io_insert(k,32);

    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int exohood_apdu_gen_commitment_mask() {
    unsigned char k[32];
    unsigned char AKout[32];

    exohood_io_fetch_decrypt(AKout,32);

    exohood_io_discard(1);
    exohood_genCommitmentMask(k,AKout);

    //ret all
    exohood_io_insert(k,32);

    return SW_OK;
}
