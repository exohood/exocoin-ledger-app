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
#include "Exohood_types.h"
#include "Exohood_api.h"
#include "Exohood_vars.h"

#ifndef Exohood_ALPHA
const unsigned char C_MAINNET_NETWORK_ID[] = {
        0x04, 0xF8, 0x23, 0xE1, 0x66, 0xC2, 0xE3, 0xA4, 0xEA, 0x5D, 0xD1, 0x2C, 0x85, 0x8E, 0xC8, 0x39
};
#endif
const unsigned char C_TESTNET_NETWORK_ID[] =  {
        0x04, 0xF8, 0x23, 0xE1, 0x66, 0xC2, 0xE3, 0xA4, 0xEA, 0x5D, 0xD1, 0x2C, 0x85, 0x8E, 0xC8, 0x41
};

const unsigned char C_STAGENET_NETWORK_ID[] =  {
    0x12 ,0x30, 0xF1, 0x71 , 0x61, 0x04 , 0x41, 0x61, 0x17, 0x31, 0x00, 0x82, 0x16, 0xA1, 0xA1, 0x12
};

// Copyright (c) 2022, The Exohood Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


const char         alphabet[]              = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
#define            alphabet_size           (sizeof(alphabet) - 1)
const unsigned int encoded_block_sizes[]   = {0, 2, 3, 5, 6, 7, 9, 10, 11};
#define  FULL_BLOCK_SIZE                   8 //(sizeof(encoded_block_sizes) / sizeof(encoded_block_sizes[0]) - 1)
#define  FULL_ENCODED_BLOCK_SIZE           11 //encoded_block_sizes[full_block_size];
#define  ADDR_CHECKSUM_SIZE                4


static uint64_t uint_8be_to_64(const unsigned char* data, size_t size) {
    uint64_t res = 0;
    switch (9 - size) {
    case 1:            res |= *data++;
    case 2: res <<= 8; res |= *data++;
    case 3: res <<= 8; res |= *data++;
    case 4: res <<= 8; res |= *data++;
    case 5: res <<= 8; res |= *data++;
    case 6: res <<= 8; res |= *data++;
    case 7: res <<= 8; res |= *data++;
    case 8: res <<= 8; res |= *data;
    break;
    }

    return res;
}

static void encode_block(const unsigned char* block, unsigned int  size,  char* res) {
    uint64_t num = uint_8be_to_64(block, size);
    int i = encoded_block_sizes[size] - 1;
    while (0 < num) {
        uint64_t remainder = num % alphabet_size;
        num /= alphabet_size;
        res[i] = alphabet[remainder];
        --i;
    }
}

int Exohood_base58_public_key(char* str_b58, unsigned char *view, unsigned char *spend, unsigned char is_subbadress, unsigned char *paymanetID) {
    unsigned char data[72+8];
    unsigned int offset;
    unsigned int prefix;

    //data[0] = N_Exohood_pstate->network_id;
    switch(N_Exohood_pstate->network_id) {
        case TESTNET:
            if (paymanetID) {
                prefix = TESTNET_CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX;
            } else if (is_subbadress) {
                prefix = TESTNET_CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX;
            } else {
                prefix = TESTNET_CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX;
            }
            break;
        case STAGENET:
            if (paymanetID) {
                prefix = STAGENET_CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX;
            } else if (is_subbadress) {
                prefix = STAGENET_CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX;
            } else {
                prefix = STAGENET_CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX;
            }
            break;
        #ifndef Exohood_ALPHA
        case MAINNET:
            if (paymanetID) {
                prefix = MAINNET_CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX;
            } else if (is_subbadress) {
                prefix = MAINNET_CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX;
            } else {
                prefix = MAINNET_CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX;
            }
            break;
        #endif
    }
    offset = Exohood_encode_varint(data, prefix);

    os_memmove(data+offset,spend,32);
    os_memmove(data+offset+32,view,32);
    offset += 64;
    if (paymanetID) {
        os_memmove(data+offset, paymanetID, 8);
        offset += 8;
    }
    Exohood_keccak_F(data, offset, G_Exohood_vstate.H);
    os_memmove(data+offset, G_Exohood_vstate.H, 4);
    offset += 4;

    unsigned int full_block_count = (offset) / FULL_BLOCK_SIZE;
    unsigned int last_block_size  = (offset) % FULL_BLOCK_SIZE;
    for (size_t i = 0; i < full_block_count; ++i) {
        encode_block(data + i * FULL_BLOCK_SIZE, FULL_BLOCK_SIZE, &str_b58[i * FULL_ENCODED_BLOCK_SIZE]);
        
        // Hard fix to correctly display some addresses on device screen
        if(str_b58[i * FULL_ENCODED_BLOCK_SIZE] == 0) {
            str_b58[i * FULL_ENCODED_BLOCK_SIZE] = '1';
        }
    }

    if (0 < last_block_size) {
        encode_block(data + full_block_count * FULL_BLOCK_SIZE, last_block_size, &str_b58[full_block_count * FULL_ENCODED_BLOCK_SIZE]);
    }

    return 0;
}
