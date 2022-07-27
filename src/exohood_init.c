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

#include "os.h"
#include "cx.h"
#include "Exohood_types.h"
#include "Exohood_api.h"
#include "Exohood_vars.h"


/* ----------------------*/
/* -- A Kind of Magic -- */
/* ----------------------*/
const unsigned char C_MAGIC[8] = {
 'M','O','N','E','R','O','H','W'
};

const unsigned char C_FAKE_SEC_VIEW_KEY[32] = {
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};
const unsigned char C_FAKE_SEC_SPEND_KEY[32] = {
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
};

/* ----------------------------------------------------------------------- */
/* --- Boot                                                            --- */
/* ----------------------------------------------------------------------- */
void Exohood_init() {
  os_memset(&G_Exohood_vstate, 0, sizeof(Exohood_v_state_t));
  //first init ?
  if (os_memcmp((void*)N_Exohood_pstate->magic, (void*)C_MAGIC, sizeof(C_MAGIC)) != 0) {
    #ifdef Exohood_ALPHA
    Exohood_install(STAGENET);
    #else
    Exohood_install(MAINNET);
    #endif
  }

  G_Exohood_vstate.protocol = 0xff;

  os_memset(G_Exohood_vstate.tx_change_idx, 0, 50);

  //load key
  Exohood_init_private_key();
  //ux conf
  Exohood_init_ux();
  // Let's go!
  G_Exohood_vstate.state = STATE_IDLE;
}


/* ----------------------------------------------------------------------- */
/* --- init private keys                                               --- */
/* ----------------------------------------------------------------------- */
void Exohood_wipe_private_key() {
 os_memset(G_Exohood_vstate.a,  0, 32);
 os_memset(G_Exohood_vstate.b,  0, 32);
 os_memset(G_Exohood_vstate.A,  0, 32);
 os_memset(G_Exohood_vstate.B,  0, 32);
 os_memset(&G_Exohood_vstate.spk, 0, sizeof(G_Exohood_vstate.spk));
 G_Exohood_vstate.key_set = 0;
}

void Exohood_init_private_key() {
  unsigned int  path[5];
  unsigned char seed[32];
  unsigned char chain[32];

  //generate account keys

  // m / purpose' / coin_type' / account' / change / address_index
  // m / 44'      / 415'       / 0'       / 0      / 0
  path[0] = 0x8000002C;
  path[1] = 0x8000019F;
  path[2] = 0x80000000;
  path[3] = 0x00000000;
  path[4] = 0x00000000;
  os_perso_derive_node_bip32(CX_CURVE_SECP256K1, path, 5 , seed, chain);

  switch(N_Exohood_pstate->key_mode) {
  case KEY_MODE_SEED:

    Exohood_keccak_F(seed,32,G_Exohood_vstate.b);
    Exohood_reduce(G_Exohood_vstate.b,G_Exohood_vstate.b);
    Exohood_keccak_F(G_Exohood_vstate.b,32,G_Exohood_vstate.a);
    Exohood_reduce(G_Exohood_vstate.a,G_Exohood_vstate.a);
    break;

  case KEY_MODE_EXTERNAL:
    os_memmove(G_Exohood_vstate.a,  (void*)N_Exohood_pstate->a, 32);
    os_memmove(G_Exohood_vstate.b,  (void*)N_Exohood_pstate->b, 32);
    break;

  default :
    THROW(SW_SECURITY_LOAD_KEY);
    return;
  }

  Exohood_ecmul_G(G_Exohood_vstate.A, G_Exohood_vstate.a);
  Exohood_ecmul_G(G_Exohood_vstate.B, G_Exohood_vstate.b);

  //generate key protection
  Exohood_aes_derive(&G_Exohood_vstate.spk,chain,G_Exohood_vstate.a,G_Exohood_vstate.b);


  G_Exohood_vstate.key_set = 1;
}

/* ----------------------------------------------------------------------- */
/* ---  Set up ui/ux                                                   --- */
/* ----------------------------------------------------------------------- */
void Exohood_init_ux() {
  #ifdef UI_NANO_X
  Exohood_base58_public_key(G_Exohood_vstate.ux_wallet_public_address, G_Exohood_vstate.A,G_Exohood_vstate.B, 0, NULL);
  os_memset(G_Exohood_vstate.ux_wallet_public_short_address, '.', sizeof(G_Exohood_vstate.ux_wallet_public_short_address));
  os_memmove(G_Exohood_vstate.ux_wallet_public_short_address, G_Exohood_vstate.ux_wallet_public_address,5);
  os_memmove(G_Exohood_vstate.ux_wallet_public_short_address+7, G_Exohood_vstate.ux_wallet_public_address+98-5,5);
  G_Exohood_vstate.ux_wallet_public_short_address[12] = 0;
  #endif
}

/* ----------------------------------------------------------------------- */
/* ---  Install/ReInstall Exohood app                                   --- */
/* ----------------------------------------------------------------------- */
void Exohood_install(unsigned char netId) {
  unsigned char c;

  //full reset data
  Exohood_nvm_write((void*)N_Exohood_pstate, NULL, sizeof(Exohood_nv_state_t));

  //set mode key
  c = KEY_MODE_SEED;
  nvm_write((void*)&N_Exohood_pstate->key_mode, &c, 1);

  //set net id
  Exohood_nvm_write((void*)&N_Exohood_pstate->network_id, &netId, 1);

  //write magic
  Exohood_nvm_write((void*)N_Exohood_pstate->magic, (void*)C_MAGIC, sizeof(C_MAGIC));
}

/* ----------------------------------------------------------------------- */
/* --- Reset                                                           --- */
/* ----------------------------------------------------------------------- */
#define Exohood_SUPPORTED_CLIENT_SIZE 1
const char * const Exohood_supported_client[Exohood_SUPPORTED_CLIENT_SIZE] = {
  "3.2.0.0"
};

int Exohood_apdu_reset() {

  unsigned int client_version_len;
  char client_version[16];
  client_version_len = G_Exohood_vstate.io_length - G_Exohood_vstate.io_offset;
  if (client_version_len > 15) {
    THROW(SW_CLIENT_NOT_SUPPORTED+1);
  }
  Exohood_io_fetch((unsigned char*)&client_version[0], client_version_len);
  client_version[client_version_len] = 0;
  unsigned int i = 0;
  while(i < Exohood_SUPPORTED_CLIENT_SIZE) {
    if ((strlen((char*)PIC(Exohood_supported_client[i])) == client_version_len) &&
        (os_memcmp((char*)PIC(Exohood_supported_client[i]), client_version, client_version_len)==0) ) {
      break;
    }
    i++; 
  }
  if (i == Exohood_SUPPORTED_CLIENT_SIZE) {
    THROW(SW_CLIENT_NOT_SUPPORTED);
  }

  Exohood_io_discard(0);
  Exohood_init();
  Exohood_io_insert_u8(Exohood_VERSION_MAJOR);
  Exohood_io_insert_u8(Exohood_VERSION_MINOR);
  Exohood_io_insert_u8(Exohood_VERSION_MICRO);
  return 0x9000;
}
