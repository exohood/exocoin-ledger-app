// Copyright (c) Exohood Protocol 2020-2022
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

#include "os_io_seproxyhal.h"

unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

#ifdef TARGET_NANOX
/* --- NANO-X config --- */

#include "ux.h"
ux_state_t G_ux;
bolos_ux_params_t G_ux_params;

#else
/* --- NANO-X config --- */

ux_state_t ux;

#endif


exohood_v_state_t  G_exohood_vstate;
