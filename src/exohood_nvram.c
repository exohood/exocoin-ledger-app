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

#ifdef TARGET_NANOX
const Exohood_nv_state_t N_state_pic;
#else
Exohood_nv_state_t N_state_pic;
#endif
