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

#ifndef exohood_VARS_H
#define exohood_VARS_H

#include "os.h"
#include "cx.h"
#include "os_io_seproxyhal.h"
#include "exohood_types.h"
#include "exohood_api.h"


extern exohood_v_state_t  G_exohood_vstate;

#ifdef TARGET_NANOX
extern const exohood_nv_state_t N_state_pic;
#define N_exohood_pstate  ((volatile  exohood_nv_state_t *)PIC(&N_state_pic))
#else
extern exohood_nv_state_t N_state_pic;
#define N_exohood_pstate  ((WIDE  exohood_nv_state_t *)PIC(&N_state_pic))
#endif

#ifdef exohood_DEBUG_MAIN
extern int apdu_n;
#endif

extern ux_state_t ux;
#endif
