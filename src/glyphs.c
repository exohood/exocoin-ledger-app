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

#include "glyphs.h"
unsigned int const C_badge_back_colors[] = {
  0x00000000,
  0x00ffffff,
};

unsigned char const C_badge_back_bitmap[] = {
  0xe0, 0x01, 0xfe, 0xc1, 0xfd, 0x38, 0x7f, 0x06, 0xdf, 0x81, 0xff, 0xc4, 0x7f, 0xf3, 0xff, 0xbc,
  0x1f, 0xe7, 0xe7, 0xf1, 0x3f, 0xf8, 0x07, 0x78, 0x00,
};
#ifdef OS_IO_SEPROXYHAL
        #include "os_io_seproxyhal.h"
        const bagl_icon_details_t C_badge_back = { GLYPH_badge_back_WIDTH, GLYPH_badge_back_HEIGHT, 1, C_badge_back_colors, C_badge_back_bitmap };
        #endif // OS_IO_SEPROXYHAL
#include "glyphs.h"
unsigned int const C_icon_back_colors[] = {
  0x00000000,
  0x00ffffff,
};

unsigned char const C_icon_back_bitmap[] = {
  0x00, 0x00, 0x00, 0x00, 0x0c, 0x80, 0x03, 0x70, 0x00, 0x0e, 0xc0, 0xff, 0xf0, 0x3f, 0x38, 0x00,
  0x1c, 0x00, 0x0e, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
};
#ifdef OS_IO_SEPROXYHAL
        #include "os_io_seproxyhal.h"
        const bagl_icon_details_t C_icon_back = { GLYPH_icon_back_WIDTH, GLYPH_icon_back_HEIGHT, 1, C_icon_back_colors, C_icon_back_bitmap };
        #endif // OS_IO_SEPROXYHAL
#include "glyphs.h"
unsigned int const C_icon_certificate_colors[] = {
  0x00000000,
  0x00ffffff,
};

unsigned char const C_icon_certificate_bitmap[] = {
  0x00, 0x00, 0xfe, 0xc1, 0xff, 0x30, 0x30, 0xec, 0x0d, 0x03, 0xc3, 0xde, 0x30, 0x30, 0xec, 0x0d,
  0x03, 0xc3, 0xc0, 0xf0, 0x3f, 0xf8, 0x07, 0x00, 0x00,
};
#ifdef OS_IO_SEPROXYHAL
        #include "os_io_seproxyhal.h"
        const bagl_icon_details_t C_icon_certificate = { GLYPH_icon_certificate_WIDTH, GLYPH_icon_certificate_HEIGHT, 1, C_icon_certificate_colors, C_icon_certificate_bitmap };
        #endif // OS_IO_SEPROXYHAL
#include "glyphs.h"
unsigned int const C_icon_coggle_colors[] = {
  0x00000000,
  0x00ffffff,
};

unsigned char const C_icon_coggle_bitmap[] = {
  0x00, 0x00, 0x00, 0x00, 0x0c, 0x40, 0x0b, 0xf8, 0x07, 0xfc, 0xc0, 0xf3, 0xf0, 0x3c, 0xf0, 0x03,
  0xfe, 0x01, 0x2d, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
};
#ifdef OS_IO_SEPROXYHAL
        #include "os_io_seproxyhal.h"
        const bagl_icon_details_t C_icon_coggle = { GLYPH_icon_coggle_WIDTH, GLYPH_icon_coggle_HEIGHT, 1, C_icon_coggle_colors, C_icon_coggle_bitmap };
        #endif // OS_IO_SEPROXYHAL
#include "glyphs.h"
unsigned int const C_icon_crossmark_colors[] = {
  0x00000000,
  0x00ffffff,
};

unsigned char const C_icon_crossmark_bitmap[] = {
  0x00, 0x80, 0x01, 0xe6, 0xc0, 0x71, 0x38, 0x38, 0x07, 0xfc, 0x00, 0x1e, 0x80, 0x07, 0xf0, 0x03,
  0xce, 0xc1, 0xe1, 0x38, 0x70, 0x06, 0x18, 0x00, 0x00,
};
#ifdef OS_IO_SEPROXYHAL
        #include "os_io_seproxyhal.h"
        const bagl_icon_details_t C_icon_crossmark = { GLYPH_icon_crossmark_WIDTH, GLYPH_icon_crossmark_HEIGHT, 1, C_icon_crossmark_colors, C_icon_crossmark_bitmap };
        #endif // OS_IO_SEPROXYHAL
#include "glyphs.h"
unsigned int const C_icon_dashboard_colors[] = {
  0x00000000,
  0x00ffffff,
};

unsigned char const C_icon_dashboard_bitmap[] = {
  0xe0, 0x01, 0xfe, 0xc1, 0xff, 0x38, 0x70, 0x06, 0xd8, 0x79, 0x7e, 0x9e, 0x9f, 0xe7, 0xe7, 0xb9,
  0x01, 0xe6, 0xc0, 0xf1, 0x3f, 0xf8, 0x07, 0x78, 0x00,
};
#ifdef OS_IO_SEPROXYHAL
        #include "os_io_seproxyhal.h"
        const bagl_icon_details_t C_icon_dashboard = { GLYPH_icon_dashboard_WIDTH, GLYPH_icon_dashboard_HEIGHT, 1, C_icon_dashboard_colors, C_icon_dashboard_bitmap };
        #endif // OS_IO_SEPROXYHAL
#include "glyphs.h"
unsigned int const C_icon_dashboard_x_colors[] = {
  0x00000000,
  0x00ffffff,
};

unsigned char const C_icon_dashboard_x_bitmap[] = {
  0x00, 0x00, 0x00, 0x00, 0x0c, 0x80, 0x07, 0xf0, 0x03, 0xfe, 0xc1, 0xff, 0xf0, 0x3f, 0xf0, 0x03,
  0xcc, 0x00, 0x33, 0xc0, 0x0c, 0x00, 0x00, 0x00, 0x00,
};
#ifdef OS_IO_SEPROXYHAL
        #include "os_io_seproxyhal.h"
        const bagl_icon_details_t C_icon_dashboard_x = { GLYPH_icon_dashboard_x_WIDTH, GLYPH_icon_dashboard_x_HEIGHT, 1, C_icon_dashboard_x_colors, C_icon_dashboard_x_bitmap };
        #endif // OS_IO_SEPROXYHAL
#include "glyphs.h"
unsigned int const C_icon_down_colors[] = {
  0x00000000,
  0x00ffffff,
};

unsigned char const C_icon_down_bitmap[] = {
  0x41, 0x11, 0x05, 0x01,
};
#ifdef OS_IO_SEPROXYHAL
        #include "os_io_seproxyhal.h"
        const bagl_icon_details_t C_icon_down = { GLYPH_icon_down_WIDTH, GLYPH_icon_down_HEIGHT, 1, C_icon_down_colors, C_icon_down_bitmap };
        #endif // OS_IO_SEPROXYHAL
#include "glyphs.h"
unsigned int const C_icon_left_colors[] = {
  0x00000000,
  0x00ffffff,
};

unsigned char const C_icon_left_bitmap[] = {
  0x48, 0x12, 0x42, 0x08,
};
#ifdef OS_IO_SEPROXYHAL
        #include "os_io_seproxyhal.h"
        const bagl_icon_details_t C_icon_left = { GLYPH_icon_left_WIDTH, GLYPH_icon_left_HEIGHT, 1, C_icon_left_colors, C_icon_left_bitmap };
        #endif // OS_IO_SEPROXYHAL
#include "glyphs.h"
unsigned int const C_icon_monero_colors[] = {
  0x00000000,
  0x00ffffff,
};

unsigned char const C_icon_monero_bitmap[] = {
  0xf0, 0x83, 0xff, 0xa7, 0x7f, 0xcd, 0xcf, 0xe3, 0xf1, 0x30, 0x3c, 0x00, 0x0f, 0xc0, 0x10, 0x02,
  0xcc, 0x00, 0x3f, 0xf8, 0x7f, 0xfc, 0x0f, 0xfc, 0x00,
};
#ifdef OS_IO_SEPROXYHAL
        #include "os_io_seproxyhal.h"
        const bagl_icon_details_t C_icon_monero = { GLYPH_icon_monero_WIDTH, GLYPH_icon_monero_HEIGHT, 1, C_icon_monero_colors, C_icon_monero_bitmap };
        #endif // OS_IO_SEPROXYHAL
#include "glyphs.h"
unsigned int const C_icon_right_colors[] = {
  0x00000000,
  0x00ffffff,
};

unsigned char const C_icon_right_bitmap[] = {
  0x21, 0x84, 0x24, 0x01,
};
#ifdef OS_IO_SEPROXYHAL
        #include "os_io_seproxyhal.h"
        const bagl_icon_details_t C_icon_right = { GLYPH_icon_right_WIDTH, GLYPH_icon_right_HEIGHT, 1, C_icon_right_colors, C_icon_right_bitmap };
        #endif // OS_IO_SEPROXYHAL
#include "glyphs.h"
unsigned int const C_icon_up_colors[] = {
  0x00000000,
  0x00ffffff,
};

unsigned char const C_icon_up_bitmap[] = {
  0x08, 0x8a, 0x28, 0x08,
};
#ifdef OS_IO_SEPROXYHAL
        #include "os_io_seproxyhal.h"
        const bagl_icon_details_t C_icon_up = { GLYPH_icon_up_WIDTH, GLYPH_icon_up_HEIGHT, 1, C_icon_up_colors, C_icon_up_bitmap };
        #endif // OS_IO_SEPROXYHAL
#include "glyphs.h"
unsigned int const C_icon_validate_14_colors[] = {
  0x00000000,
  0x00ffffff,
};

unsigned char const C_icon_validate_14_bitmap[] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x38, 0x00, 0x67, 0xe0, 0x38, 0x1c, 0x9c, 0x03,
  0x7e, 0x00, 0x0f, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00,
};
#ifdef OS_IO_SEPROXYHAL
        #include "os_io_seproxyhal.h"
        const bagl_icon_details_t C_icon_validate_14 = { GLYPH_icon_validate_14_WIDTH, GLYPH_icon_validate_14_HEIGHT, 1, C_icon_validate_14_colors, C_icon_validate_14_bitmap };
        #endif // OS_IO_SEPROXYHAL
#include "glyphs.h"
unsigned int const C_icon_warning_colors[] = {
  0x00000000,
  0x00ffffff,
};

unsigned char const C_icon_warning_bitmap[] = {
  0x00, 0x00, 0x30, 0x00, 0x0c, 0x80, 0x07, 0x20, 0x01, 0xcc, 0x00, 0x33, 0xe0, 0x1c, 0x38, 0x07,
  0xff, 0xc3, 0xf3, 0xf8, 0x7c, 0xfe, 0x1f, 0x00, 0x00,
};
#ifdef OS_IO_SEPROXYHAL
        #include "os_io_seproxyhal.h" 
        const bagl_icon_details_t C_icon_warning = { GLYPH_icon_warning_WIDTH, GLYPH_icon_warning_HEIGHT, 1, C_icon_warning_colors, C_icon_warning_bitmap };
        #endif // OS_IO_SEPROXYHAL
