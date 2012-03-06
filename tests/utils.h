/*
 * Copyright (c) - 2011 David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by as
 * published by the Free Software Foundation; only version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdio.h>

#define BRIGHT 1
#define GREEN 32
#define RED 31

#define PRINT_OK() printf("%c[%d;%dmOK%c[%dm\n", 0x1B, BRIGHT, GREEN, 0x1B, 0);
#define PRINT_FAIL() printf("%c[%d;%dmFAIL%c[%dm\n", 0x1B, BRIGHT, RED, 0x1B, 0);
