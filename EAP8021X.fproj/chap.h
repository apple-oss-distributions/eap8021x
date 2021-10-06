/*
 * Copyright (c) 2001-2002 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */

#ifndef _EAP8021X_CHAP_H
#define _EAP8021X_CHAP_H

#include <stdint.h>

/* 
 * Modification History
 *
 * December 10, 2001	Dieter Siegmund (dieter@apple.com)
 * - created
 */

/*
 * Function: chap_md5
 * Purpose:
 *   Compute the CHAP MD5 hash using the method described in
 *   RFC 1994.
 */
void
chap_md5(uint8_t identifier, const uint8_t * password, int password_length,
	 const uint8_t * challenge, int challenge_len,
	 uint8_t * hash);
#endif _EAP802_1x_CHAP_H
