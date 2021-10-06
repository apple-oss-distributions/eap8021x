/*
 * Copyright (c) 2002 Apple Computer, Inc. All rights reserved.
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

#ifndef _EAPOLCONTROLLER_EXT_H
#define _EAPOLCONTROLLER_EXT_H

#include <mach/mach_init.h>
#include <servers/bootstrap.h>

#define EAPOLCONTROLLER_SERVER		"com.apple.network.EAPOLController"

static __inline__ kern_return_t
eapolcontroller_server_port(mach_port_t * server)
{
    return (bootstrap_look_up(bootstrap_port, EAPOLCONTROLLER_SERVER, server));
}

#endif _EAPOLCONTROLLER_EXT_H
