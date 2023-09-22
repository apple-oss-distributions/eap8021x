/*
 * Copyright (c) 2006-2019, 2023 Apple Inc. All rights reserved.
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

#ifndef _EAP8021X_EAPKEYCHAINUTILINTERNAL_H
#define _EAP8021X_EAPKEYCHAINUTILINTERNAL_H

/*
 * EAPKeychainUtilInternal.h
 * - internal definitions for setting keychain items
 */

/* 
 * Modification History
 *
 * January 14, 2010	Dieter Siegmund (dieter@apple)
 * - created
 */

#include <TargetConditionals.h>

#if ! TARGET_OS_IPHONE

#include "symbol_scope.h"
#include <Security/SecAccess.h>

PRIVATE_EXTERN OSStatus
EAPSecKeychainItemSetAccessForTrustedApplications(SecKeychainItemRef item,
						  CFArrayRef trusted_apps);
#endif /* ! TARGET_OS_IPHONE */

#if TARGET_OS_IPHONE

OSStatus
EAPKeychainSetIdentityReference(CFStringRef unique_string, CFDataRef reference, Boolean update);

OSStatus
EAPKeychainCopyIdentityReference(CFStringRef unique_string, CFDataRef *reference);

OSStatus
EAPKeychainSetPasswordItem(CFStringRef unique_string, CFDataRef username, CFDataRef password, Boolean update);

OSStatus
EAPKeychainCopyPasswordItem(CFStringRef unique_string, CFDataRef *username_p, CFDataRef *password_p);

OSStatus
EAPKeychainRemovePasswordItem(CFStringRef unique_string);

#endif /* TARGET_OS_IPHONE */

#endif /* _EAP8021X_EAPKEYCHAINUTILINTERNAL_H */

