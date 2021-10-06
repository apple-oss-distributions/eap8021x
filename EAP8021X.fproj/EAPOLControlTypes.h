
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

#ifndef _EAP8021X_EAPOLCONTROLTYPES_H
#define _EAP8021X_EAPOLCONTROLTYPES_H

#include <stdint.h>

#include <CoreFoundation/CFString.h>

enum {
    kEAPOLControlStateIdle,
    kEAPOLControlStateStarting,
    kEAPOLControlStateRunning,
    kEAPOLControlStateStopping,
};

typedef uint32_t EAPOLControlState;

/*
 * Property: kEAPOLControlEAPClientConfiguration
 * Purpose:
 *   The name of the sub-dictionary that contains the
 *   EAP client configuration parameters (keys defined in
 *   <EAP8021X/EAPClientProperties.h>).
 */
#define kEAPOLControlEAPClientConfiguration	CFSTR("EAPClientConfiguration")

/*
 * Property: kEAPOLControlUniqueIdentifier
 * Purpose:
 *   Mark the configuration with a unique string so that the
 *   UI can match it to a stored preference.
 *
 *   This property is also published as part of the status dictionary.
 */
#define kEAPOLControlUniqueIdentifier	CFSTR("UniqueIdentifier") /* CFString */

/*
 * Property: kEAPOLControlLogLevel
 * Purpose:
 *   Set the log level.  If the property is not present,
 *   logging is disabled.
 */
#define kEAPOLControlLogLevel		CFSTR("LogLevel") /* CFNumber */

/*
 * properties that appear in the status dictionary
 */
#define kEAPOLControlIdentityAttributes	CFSTR("IdentityAttributes") /* CFArray(CFString) */
#define kEAPOLControlEAPType		CFSTR("EAPType")	/* CFNumber (EAPType) */
#define kEAPOLControlEAPTypeName	CFSTR("EAPTypeName")	/* CFString */
#define kEAPOLControlSupplicantState	CFSTR("SupplicantState") /* CFNumber (SupplicantState) */
#define kEAPOLControlClientStatus	CFSTR("ClientStatus")	/* CFNumber (EAPClientStatus) */
#define kEAPOLControlDomainSpecificError	CFSTR("DomainSpecificError") /* CFNumber (EAPClientDomainSpecificError) */
#define kEAPOLControlTimestamp		CFSTR("Timestamp")	/* CFDate */
#define kEAPOLControlRequiredProperties	CFSTR("RequiredProperties") /* CFArray[CFString] */
#define kEAPOLControlAdditionalProperties	CFSTR("AdditionalProperties") /* CFDictionary */
#define kEAPOLControlSystemMode		CFSTR("SystemMode") /* CFBoolean */
#endif _EAP8021X_EAPOLCONTROLTYPES_H
