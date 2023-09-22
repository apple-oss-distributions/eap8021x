/*
 * Copyright (c) 2001-2020, 2023 Apple Inc. All rights reserved.
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

#ifndef _EAP8021X_EAPCERTIFICATE_UTIL_H
#define _EAP8021X_EAPCERTIFICATE_UTIL_H


/*
 * EAPCertificateUtil.h
 * - certificate utility functions
 */

/* 
 * Modification History
 *
 * April 2, 2004	Dieter Siegmund (dieter@apple.com)
 * - created
 */

#include <TargetConditionals.h>
#include <os/availability.h>
#include <CoreFoundation/CFBase.h>
#include <CoreFoundation/CFData.h>
#include <CoreFoundation/CFArray.h>
#include <CoreFoundation/CFString.h>
#include <CoreFoundation/CFPropertyList.h>
#include <Security/Security.h>
#include <Security/SecCertificate.h>

/*
 * Type: EAPSecIdentityHandleRef
 * Purpose:
 *   Type used to store a handle for a SecIdentityRef.  This is just
 *   an alias for a CFPropertyListRef, thus it can be serialized and stored
 *   in persistent storage.
 */
typedef CFPropertyListRef	EAPSecIdentityHandleRef;

/*
 * Function: EAPSecIdentityHandleCreate
 * Purpose:
 *   Returns an EAPSecIdentityHandleRef (CFPropertyListRef) to represent
 *   the specified SecIdentityRef. The EAPSecIdentityHandleRef is a
 *   CFPropertyListRef and therefore can be serialized and stored
 *   externally.
 */
EAPSecIdentityHandleRef
EAPSecIdentityHandleCreate(SecIdentityRef identity);

/*
 * Function: EAPSecIdentityHandleCreateSecIdentityTrustChain
 * Purpose:
 *   Find the identity that matches the given id_handle, and
 *   return it along with the certificate trust chain (see
 *   EAPSecIdentityHandleCreateSecIdentity() below).
 *
 * Returns:
 *   If return value is noErr, returns an array (*ret_array) containing the 
 *   identity plus certificate trust chain for use with SSLSetCertificate().
 *
 *   If return code is not noErr, *ret_array is NULL.
 */
OSStatus
EAPSecIdentityHandleCreateSecIdentityTrustChain(EAPSecIdentityHandleRef handle,
						CFArrayRef * ret_array);

/*
 * Function: EAPSecIdentityCreateTrustChain
 *
 * Purpose:
 *   Turns an SecIdentityRef into the array required by
 *   SSLSetCertificates().  See the <Security/SecureTransport.h> for more
 *   information.
 *
 * Returns:
 *   noErr and *ret_array != NULL on success, non-noErr otherwise.
 */
OSStatus
EAPSecIdentityCreateTrustChain(SecIdentityRef identity,
			       CFArrayRef * ret_array);

/*
 * Function: EAPSecIdentityHandleCreateSecIdentity
 * Purpose:
 *   Retrieve a SecIdentityRef corresponding to the given id_handle.
 *   If id_handle is NULL, finds the first SecIdentityRef capable of
 *   signing.
 *
 *   To create the id_handle, use EAPSecIdentityHandleCreateFromSecIdentity().
 */
OSStatus
EAPSecIdentityHandleCreateSecIdentity(EAPSecIdentityHandleRef id_handle,
				      SecIdentityRef * ret_identity);

/*
 * Function: EAPSecIdentityListCreate
 * Purpose:
 *   Return a list of SecIdentityRef's suitable for use with EAP/TLS.
 * Returns:
 *   If the return value is noErr, a CFArrayRef of SecIdentityRef's.
 */
OSStatus
EAPSecIdentityListCreate(CFArrayRef * ret_array);

/*
 * Function: EAPSecCertificateArrayCreateCFDataArray
 * Purpose:
 *   Creates a CFArray[CFData] from a CFArray[SecCertificate].
 */
CFArrayRef
EAPSecCertificateArrayCreateCFDataArray(CFArrayRef certs);

/*
 * Function: EAPCFDataArrayCreateSecCertificateArray
 * Purpose:
 *   Creates a CFArray[SecCertificate] from a CFArray[CFData].
 */
CFArrayRef
EAPCFDataArrayCreateSecCertificateArray(CFArrayRef certs);

CFTypeRef
isA_SecCertificate(CFTypeRef obj);

CFTypeRef
isA_SecIdentity(CFTypeRef obj);

/*
 * Function: EAPSecIdentityCreateTrustChainWithPersistentCertificateRefs
 * Purpose:
 *   Create client's certificate trust chain using configuration passed
 *   by NEHotspotConfiguration application.
 */
OSStatus
EAPSecIdentityCreateTrustChainWithPersistentCertificateRefs(SecIdentityRef sec_identity, CFArrayRef chain, CFArrayRef * ret_array) API_AVAILABLE(ios(11.0), watchos(5.0), tvos(9.0)) API_UNAVAILABLE(macos, macCatalyst);

OSStatus
EAPSecIdentityCompareIdentityHandle(SecIdentityRef identity, CFDataRef handle, Boolean *result);

/*
 * EAPSecCertificateAttribute dictionary keys:
 */
/* CFBoolean's */
#define kEAPSecCertificateAttributeIsRoot		CFSTR("IsRoot")

/* CFString's */
#define kEAPSecCertificateAttributeCommonName		CFSTR("CommonName")
#define kEAPSecCertificateAttributeNTPrincipalName	CFSTR("NTPrincipalName")
#define kEAPSecCertificateAttributeRFC822Name		CFSTR("RFC822Name")
#define kEAPSecCertificateAttributeEmailAddress		CFSTR("EmailAddress")
#define kEAPSecCertificateAttributeDNSName		CFSTR("DNSName")

/*
 * Function: EAPSecCertificateCopyAttributesDictionary
 * Purpose:
 *   Returns a CFDictionary containing certificate attributes.
 * Notes:
 *   A certificate can contain multiple value for a given attribute i.e. a 
 *   cert can contain multiple Subject Alt Name's with multiple RFC 822 fields.
 *   This API stores just the first one that is encountered.
 */
CFDictionaryRef
EAPSecCertificateCopyAttributesDictionary(SecCertificateRef cert);

/* 
 * Function: EAPSecCertificateCopyUserNameString
 * Purpose:
 *   Parse the given certificate, and return the best name to use as a 
 *   username.
 * Returns:
 *   Non-NULL username, if one was found, NULL otherwise.
 */
CFStringRef
EAPSecCertificateCopyUserNameString(SecCertificateRef cert);

/*
 * Function EAPSecCertificateCopySHA1DigestString
 * Purpose:
 *   Return the SHA1 digest for the given cert as a CFString.
 */
CFStringRef
EAPSecCertificateCopySHA1DigestString(SecCertificateRef cert) API_AVAILABLE(ios(8.0), watchos(5.0), tvos(9.0), macos(10.16));

#endif /* _EAP8021X_EAPCERTIFICATE_UTIL_H */
