
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

/* 
 * Modification History
 *
 * September 19, 2002	Dieter Siegmund (dieter@apple.com)
 * - taken out of EAPOLSocket.c
 */

/*
 * EAPUtil.c
 * - functions to return string values, and validate values for EAP
 */

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "EAPUtil.h"
#include "printdata.h"


int
EAPCodeValid(EAPCode code)
{
    if (code >= kEAPCodeRequest
	&& code <= kEAPCodeFailure) {
	return (true);
    }
    return (false);
}

const char *
EAPCodeStr(EAPCode code)
{
    static const char * str[] = {	
	"Request", 
	"Response", 
	"Success",
	"Failure" 
    };
    if (EAPCodeValid(code)) {
	return (str[code - 1]);
    }
    return ("<unknown>");
}

const char *
EAPTypeStr(EAPType type)
{
    switch (type) {
    case kEAPTypeInvalid:
	return ("0 (invalid)");
    case kEAPTypeIdentity:
	return ("Identity");
    case kEAPTypeNotification:
	return ("Notification");
    case kEAPTypeNak:
	return ("Nak");
    case kEAPTypeMD5Challenge:
	return ("MD5");
    case kEAPTypeOneTimePassword:
	return ("One Time Password");
    case kEAPTypeGenericTokenCard:
	return ("Generic Token Card");
    case kEAPTypeTLS:
	return ("TLS");
    case kEAPTypeCiscoLEAP:
	return ("LEAP");
    case kEAPTypeSRPSHA1:
	return ("SRPSHA1");
    case kEAPTypeTTLS:
	return ("TTLS");
    case kEAPTypePEAP:
	return ("PEAP");
    case kEAPTypeMSCHAPv2:
	return ("MSCHAPv2");
    case kEAPTypeExtensions:
	return ("PEAP-Extensions");
    case kEAPTypeEAPFAST:
	return ("EAP-FAST");
    default:
	break;
    }
    return ("<unknown>");
}

static bool
EAPRequestResponseValid(EAPPacketRef eap_p, uint32_t length, bool debug)
{
    EAPNakPacketRef 	nak_p = (EAPNakPacketRef)eap_p;
    EAPRequestPacketRef	rd_p = (EAPRequestPacketRef)eap_p;

    if (length < sizeof(*rd_p)) {
	if (debug) {
	    printf("eap_request_response_valid:"
		   " length %d < sizeof(*rd_p) %ld\n",
		   length, sizeof(*rd_p));
	}
	return (false);
    }
    
    if (debug) {
	printf("%s (%d)\n", EAPTypeStr(rd_p->type),
	       rd_p->type);
    }
    switch (rd_p->type) {
    case kEAPTypeInvalid:
	if (debug) {
	    printf("EAP type is invalid (0)\n");
	}
	return (false);

    case kEAPTypeNak:
	if (length < sizeof(*nak_p)) {
	    if (debug) {
		printf("Nak packet too short\n");
	    }
	    return (false);
	}
	if (debug) {
	    printf("Desired authentication type: %s (%d)\n", 
		   EAPTypeStr(nak_p->desired_type),
		   nak_p->desired_type);
	}
	break;

    default:
	if (debug) {
	    printf("length %d  - sizeof(*rd_p) %ld = %ld\n",
		   length, sizeof(*rd_p), length - sizeof(*rd_p));
	    print_data(rd_p->type_data, length - sizeof(*rd_p));
	}
	break;
    }
    return (true);
}

bool
EAPPacketValid(EAPPacketRef eap_p, uint16_t pkt_length, bool debug)
{
    int			length;
    bool		ret = true;

    if (pkt_length < sizeof(*eap_p)) {
	if (debug) {
	    printf("EAPPacketValid: pkt_length %d < sizeof(*eap_p) %ld\n",
		   pkt_length, sizeof(*eap_p));
	}
	return (false);
    }
    length = EAPPacketGetLength(eap_p);
    if (debug) {
	printf("EAP %s (%d): identifier %d length %d\n",
	       EAPCodeStr(eap_p->code), eap_p->code,
	       eap_p->identifier, length);
    }
    if (pkt_length < length) {
	if (debug) {
	    printf("EAPPacketValid: pkt_length %d < length %d\n",
		   pkt_length, length);
	}
	return (false);
    }
    switch (eap_p->code) {
    case kEAPCodeRequest:
    case kEAPCodeResponse:
	ret = EAPRequestResponseValid(eap_p, length, debug);
	break;
    case kEAPCodeFailure:
    case kEAPCodeSuccess:
	break;
    default:
	break;
    }
    if (debug) {
	if (length < pkt_length) {
	    printf("EAP: %d bytes follow data:\n", pkt_length - length);
	    print_data(eap_p->data + length,
		       pkt_length - length);
	}
    }
    return (ret);
}

EAPPacketRef
EAPPacketCreate(void * buf, int buf_size, 
		uint8_t code, int identifier, int type,
		const void * data, int data_len,
		int * ret_size_p)
{
    EAPPacketRef		pkt_p;
    int				size;

    size = sizeof(*pkt_p);
    if (type != kEAPTypeInvalid) {
	size += data_len + 1;
    }
    if (buf == NULL || size > buf_size) {
	pkt_p = (EAPPacketRef)malloc(size);
    }
    else {
	pkt_p = (EAPPacketRef)buf;
    }
    pkt_p->code = code;
    pkt_p->identifier = identifier;
    EAPPacketSetLength(pkt_p, size);
    if (type != kEAPTypeInvalid) {
	EAPResponsePacketRef	r_p;

	r_p = (EAPResponsePacketRef)pkt_p;
	r_p->type = type;
	if (data != NULL) {
	    memcpy(r_p->type_data, data, data_len);
	}
    }
    else if (data != NULL) {
	memcpy(pkt_p->data, data, data_len);
    }
    if (ret_size_p != NULL) {
	*ret_size_p = size;
    }
    return (pkt_p);
}

