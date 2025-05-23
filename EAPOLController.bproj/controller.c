/*
 * Copyright (c) 2002-2024 Apple Inc. All rights reserved.
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
 * November 8, 2001	Dieter Siegmund
 * - created
 */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/sockio.h>
#include <sys/socket.h>
#include <string.h>
#include <net/if.h>
#include <net/if_media.h>
#include <net/ethernet.h>
#include <sys/errno.h>
#include <sys/queue.h>
#include <mach/mach.h>
#include <mach/message.h>
#include <mach/mach_error.h>
#include <sys/param.h>
#include <sys/types.h>
#include <fcntl.h>
#include <paths.h>
#include <pwd.h>
#include <pthread.h>
#include <SystemConfiguration/SystemConfiguration.h>
#include <SystemConfiguration/SCValidation.h>
#include <SystemConfiguration/SCPrivate.h>
#include <CoreFoundation/CFDictionary.h>
#include <CoreFoundation/CFMachPort.h>
#include <CoreFoundation/CFRunLoop.h>
#if TARGET_OS_IPHONE
#include <CoreTelephony/CTSimSupportStrings.h>
#include <MobileWiFi/MobileWiFi.h>
#include "SIMAccessPrivate.h"
#include <notify.h>
#include <MobileKeyBag/UserManager.h>
#include <os/feature_private.h>
#endif /* TARGET_OS_IPHONE */
#include <SystemConfiguration/SCDPlugin.h>
#include <TargetConditionals.h>
#include <EAP8021X/myCFUtil.h>
#include "controller.h"
#include "server.h"
#include <CoreFoundation/CFSocket.h>
#include "EAPOLClientConfiguration.h"
#include "EAPOLClientConfigurationPrivate.h"
#include "EAPOLControlPrivate.h"
#include "EAPOLControlTypesPrivate.h"
#if TARGET_OS_IPHONE
#include "EAPOLSIMPrefsManage.h"
#endif /* TARGET_OS_IPHONE */
#include "ClientControlInterface.h"
#include "EAPOLControlTypes.h"
#include "EAPClientProperties.h"
#include "eapol_socket.h"
#include "EAPLog.h"
#include "EAPOLControlPrefs.h"
#include "EAP.h"
#include "EAPWiFiUtil.h"

#ifndef kSCEntNetRefreshConfiguration
#define kSCEntNetRefreshConfiguration	CFSTR("RefreshConfiguration")
#endif /* kSCEntNetRefreshConfiguration */

#ifndef kSCEntNetEAPOL
#define kSCEntNetEAPOL			CFSTR("EAPOL")
#endif /* kSCEntNetEAPOL */

#define kSystemModeManagedExternally	CFSTR("_SystemModeManagedExternally")

static SCDynamicStoreRef	S_store;
static char * 			S_eapolclient_path = NULL;

struct eapolClient_s;
#define LIST_HEAD_clientHead 	LIST_HEAD(clientHead, eapolClient_s)
static LIST_HEAD_clientHead	S_head;
static struct clientHead * S_clientHead_p = &S_head;

#define LIST_ENTRY_eapolClient_s	LIST_ENTRY(eapolClient_s)

typedef struct eapolClient_s {
    LIST_ENTRY_eapolClient_s	link;
    EAPOLControlState		state;

    if_name_t			if_name;
    CFStringRef 		if_name_cf;
    boolean_t			is_wifi;

    CFStringRef			notification_key;
    CFStringRef			force_renew_key;
    struct {
	uid_t			uid;
	gid_t			gid;
    } owner;

    pid_t			pid;
    mach_port_t			notify_port;
    mach_port_t			bootstrap;
    mach_port_t			au_session;
    boolean_t 			ports_provided;
    CFMachPortRef		session_cfport;
    boolean_t			notification_sent;
    boolean_t			retry;
    boolean_t			user_input_provided;

    boolean_t			console_user;	/* started by console user */
    EAPOLControlMode		mode;
    CFDictionaryRef		config_dict;
    CFDictionaryRef		user_input_dict;

    CFDictionaryRef		status_dict;
    boolean_t			using_global_system_profile;
    boolean_t			autodetect_can_start_system_mode;
    CFSocketRef			eapol_sock;
    int				eapol_fd;
#define BAD_IDENTIFIER		(-1)
    int				packet_identifier;
    struct ether_addr		authenticator_mac;
#if ! TARGET_OS_IPHONE
    CFDictionaryRef		loginwindow_config;
    bool			user_cancelled;
    bool 			preboot_auto_detection_handled;
#endif /* ! TARGET_OS_IPHONE */
} eapolClient, *eapolClientRef;

#if TARGET_OS_IPHONE

static __inline__ boolean_t
is_console_user(uid_t check_uid)
{
    return (TRUE);
}

#else /* TARGET_OS_IPHONE */

static void
clear_loginwindow_config(eapolClientRef client)
{
    my_CFRelease(&client->loginwindow_config);
    return;
}

static void
set_loginwindow_config(eapolClientRef client)
{
    CFDictionaryRef	itemID_dict;

    clear_loginwindow_config(client);
    if (client->config_dict == NULL) {
	return;
    }
    /*
     * If there's an EAPOLClientItemID dictionary, save a dictionary containing
     * just that property: don't save the whole dictionary because it contains
     * the name/password.
     */
    itemID_dict = CFDictionaryGetValue(client->config_dict,
				       kEAPOLControlClientItemID);
    if (isA_CFDictionary(itemID_dict) != NULL) {
	CFStringRef	key;

	key = kEAPOLControlClientItemID;
	client->loginwindow_config
	    = CFDictionaryCreate(NULL,
				 (const void * *)&key,
				 (const void * *)&itemID_dict, 1,
				 &kCFTypeDictionaryKeyCallBacks,
				 &kCFTypeDictionaryValueCallBacks);
    }
    return;
}

static uid_t
login_window_uid(void)
{
    static uid_t	login_window_uid = -1;

    /* look up the _securityagent user */
    if (login_window_uid == -1) {
	struct passwd *	pwd = getpwnam("_securityagent");
	if (pwd == NULL) {
	    EAPLOG(LOG_NOTICE,
		   "EAPOLController: getpwnam(_securityagent) failed");
	    return (92);
	}
	login_window_uid = pwd->pw_uid;
    }
    return (login_window_uid);
}

static boolean_t
is_console_user(uid_t check_uid)
{
    uid_t	uid;
    CFStringRef user;

    user = SCDynamicStoreCopyConsoleUser(S_store, &uid, NULL);
    if (user == NULL) {
	return (FALSE);
    }
    CFRelease(user);
    return (check_uid == uid);
}

#endif /* TARGET_OS_IPHONE */

static CFDictionaryRef
S_profile_copy_itemID_dict(EAPOLClientProfileRef profile)
{
    CFStringRef			key;
    CFDictionaryRef		dict;
    EAPOLClientItemIDRef	itemID;
    CFDictionaryRef		itemID_dict;

    itemID = EAPOLClientItemIDCreateWithProfile(profile);
    itemID_dict = EAPOLClientItemIDCopyDictionary(itemID);
    CFRelease(itemID);
    key = kEAPOLControlClientItemID;
    dict = CFDictionaryCreate(NULL,
			      (const void * *)&key,
			      (const void * *)&itemID_dict, 1,
			      &kCFTypeDictionaryKeyCallBacks,
			      &kCFTypeDictionaryValueCallBacks);
    CFRelease(itemID_dict);
    return (dict);
}

static int
get_ifm_type(const char * name)
{
    int			i;
    struct ifmediareq	ifm;
    int			media_static[20];
    int			media_static_count = sizeof(media_static) / sizeof(media_static[0]);
    int			s;
    int			ifm_type = 0;
    bool		supports_full_duplex = FALSE;
    bool 		ifm_ulist_allocated = FALSE;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
	perror("socket");
	goto done;
    }
    bzero(&ifm, sizeof(ifm));
    strlcpy(ifm.ifm_name, name, sizeof(ifm.ifm_name));
    if (ioctl(s, SIOCGIFMEDIA, (caddr_t)&ifm) < 0) {
	goto done;
    }
    ifm_type = IFM_TYPE(ifm.ifm_current);
    if (ifm_type != IFM_ETHER) {
	goto done;
    }
    if (ifm.ifm_count == 0) {
	goto done;
    }
    if (ifm.ifm_count > media_static_count) {
	ifm.ifm_ulist = (int *)malloc(ifm.ifm_count * sizeof(int));
	ifm_ulist_allocated = TRUE;
    }
    else {
	ifm.ifm_ulist = media_static;
    }
    if (ioctl(s, SIOCGIFMEDIA, (caddr_t)&ifm) == -1) {
	goto done;
    }
    if (ifm.ifm_count == 1) {
	/* only support one media type, not real ethernet */
	goto done;
    }
    for (i = 0; i < ifm.ifm_count; i++) {
	if ((ifm.ifm_ulist[i] & IFM_FDX) != 0) {
	    supports_full_duplex = TRUE;
	    break;
	}
    }

 done:
    if (ifm_ulist_allocated) {
	free(ifm.ifm_ulist);
    }
    if (s >= 0) {
	close(s);
    }
    if (ifm_type == IFM_ETHER && supports_full_duplex == FALSE) {
	/* not really ethernet */
	ifm_type = 0;
    }
    return (ifm_type);
}


static CFMachPortRef
my_CFMachPortCreate(const void * port_context,
		    CFMachPortCallBack callout,
		    CFMachPortContext * context)
{
    CFMachPortRef	cf_port;
    mach_port_options_t	opts;
    mach_port_t 	port = MACH_PORT_NULL;
    kern_return_t 	status;

    memset(&opts, 0, sizeof(opts));
    opts.flags = MPO_CONTEXT_AS_GUARD | MPO_INSERT_SEND_RIGHT;
    status = mach_port_construct(mach_task_self(), &opts,
				 (mach_port_context_t)port_context, &port);
    if (status != KERN_SUCCESS) {
	EAPLOG(LOG_ERR,
	       "could not allocate mach port: %s", mach_error_string(status));
	return (NULL);
    }
    cf_port = _SC_CFMachPortCreateWithPort("EAPOLController",
					   port, callout, context);
    if (cf_port == NULL) {
	/* _SC_CFMachPortCreateWithPort already logged the failure */
	(void)mach_port_destruct(mach_task_self(),
				 port, 0, (mach_port_context_t)port_context);
    }
    return (cf_port);
}

static void
my_CFMachPortDeallocate(const void * port_context,
			CFMachPortRef * cf_port_p)
{
    CFMachPortRef	cf_port = *cf_port_p;
    mach_port_t		port;

    port = CFMachPortGetPort(cf_port);
    CFMachPortInvalidate(cf_port);
    (void)mach_port_destruct(mach_task_self(), port, 0,
			     (mach_port_context_t)port_context);
    my_CFRelease(cf_port_p);
}

static int
eapolClientStop(eapolClientRef client);

static void
eapolClientSetState(eapolClientRef client, EAPOLControlState state);


static CFNumberRef
make_number(int val)
{
    return (CFNumberCreate(NULL, kCFNumberIntType, &val));
}

eapolClientRef
eapolClientLookupInterfaceCF(CFStringRef if_name_cf)
{
    eapolClientRef	scan;

    LIST_FOREACH(scan, S_clientHead_p, link) {
	if (CFEqual(if_name_cf, scan->if_name_cf)) {
	    return (scan);
	}
    }
    return (NULL);
}
eapolClientRef
eapolClientLookupInterface(const char * if_name)
{
    eapolClientRef	scan;

    LIST_FOREACH(scan, S_clientHead_p, link) {
	if (strcmp(if_name, scan->if_name) == 0) {
	    return (scan);
	}
    }
    return (NULL);
}

eapolClientRef
eapolClientLookupProcess(pid_t pid)
{
    eapolClientRef	scan;

    LIST_FOREACH(scan, S_clientHead_p, link) {
	if (pid == scan->pid) {
	    return (scan);
	}
    }
    return (NULL);
}

eapolClientRef
eapolClientLookupSession(mach_port_t session_port)
{
    eapolClientRef	scan;

    LIST_FOREACH(scan, S_clientHead_p, link) {
	if (scan->session_cfport != NULL
	    && session_port == CFMachPortGetPort(scan->session_cfport)) {
	    return (scan);
	}
    }
    return (NULL);
}

eapolClientRef
eapolClientAdd(const char * if_name, boolean_t is_wifi)
{
    eapolClientRef client;

    client = malloc(sizeof(*client));
    if (client == NULL) {
	return (NULL);
    }
    bzero(client, sizeof(*client));
    strlcpy(client->if_name, if_name, sizeof(client->if_name));
    client->if_name_cf = CFStringCreateWithCString(NULL, client->if_name, 
						   kCFStringEncodingASCII);
    client->is_wifi = is_wifi;
    client->pid = -1;
    client->eapol_fd = -1;
    client->packet_identifier = BAD_IDENTIFIER;
    client->autodetect_can_start_system_mode = !is_wifi;
    LIST_INSERT_HEAD(S_clientHead_p, client, link);
    return (client);
}

void
eapolClientRemove(eapolClientRef client)
{
#if ! TARGET_OS_IPHONE
    clear_loginwindow_config(client);
#endif /* ! TARGET_OS_IPHONE */
    my_CFRelease(&client->if_name_cf);
    LIST_REMOVE(client, link);
    free(client);
    return;
}

static void
eapolClientInvalidate(eapolClientRef client)
{
    eapolClientSetState(client, kEAPOLControlStateIdle);
    client->pid = -1;
    client->owner.uid = 0;
    client->owner.gid = 0;
    client->mode = kEAPOLControlModeNone;
    client->retry = FALSE;
    client->notification_sent = FALSE;
    client->console_user = FALSE;
    client->user_input_provided = FALSE;
    client->ports_provided = FALSE;
    client->using_global_system_profile = FALSE;
    client->packet_identifier = BAD_IDENTIFIER;
    my_CFRelease(&client->notification_key);
    my_CFRelease(&client->force_renew_key);
    if (client->notify_port != MACH_PORT_NULL) {
	(void)mach_port_deallocate(mach_task_self(), client->notify_port);
	client->notify_port = MACH_PORT_NULL;
    }
    if (client->bootstrap != MACH_PORT_NULL) {
	(void)mach_port_deallocate(mach_task_self(), client->bootstrap);
	client->bootstrap = MACH_PORT_NULL;
    }
    if (client->au_session != MACH_PORT_NULL) {
	(void)mach_port_deallocate(mach_task_self(), client->au_session);
	client->au_session = MACH_PORT_NULL;
    }
    if (client->session_cfport != NULL) {
	my_CFMachPortDeallocate(client, &client->session_cfport);
    }
    my_CFRelease(&client->config_dict);
    my_CFRelease(&client->user_input_dict);
    my_CFRelease(&client->status_dict);
    return;
}

static void
eapolClientNotify(eapolClientRef client)
{
    mach_msg_empty_send_t	msg;
    kern_return_t		status;

    if (client->notify_port == MACH_PORT_NULL) {
	return;
    }
    if (client->notification_sent == TRUE) {
	/* no need to send more than a single message */
	return;
    }
    msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    msg.header.msgh_size = sizeof(msg);
    msg.header.msgh_remote_port = client->notify_port;
    msg.header.msgh_local_port = MACH_PORT_NULL;
    msg.header.msgh_id = 0;
    status = mach_msg(&msg.header,			/* msg */
		      MACH_SEND_MSG | MACH_SEND_TIMEOUT,/* options */
		      msg.header.msgh_size,		/* send_size */
		      0,				/* rcv_size */
		      MACH_PORT_NULL,			/* rcv_name */
		      0,				/* timeout */
		      MACH_PORT_NULL);			/* notify */
    if (status != KERN_SUCCESS) {
	EAPLOG_FL(LOG_NOTICE,  "mach_msg(%s) failed: %s",
		  client->if_name, mach_error_string(status));
    }
    client->notification_sent = TRUE;
    return;
}

static CFStringRef
eapolClientNotificationKey(eapolClientRef client)
{
    if (client->notification_key == NULL) {
	client->notification_key
	    = SCDynamicStoreKeyCreateNetworkInterfaceEntity(NULL,
							    kSCDynamicStoreDomainState,
							    client->if_name_cf,
							    kSCEntNetEAPOL);
    }
    return (client->notification_key);
}

static void
eapolClientSetState(eapolClientRef client, EAPOLControlState state)
{
    client->state = state;
    if (S_store == NULL) {
	return;
    }
    SCDynamicStoreNotifyValue(S_store, eapolClientNotificationKey(client));
    return;
}

static void
eapolClientPublishStatus(eapolClientRef client, CFDictionaryRef status_dict)

{
    CFRetain(status_dict);
    my_CFRelease(&client->status_dict);
    client->status_dict = status_dict;
    if (S_store != NULL) {
	SCDynamicStoreNotifyValue(S_store, eapolClientNotificationKey(client));
    }
    return;
}

static CFStringRef
eapolClientForceRenewKey(eapolClientRef client)
{
    if (client->force_renew_key == NULL) {
	client->force_renew_key
	    = SCDynamicStoreKeyCreateNetworkInterfaceEntity(NULL,
							    kSCDynamicStoreDomainState,
							    client->if_name_cf,
							    kSCEntNetRefreshConfiguration);
    }
    return (client->force_renew_key);
}

static void
eapolClientForceRenew(eapolClientRef client)

{
    if (S_store == NULL) {
	return;
    }
    SCDynamicStoreNotifyValue(S_store, eapolClientForceRenewKey(client));
    return;
}

#define kPrefsName	CFSTR("EAPOLController")

static void
start_eapolclient_with_system_ethernet_configuration(eapolClientRef client);

#pragma mark - functions to access auto-detect status

#if TARGET_OS_OSX

#include <os/boot_mode_private.h>
#include <limits.h>
#include <uuid/uuid.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <string.h>

static bool
is_fvunlock_current_boot_mode(void)
{
    bool 	result = false;
    const char *boot_mode = NULL;

    if (os_boot_mode_query(&boot_mode) && boot_mode != NULL) {
	result = (strcmp(boot_mode, OS_BOOT_MODE_FVUNLOCK) == 0);
	EAPLOG(LOG_DEBUG, "EAPOLController: %s: boot mode: %s",
	       __func__, boot_mode);
    } else {
	EAPLOG(LOG_DEBUG, "EAPOLController: %s: boot mode unavailable", __func__);
    }
    return result;
}

#define kEAPOLControllerAutoDetectPrefsID		CFSTR("com.apple.network.eapol.auto-detect.plist")
#define kEAPOLControllerAutoDetectInterfaces		CFSTR("Interfaces") /* dictionary */
#define kEAPOLControllerAutoDetectBootUUID		CFSTR("BootUUID") /* string */
#define kEAPOLControllerAutoDetectAuthenticatorMAC	CFSTR("AuthenticatorMAC") /* data */
#define kEAPOLControllerAutoDetectIdentifier		CFSTR("Identifier") /* number */

/* auto-detect status schema
 *    {
 *        "BootUUID" => "EAFD1150-5056-4AE3-BFE4-90DAE1268A3F"
 *        "Interfaces" => {
 *                            "en0" => {
 *			                   "AuthenticatorMAC" => {}
 *				           "Identifier" => 1
 *				       },
 *                            "en1" => {
 *			                   "AuthenticatorMAC" => {}
 *				           "Identifier" => 1
 *				       }
 *                        }
 *    }
 */

static CFStringRef
get_boot_uuid(void)
{
    static dispatch_once_t 	once;
    static CFStringRef 		boot_uuid;

    dispatch_once(&once, ^{
	uuid_string_t 	boot_uuid_str;
	size_t		size = sizeof(boot_uuid_str);
	int result = sysctlbyname("kern.bootuuid", boot_uuid_str, &size, NULL, 0);
	if (result != 0) {
	    EAPLOG(LOG_ERR, "EAPOLController: %s: sysctlbyname failed to read kern.bootuuid %s (%d)",
		   __func__, strerror(errno), errno);
	} else {
	    boot_uuid = CFStringCreateWithCString(NULL, boot_uuid_str, kCFStringEncodingASCII);
	}
    });
    return (boot_uuid);
}

#ifndef kSCPreferencesOptionUsePrebootVolume
#define kSCPreferencesOptionUsePrebootVolume 	CFSTR("use-preboot-volume")
#endif /* kSCPreferencesOptionUsePrebootVolume */

static CFDictionaryRef
copy_preboot_volume_options(void)
{
#ifdef TEST_AUTO_DETECT_STATUS
    return NULL;
#else /* TEST_AUTO_DETECT_STATUS */
    CFStringRef	key = kSCPreferencesOptionUsePrebootVolume;
    CFTypeRef	value = kCFBooleanTrue;
    return CFDictionaryCreate(NULL,
			      (const void **)&key,
			      (const void **)&value,
			      1,
			      &kCFTypeDictionaryKeyCallBacks,
			      &kCFTypeDictionaryValueCallBacks);
#endif /* TEST_AUTO_DETECT_STATUS */
}

static void
add_interface_to_auto_detect_status(CFStringRef interface, CFDataRef authenticator_mac, CFNumberRef identifier)
{
    SCPreferencesRef		prefs = NULL;
    CFDictionaryRef		options = NULL;
    CFDictionaryRef 		interfaces = NULL;
    CFMutableDictionaryRef 	new_interfaces = NULL;
    CFDictionaryRef		new_interface_info = NULL;
    CFStringRef 		prefs_boot_uuid = NULL;
    CFStringRef 		current_boot_uuid = get_boot_uuid();

    if (current_boot_uuid == NULL) {
	EAPLOG(LOG_DEBUG, "EAPOLController: %s: no current boot uuid found", __func__);
	return;
    }

    options = copy_preboot_volume_options();
    prefs = SCPreferencesCreateWithOptions(NULL, kPrefsName, kEAPOLControllerAutoDetectPrefsID, NULL, options);
    if (prefs == NULL) {
	EAPLOG(LOG_ERR, "EAPOLController: %s: SCPreferencesCreateWithOptions() failed for [%@]",
	       __func__, kEAPOLControllerAutoDetectPrefsID);
	goto done;
    }

    interfaces = SCPreferencesGetValue(prefs, kEAPOLControllerAutoDetectInterfaces);
    if (isA_CFDictionary(interfaces) != NULL) {
	if (CFDictionaryContainsKey(interfaces, interface)) {
	    EAPLOG(LOG_DEBUG, "EAPOLController: %s: auto-detect status already has interface info for [%@]",
		   __func__, interface);
	    goto done;
	}
	new_interfaces = CFDictionaryCreateMutableCopy(NULL, 0, interfaces);
    } else {
	new_interfaces = CFDictionaryCreateMutable(NULL, 1, &kCFTypeDictionaryKeyCallBacks,
						   &kCFTypeDictionaryValueCallBacks);
    }

    {
	CFStringRef 	keys[2];
	CFTypeRef 	vals[2];

	keys[0] = kEAPOLControllerAutoDetectAuthenticatorMAC;
	vals[0] = authenticator_mac;
	keys[1] = kEAPOLControllerAutoDetectIdentifier;
	vals[1] = identifier;
	new_interface_info = CFDictionaryCreate(NULL,
					(const void **)keys,
					(const void **)vals,
					2,
					&kCFTypeDictionaryKeyCallBacks,
					&kCFTypeDictionaryValueCallBacks);
	CFDictionaryAddValue(new_interfaces, interface, new_interface_info);
    }

    prefs_boot_uuid = SCPreferencesGetValue(prefs, kEAPOLControllerAutoDetectBootUUID);
    if (isA_CFString(prefs_boot_uuid) == NULL) {
	SCPreferencesSetValue(prefs, kEAPOLControllerAutoDetectBootUUID, current_boot_uuid);
    }

    if (new_interfaces != NULL) {
	SCPreferencesSetValue(prefs, kEAPOLControllerAutoDetectInterfaces, new_interfaces);
	SCPreferencesCommitChanges(prefs);
	EAPLOG(LOG_NOTICE, "EAPOLController: %s: added [%@] in auto-detect status with info %@",
	       __func__, interface, new_interface_info);
    }

done:
    my_CFRelease(&new_interfaces);
    my_CFRelease(&new_interface_info);
    my_CFRelease(&options);
    my_CFRelease(&prefs);
}

static CFDictionaryRef
copy_interfaces_from_auto_detect_status(void)
{
    SCPreferencesRef	prefs = NULL;
    CFDictionaryRef	options = NULL;
    CFDictionaryRef 	interfaces = NULL;
    CFDictionaryRef 	ret_interfaces = NULL;
    CFStringRef 	prefs_boot_uuid = NULL;
    CFStringRef 	current_boot_uuid = get_boot_uuid();

    if (current_boot_uuid == NULL) {
	EAPLOG(LOG_DEBUG, "EAPOLController: %s: no current boot uuid found", __func__);
	return NULL;
    }

    options = copy_preboot_volume_options();
    prefs = SCPreferencesCreateWithOptions(NULL, kPrefsName, kEAPOLControllerAutoDetectPrefsID, NULL, options);
    if (prefs == NULL) {
	EAPLOG(LOG_ERR, "EAPOLController: %s: SCPreferencesCreateWithOptions() failed for [%@]",
	       __func__, kEAPOLControllerAutoDetectPrefsID);
	goto done;
    }

    prefs_boot_uuid = SCPreferencesGetValue(prefs, kEAPOLControllerAutoDetectBootUUID);
    if (isA_CFString(prefs_boot_uuid) == NULL) {
	EAPLOG(LOG_DEBUG, "EAPOLController: %s: no BootUUID found", __func__);
	goto done;
    }

    if (CFStringCompare(prefs_boot_uuid, current_boot_uuid, kCFCompareCaseInsensitive) != kCFCompareEqualTo) {
	/* actual boot uuid and and one stored in the prefs are not same
	 * which means the information in the prefs is stale.
	 */
	EAPLOG(LOG_DEBUG, "EAPOLController: %s: boot uuids don't match", __func__);
	goto done;
    }

    interfaces = SCPreferencesGetValue(prefs, kEAPOLControllerAutoDetectInterfaces);
    if (isA_CFDictionary(interfaces) == NULL) {
	EAPLOG(LOG_DEBUG, "EAPOLController: %s: no interfaces found", __func__);
	goto done;
    }

    ret_interfaces = CFDictionaryCreateCopy(NULL, interfaces);

done:
    my_CFRelease(&options);
    my_CFRelease(&prefs);
    return ret_interfaces;
}

static void
cleanup_auto_detect_status(void)
{
    SCPreferencesRef	prefs = NULL;
    CFDictionaryRef	options = NULL;

    options = copy_preboot_volume_options();
    prefs = SCPreferencesCreateWithOptions(NULL, kPrefsName, kEAPOLControllerAutoDetectPrefsID, NULL, options);
    if (prefs == NULL) {
	EAPLOG(LOG_ERR, "EAPOLController: %s: SCPreferencesCreateWithOptions() failed for [%@]",
	       __func__, kEAPOLControllerAutoDetectPrefsID);
	goto done;
    }
    SCPreferencesRemoveValue(prefs, kEAPOLControllerAutoDetectBootUUID);
    SCPreferencesRemoveValue(prefs, kEAPOLControllerAutoDetectInterfaces);
    SCPreferencesCommitChanges(prefs);

done:
    my_CFRelease(&options);
    my_CFRelease(&prefs);
}

static bool
handle_preboot_auto_detected_interface(CFDictionaryRef auto_detected_interfaces, eapolClientRef client)
{
    bool 		ret = false;
    CFDictionaryRef 	interface_info = NULL;
    CFDataRef 		auth_mac = NULL;
    CFNumberRef 	pkt_id = NULL;

    if (client->preboot_auto_detection_handled) {
	/* supplicant was started for this interface once before */
	goto done;
    }
    client->preboot_auto_detection_handled = TRUE;
    if (CFDictionaryContainsKey(auto_detected_interfaces, client->if_name_cf) == FALSE) {
	goto done;
    }
    interface_info = CFDictionaryGetValue(auto_detected_interfaces, client->if_name_cf);
    if (isA_CFDictionary(interface_info) == NULL) {
	goto done;
    }
    auth_mac = CFDictionaryGetValue(interface_info, kEAPOLControllerAutoDetectAuthenticatorMAC);
    pkt_id = CFDictionaryGetValue(interface_info, kEAPOLControllerAutoDetectIdentifier);
    if (isA_CFData(auth_mac) != NULL && isA_CFNumber(pkt_id) != NULL &&
	CFDataGetLength(auth_mac) == sizeof(client->authenticator_mac)) {
	int id_val;

	CFNumberGetValue(pkt_id, kCFNumberIntType, &id_val);
	CFDataGetBytes(auth_mac, CFRangeMake(0, sizeof(client->authenticator_mac)),
		       (UInt8 *)&client->authenticator_mac);
	client->packet_identifier = id_val;
	if (client->autodetect_can_start_system_mode == TRUE) {
	    start_eapolclient_with_system_ethernet_configuration(client);
	}
	ret = true;
    }

done:
    return ret;
}

#endif /* TARGET_OS_OSX */

/**
 ** 802.1X socket monitoring routines
 **/

#include "EAPOLUtil.h"

#define ALIGNED_BUF(name, size, type)	type 	name[(size) / (sizeof(type))]

static boolean_t
S_if_get_link_active(const char * if_name)
{
    boolean_t	link_active = TRUE;
    int		s;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
	EAPLOG(LOG_NOTICE, "EAPOLController: get link status, socket failed %s",
	       strerror(errno));
    }
    else {
	struct ifmediareq	ifmr;

	memset(&ifmr, 0, sizeof(ifmr));
	strlcpy(ifmr.ifm_name, if_name, sizeof(ifmr.ifm_name));
	if (ioctl(s, SIOCGIFMEDIA, (caddr_t)&ifmr) != -1
	    && ifmr.ifm_count > 0
	    && (ifmr.ifm_status & IFM_AVALID) != 0
	    && (ifmr.ifm_status & IFM_ACTIVE) == 0) {
	    link_active = FALSE;
	}
	close(s);
    }
    return (link_active);
}

static void
handle_config_changed(boolean_t start_system_mode);

static int
eapolClientStart(eapolClientRef client, uid_t uid, gid_t gid,
		 CFDictionaryRef config_dict, mach_port_t bootstrap,
		 mach_port_t au_session);

#define RECV_SIZE	1600

static CFDictionaryRef
copy_system_ethernet_configuration(void)
{
    EAPOLClientConfigurationRef eap_client_cfg = EAPOLClientConfigurationCreate(NULL);
    CFDictionaryRef		profile_config = NULL;
    EAPOLClientProfileRef	profile = NULL;

    if (eap_client_cfg == NULL) {
	return NULL;
    }
    profile = EAPOLClientConfigurationGetSystemEthernetProfile(eap_client_cfg);
    if (profile == NULL) {
	goto done;
    }
    profile_config = S_profile_copy_itemID_dict(profile);
done:
    my_CFRelease(&eap_client_cfg);
    return profile_config;
}

static void
start_eapolclient_with_system_ethernet_configuration(eapolClientRef client)
{
    CFDictionaryRef system_eth_config = copy_system_ethernet_configuration();
    if (system_eth_config != NULL && client->state == kEAPOLControlStateIdle) {
	EAPLOG(LOG_DEBUG, "starting 802.1X authentication with system ethernet profile");
	int status = eapolClientStart(client, 0, 0, system_eth_config, MACH_PORT_NULL, MACH_PORT_NULL);
	if (status != 0) {
	    EAPLOG(LOG_ERR, " eapolClientStart (%s) failed %d", client->if_name, status);
	} else {
	    client->using_global_system_profile = TRUE;
	}
    }
    my_CFRelease(&system_eth_config);
}

static void
monitoring_callback(CFSocketRef s, CFSocketCallBackType type,
		    CFDataRef address, const void * data, void * info)
{
    ALIGNED_BUF(buf, RECV_SIZE, uint32_t);
    eapolClientRef		client = (eapolClientRef)info;
    struct ether_header *	eh_p = (struct ether_header *)buf;
    EAPOLPacketRef		eapol_p;
    int 			n;
    EAPRequestPacketRef 	req_p;

    n = (int)recv(client->eapol_fd, buf, sizeof(buf), 0);
    if (n < sizeof(*eh_p)) {
	if (n < 0) {
	    EAPLOG(LOG_NOTICE, "EAPOLController: monitor %s recv failed %s",
		   client->if_name,
		   strerror(errno));
	}
	return;
    }
    eapol_p = (EAPOLPacketRef)(eh_p + 1);
    if (EAPOLPacketValid(eapol_p, n - sizeof(*eh_p), NULL) == FALSE) {
	/* bad packet */
	return;
    }
    req_p = (EAPRequestPacketRef)eapol_p->body;
    if (eapol_p->packet_type != kEAPOLPacketTypeEAPPacket
	|| req_p->code != kEAPCodeRequest
	|| req_p->type != kEAPTypeIdentity) {
	/* only EAP Request Identity packets can trigger */
	return;
    }

    bcopy(eh_p->ether_shost, &client->authenticator_mac,
	  sizeof(client->authenticator_mac));
    client->packet_identifier = req_p->identifier;
    EAPLOG(LOG_INFO, "EAPOLController: %s requires 802.1X", client->if_name);
#if ! TARGET_OS_IPHONE
    if (S_store != NULL) {
	SCDynamicStoreNotifyValue(S_store,
				  kEAPOLControlAutoDetectInformationNotifyKey);
    }
    if (is_fvunlock_current_boot_mode()) {
	CFDataRef authenticator_mac = CFDataCreate(NULL, (const UInt8 *)&client->authenticator_mac,
						   sizeof(client->authenticator_mac));
	CFNumberRef identifier = CFNumberCreate(NULL, kCFNumberIntType, &client->packet_identifier);
	if (authenticator_mac != NULL && identifier != NULL) {
	    EAPLOG(LOG_NOTICE, "EAPOLController: adding [%@] to auto-detect status",
		   client->if_name_cf);
	    add_interface_to_auto_detect_status(client->if_name_cf, authenticator_mac, identifier);
	}
	my_CFRelease(&authenticator_mac);
	my_CFRelease(&identifier);
    }
#endif /* ! TARGET_OS_IPHONE */
    /* check if we can start system mode */
    if (client->autodetect_can_start_system_mode == TRUE) {
	start_eapolclient_with_system_ethernet_configuration(client);
    }
    return;
}

static void
eapolClientStopMonitoring(eapolClientRef client)
{
    if (client->eapol_fd == -1) {
	return;
    }
    if (client->eapol_sock != NULL) {
	/* remove one socket reference, close the file descriptor */
	CFSocketInvalidate(client->eapol_sock);

	/* release the socket */
	my_CFRelease(&client->eapol_sock);
    }
    else {
	close(client->eapol_fd);
    }
    client->eapol_fd = -1;
    EAPLOG(LOG_INFO, "EAPOLController: no longer monitoring %s",
	   client->if_name);
    return;
}

static void
eapolClientStartMonitoring(eapolClientRef client)
{
    CFSocketContext	context = { 0, NULL, NULL, NULL, NULL };
    CFRunLoopSourceRef	rls;

    if (client->eapol_fd != -1) {
	EAPLOG(LOG_INFO, "EAPOLController: already monitoring %s",
	       client->if_name);
	return;
    }
    EAPLOG(LOG_INFO,
	   "EAPOLController: starting monitoring on %s", client->if_name);
    client->eapol_fd = eapol_socket(client->if_name, FALSE);
    if (client->eapol_fd < 0) {
	EAPLOG(LOG_NOTICE,
	       "EAPOLController: failed to open EAPOL socket over %s",
	       client->if_name);
	return;
    }

    /* arrange to be called back when socket has data */
    context.info = client;
    client->eapol_sock
	= CFSocketCreateWithNative(NULL, client->eapol_fd,
				   kCFSocketReadCallBack,
				   monitoring_callback, &context);
    if (client->eapol_sock == NULL) {
	EAPLOG(LOG_NOTICE,
	       "EAPOLController: failed create CFSocket over %s",
	       client->if_name);
	goto failed;
    }
    rls = CFSocketCreateRunLoopSource(NULL, client->eapol_sock, 0);
    if (rls == NULL) {
	EAPLOG(LOG_NOTICE,
	       "EAPOLController: failed create CFRunLoopSource for %s",
	       client->if_name);
	goto failed;
    }
    CFRunLoopAddSource(CFRunLoopGetCurrent(), rls, kCFRunLoopDefaultMode);
    CFRelease(rls);
    return;

 failed:
    eapolClientStopMonitoring(client);
    return;
}

static void
eapolClientExited(eapolClientRef client, EAPOLControlMode mode)
{
    boolean_t		start_system_mode = FALSE;
#if ! TARGET_OS_IPHONE
    CFStringRef		user;
    
    if (S_store == NULL) {
	return;
    }
    user = SCDynamicStoreCopyConsoleUser(S_store, NULL, NULL);
    if (user == NULL) {
	if (mode != kEAPOLControlModeSystem) {
	    start_system_mode = TRUE;
	}
    }
    else {
	CFRelease(user);
    }
#endif /* ! TARGET_OS_IPHONE */
    handle_config_changed(start_system_mode);
    return;
}

/**
 ** fork/exec eapolclient routines
 **/
static void 
exec_callback(pid_t pid, int status, struct rusage * rusage, void * context)
{
    eapolClientRef	client;
    EAPOLControlMode	mode;

    client = eapolClientLookupProcess(pid);
    if (client == NULL) {
	return;
    }
    if (client->state != kEAPOLControlStateIdle) {
	EAPLOG(LOG_NOTICE, 
	       "EAPOLController: eapolclient(%s) pid=%d exited with status %d",
	       client->if_name,  pid, status);
    }
    mode = client->mode;
    eapolClientInvalidate(client);
    eapolClientExited(client, mode);
    return;
}

typedef struct {
    int			eapol_fd;
    eapolClientRef	client;
} exec_context_t;

static void
exec_setup(pid_t pid, void * context)
{
    int			fd;
    int 		i;
    exec_context_t *	ec_p = (exec_context_t *)context;

    if (pid != 0) {
	/* parent: clean up file descriptors */
	if (ec_p->client->eapol_fd == ec_p->eapol_fd) {
	    eapolClientStopMonitoring(ec_p->client);
	}
	else {
	    close(ec_p->eapol_fd);
	}
	return;
    }

    /* child: close all fds except the ones we inherit from parent */
    for (i = (getdtablesize() - 1); i >= 0; i--) {
	if (i != ec_p->eapol_fd) {
	    close(i);
	}
    }

    /* re-direct stdin to the inherited eapol_fd */
    if (ec_p->eapol_fd != STDIN_FILENO) {
	dup(ec_p->eapol_fd);			/* stdin */
	close(ec_p->eapol_fd);
    }

    /* re-direct stdout/stderr to /dev/null */
    fd = open(_PATH_DEVNULL, O_RDWR, 0);	/* stdout */
    dup(fd);					/* stderr */
    return;
}

static int
open_eapol_socket(eapolClientRef client)
{
    if (client->eapol_fd != -1) {
	return (client->eapol_fd);
    }
    return (eapol_socket(client->if_name,
			 (get_ifm_type(client->if_name) 
			  == IFM_IEEE80211)));
}

static int
eapolClientStart(eapolClientRef client, uid_t uid, gid_t gid,
		 CFDictionaryRef config_dict, mach_port_t bootstrap,
		 mach_port_t au_session)
{
    char * 			argv[] = { S_eapolclient_path, 	/* 0 */
					   "-i",	       	/* 1 */
					   client->if_name,	/* 2 */
					   NULL,		/* 3 */
					   NULL,		/* 4 */
					   NULL,		/* 5 */
					   NULL,		/* 6 */
					   NULL };
    exec_context_t		ec;
    char			gid_str[32];
    int				status = 0;
    char			uid_str[32];

#if ! TARGET_OS_IPHONE
    client->user_cancelled = FALSE;
#endif /* ! TARGET_OS_IPHONE */

    bzero(&ec, sizeof(ec));
    ec.client = client;
    ec.eapol_fd = open_eapol_socket(client);
    if (ec.eapol_fd < 0) {
	EAPLOG(LOG_NOTICE,
	       "EAPOLController: failed to open EAPOL socket over %s",
	       client->if_name);
	return (errno);
    }
    if (bootstrap != MACH_PORT_NULL) {
	snprintf(uid_str, sizeof(uid_str), "%u", uid);
	snprintf(gid_str, sizeof(gid_str), "%u", gid);
	argv[3] = "-u";
	argv[4] = uid_str;
	argv[5] = "-g";
	argv[6] = gid_str;
    }
    client->pid = _SCDPluginExecCommand2(exec_callback, NULL, 0, 0,
					 S_eapolclient_path, argv,
					 exec_setup, &ec);
    if (client->pid == -1) {
	/* failure, clean-up too */
	exec_setup(-1, &ec);
	status = errno;
    }
    else {
	boolean_t			on_console = FALSE;

	if (bootstrap != MACH_PORT_NULL) {
	    on_console = is_console_user(uid);
	    client->owner.uid = uid;
	    client->owner.gid = gid;
	    client->console_user = on_console;
#if TARGET_OS_IPHONE
	    client->mode = kEAPOLControlModeUser;
	    client->bootstrap = bootstrap;
#else /* TARGET_OS_IPHONE */
	    if (on_console == FALSE
		&& uid == login_window_uid()) {
		client->mode = kEAPOLControlModeLoginWindow;
	    }
	    else {
		client->mode = kEAPOLControlModeUser;
		client->bootstrap = bootstrap;
		client->au_session = au_session;
	    }
#endif /* TARGET_OS_IPHONE */
	}
	else {
	    client->mode = kEAPOLControlModeSystem;
	}
	if (config_dict != NULL) {
	    client->config_dict = CFRetain(config_dict);
	}
	eapolClientSetState(client, kEAPOLControlStateStarting);
    }
    return (status);
}

static int
eapolClientUpdate(eapolClientRef client, CFDictionaryRef config_dict)
{
    int			status = 0;

    switch (client->state) {
    case kEAPOLControlStateStarting:
    case kEAPOLControlStateRunning:
	break;
    case kEAPOLControlStateIdle:
	status = ENOENT;
	goto done;
    default:
	status = EBUSY;
	goto done;
    }

    if (client->state == kEAPOLControlStateRunning) {
	/* tell the client to re-read */
	eapolClientNotify(client);
    }
    my_CFRelease(&client->config_dict);
    my_CFRelease(&client->user_input_dict);
    client->config_dict = CFRetain(config_dict);
    client->retry = FALSE;
    client->user_input_provided = FALSE;

 done:
    return (status);
}

static int
eapolClientProvideUserInput(eapolClientRef client, CFDictionaryRef user_input)
{
    int			status = 0;

    switch (client->state) {
    case kEAPOLControlStateRunning:
	break;
    case kEAPOLControlStateStarting:
	status = EINVAL;
	goto done;
    case kEAPOLControlStateIdle:
	status = ENOENT;
	goto done;
    default:
	status = EBUSY;
	goto done;
    }

    /* tell the client to re-read */
    eapolClientNotify(client);
    my_CFRelease(&client->user_input_dict);
    if (user_input != NULL) {
	client->user_input_dict = CFRetain(user_input);
    }
    client->retry = FALSE;
    client->user_input_provided = TRUE;

 done:
    return (status);
}

int 
ControllerGetState(if_name_t if_name, int * state)
{
    eapolClientRef 	client;
    int			status = 0;

    *state = kEAPOLControlStateIdle;
    client = eapolClientLookupInterface(if_name);
    if (client == NULL) {
	status = ENOENT;
    }
    else {
	*state = client->state;
    }
    return (status);
}

int 
ControllerCopyStateAndStatus(if_name_t if_name, 
			     int * state,
			     CFDictionaryRef * status_dict)
{
    eapolClientRef 	client;
    int			status = 0;

    *state = kEAPOLControlStateIdle;
    *status_dict = NULL;
    client = eapolClientLookupInterface(if_name);
    if (client == NULL) {
	status = ENOENT;
    }
    else {
	if (client->status_dict != NULL) {
	    *status_dict = CFRetain(client->status_dict);
	}
	*state = client->state;
    }
    return (status);
}

int
ControllerStart(if_name_t if_name, uid_t uid, gid_t gid,
		CFDictionaryRef config_dict, mach_port_t bootstrap,
		mach_port_t au_session)
{
    eapolClientRef 	client;
    int			status = 0;

    client = eapolClientLookupInterface(if_name);
    if (client != NULL) {
	if (client->state != kEAPOLControlStateIdle) {
	    if (client->state == kEAPOLControlStateRunning) {
		status = EEXIST;
	    }
	    else {
		status = EBUSY;
	    }
	    goto done;
	}
    }
    else {
	int	ifm_type;

	/* make sure that the interface is one that we support */
	ifm_type = get_ifm_type(if_name);
	switch (ifm_type) {
	case IFM_ETHER:
	case IFM_IEEE80211:
	    break;
	default:
	    status = ENXIO;
	    goto done;
	}
	client = eapolClientAdd(if_name, (ifm_type == IFM_IEEE80211));
	if (client == NULL) {
	    status = ENOMEM;
	    goto done;
	}
    }
#if TARGET_OS_IPHONE
    /* automatically map all requests by root to the mobile user */
    if (uid == 0) {
	static gid_t	mobile_gid = -1;
	static uid_t	mobile_uid = -1;

	if (mobile_uid == -1) {
	    struct passwd *	pwd;

	    /* lookup the mobile user */
	    pwd = getpwnam("mobile");
	    if (pwd != NULL) {
		mobile_uid = pwd->pw_uid;
		mobile_gid = pwd->pw_gid;
	    }
	    else {
		EAPLOG(LOG_NOTICE,
		       "EAPOLController: getpwnam(mobile) failed");
	    }
	}
	if (mobile_uid != -1) {
	    uid = mobile_uid;
	    if (mobile_gid != -1) {
		gid = mobile_gid;
	    }
	}
    }
#endif /* TARGET_OS_IPHONE */
    status = eapolClientStart(client, uid, gid, config_dict, bootstrap,
			      au_session);
 done:
    if (status != 0) {
	if (bootstrap != MACH_PORT_NULL) {
	    (void)mach_port_deallocate(mach_task_self(), bootstrap);
	}
	if (au_session != MACH_PORT_NULL) {
	    (void)mach_port_deallocate(mach_task_self(), au_session);
	}
    }
    return (status);
}

static int
eapolClientStop(eapolClientRef client)
{
    int			status = 0;

    switch (client->state) {
    case kEAPOLControlStateRunning:
    case kEAPOLControlStateStarting:
	break;
    case kEAPOLControlStateIdle:
	status = ENOENT;
	goto done;
    default:
	status = EBUSY;
	goto done;
    }
    eapolClientSetState(client, kEAPOLControlStateStopping);
    my_CFRelease(&client->config_dict);

    /* send a message to stop it */
    eapolClientNotify(client);
    /* should set a timeout so that if it doesn't detach, we kill it XXX */
#if 0
    if (client->pid != -1 && client->pid != 0) {
	kill(client->pid, SIGTERM);
    }
#endif /* 0 */

 done:
    return (status);

}

#if ! TARGET_OS_IPHONE

static boolean_t
S_get_plist_boolean(CFDictionaryRef plist, CFStringRef key, boolean_t def)
{
    CFBooleanRef 	b;
    boolean_t		ret = def;

    b = isA_CFBoolean(CFDictionaryGetValue(plist, key));
    if (b != NULL) {
	ret = CFBooleanGetValue(b);
    }
    return (ret);
}

#endif /* ! TARGET_OS_IPHONE */

int
ControllerStop(if_name_t if_name, uid_t uid, gid_t gid)
{
    eapolClientRef 	client;
    int			status = 0;

    client = eapolClientLookupInterface(if_name);
    if (client == NULL) {
	status = ENOENT;
	goto done;
    }
#if TARGET_OS_IPHONE
    if (uid != 0 && uid != client->owner.uid) {
	status = EPERM;
	goto done;
    }
#else /* TARGET_OS_IPHONE */
    if (uid != 0) {
	if (uid != client->owner.uid) {
	    if (client->mode == kEAPOLControlModeSystem
		&& (client->config_dict == NULL
		    || S_get_plist_boolean(client->config_dict,
					   CFSTR("AllowStop"), TRUE))
		&& (uid == login_window_uid() || is_console_user(uid))) {
		/* allow the change */
		if (is_console_user(uid)) {
		    /* console user stopped us, don't automatically start system mode */
		    client->autodetect_can_start_system_mode = FALSE;
		}
	    }
	    else {
		status = EPERM;
		goto done;
	    }
	}
	else if (client->mode == kEAPOLControlModeLoginWindow
		 && uid == login_window_uid()) {
	    /* LoginWindow mode is being turned off, clear the config */
	    clear_loginwindow_config(client);
	} 
    }

#endif /* TARGET_OS_IPHONE */
    status = eapolClientStop(client);
 done:
    return (status);
}


int
ControllerUpdate(if_name_t if_name, uid_t uid, gid_t gid,
		 CFDictionaryRef config_dict)
{
    eapolClientRef 	client;
    int			status = 0;

    client = eapolClientLookupInterface(if_name);
    if (client == NULL) {
	status = ENOENT;
	goto done;
    }
    if (uid != 0 && uid != client->owner.uid) {
	status = EPERM;
	goto done;
    }
    status = eapolClientUpdate(client, config_dict);
 done:
    return (status);
}

int
ControllerProvideUserInput(if_name_t if_name, uid_t uid, gid_t gid,
			   CFDictionaryRef user_input)
{
    eapolClientRef 	client;
    int			status = 0;

    client = eapolClientLookupInterface(if_name);
    if (client == NULL) {
	status = ENOENT;
	goto done;
    }
    if (uid != 0 && uid != client->owner.uid) {
	status = EPERM;
	goto done;
    }
    status = eapolClientProvideUserInput(client, user_input);
 done:
    return (status);
}

int
ControllerRetry(if_name_t if_name, uid_t uid, gid_t gid)
{
    eapolClientRef 	client;
    int			status = 0;

    client = eapolClientLookupInterface(if_name);
    if (client == NULL) {
	status = ENOENT;
	goto done;
    }
    if (uid != 0 && uid != client->owner.uid) {
	status = EPERM;
	goto done;
    }
    switch (client->state) {
    case kEAPOLControlStateStarting:
	goto done;
    case kEAPOLControlStateRunning:
	break;
    case kEAPOLControlStateIdle:
	status = ENOENT;
	goto done;
    default:
	status = EBUSY;
	goto done;
    }
    /* tell the client to re-read */
    eapolClientNotify(client);
    client->retry = TRUE;

 done:
    return (status);

}

static CFDictionaryRef
system_eapol_copy(const char * if_name)
{
    CFDictionaryRef		dict = NULL;
    EAPOLClientConfigurationRef	cfg;

    cfg = EAPOLClientConfigurationCreate(NULL);
    if (cfg != NULL) {
	EAPOLClientProfileRef	profile = NULL;
#if ! TARGET_OS_IPHONE
	CFStringRef if_name_cf = CFStringCreateWithCString(NULL, if_name,
							   kCFStringEncodingASCII);
	profile = EAPOLClientConfigurationGetSystemProfile(cfg, if_name_cf);
	CFRelease(if_name_cf);
#else /* ! TARGET_OS_IPHONE */
	profile = EAPOLClientConfigurationGetSystemEthernetProfile(cfg);
#endif /* ! TARGET_OS_IPHONE */
	if (profile != NULL) {
	    /* new, profileID-based configuration */
	    dict = S_profile_copy_itemID_dict(profile);
	}
	CFRelease(cfg);
    }
    return (dict);
}

int
ControllerStartSystem(if_name_t if_name, uid_t uid, gid_t gid,
		      CFDictionaryRef options)
{
    eapolClientRef 	client;
    CFDictionaryRef	dict = NULL;
    int			ifm_type;
    CFDictionaryRef	itemID_dict = NULL;
    int			status = 0;

    /* make sure the interface is a type we support */
    ifm_type = get_ifm_type(if_name);
    switch (ifm_type) {
    case IFM_ETHER:
    case IFM_IEEE80211:
	break;
    default:
	status = ENXIO;
	goto done;
    }

    /* make sure that 802.1X isn't already running on the interface */
    client = eapolClientLookupInterface(if_name);
    if (client != NULL && client->state != kEAPOLControlStateIdle) {
	if (client->state == kEAPOLControlStateRunning) {
	    status = EEXIST;
	}
	else {
	    status = EBUSY;
	}
	goto done;
    }

#if ! TARGET_OS_IPHONE
    /* verify that non-root caller is either loginwindow or a logged-in user */
    if (uid != 0
	&& uid != login_window_uid() 
	&& is_console_user(uid) == FALSE) {
	status = EPERM;
	goto done;
    }
#endif /* ! TARGET_OS_IPHONE */

    /* check whether the caller provided which profile to use */
    if (options != NULL) {
	itemID_dict
	    = CFDictionaryGetValue(options, kEAPOLControlClientItemID);
	if (isA_CFDictionary(itemID_dict) != NULL) {
	    CFMutableDictionaryRef	new_dict;

	    new_dict = CFDictionaryCreateMutableCopy(NULL, 0, options);
	    CFDictionarySetValue(new_dict, kSystemModeManagedExternally,
				 kCFBooleanTrue);
	    dict = new_dict;
	}
    }

    /* check whether system mode is configured in the preferences */
    if (dict == NULL) {
	dict = system_eapol_copy(if_name);
	if (dict == NULL) {
	    status = ESRCH;
	    goto done;
	}
    }

    /* if there's no client entry yet, create it */
    if (client == NULL) {
	client = eapolClientAdd(if_name, (ifm_type == IFM_IEEE80211));
	if (client == NULL) {
	    status = ENOMEM;
	    goto done;
	}
    }
#if ! TARGET_OS_IPHONE
    /* start system mode over the specific interface */
    client->using_global_system_profile = FALSE;
#endif
    status = eapolClientStart(client, 0, 0, dict, MACH_PORT_NULL,
			      MACH_PORT_NULL);

 done:
    my_CFRelease(&dict);
    return (status);
}

#if ! TARGET_OS_IPHONE

int 
ControllerCopyLoginWindowConfiguration(if_name_t if_name, 
				       CFDictionaryRef * config_data_p)
{
    eapolClientRef 	client;
    int			status = 0;

    *config_data_p = NULL;
    client = eapolClientLookupInterface(if_name);
    if (client == NULL
	|| client->loginwindow_config == NULL) {
	status = ENOENT;
    }
    else {
	*config_data_p = CFRetain(client->loginwindow_config);
    }
    return (status);
}

int
ControllerCopyAutoDetectInformation(CFDictionaryRef * info_p)
{
    CFMutableDictionaryRef	all_dict = NULL;
    eapolClientRef		scan;
    int				status = 0;

    LIST_FOREACH(scan, S_clientHead_p, link) {
	CFDataRef		data;
	CFMutableDictionaryRef	this_dict = NULL;

	if (scan->state != kEAPOLControlStateIdle
	    || scan->eapol_fd == -1
	    || scan->packet_identifier == BAD_IDENTIFIER) {
	    continue;
	}
	this_dict = CFDictionaryCreateMutable(NULL, 0,
					      &kCFTypeDictionaryKeyCallBacks,
					      &kCFTypeDictionaryValueCallBacks);
	data = CFDataCreate(NULL, (const UInt8 *)&scan->authenticator_mac,
			    sizeof(scan->authenticator_mac));
	CFDictionarySetValue(this_dict, kEAPOLAutoDetectAuthenticatorMACAddress,
			     data);
	CFRelease(data);
	if (all_dict == NULL) {
	    all_dict = CFDictionaryCreateMutable(NULL, 0,
					     &kCFTypeDictionaryKeyCallBacks,
					     &kCFTypeDictionaryValueCallBacks);
	}
	CFDictionarySetValue(all_dict, scan->if_name_cf, this_dict);
	CFRelease(this_dict);
    }
    if (all_dict != NULL && CFDictionaryGetCount(all_dict) == 0) {
	status = ENOENT;
	my_CFRelease(&all_dict);
    }
    *info_p = all_dict;
    return (status);
}

boolean_t
ControllerDidUserCancel(if_name_t if_name)
{
    boolean_t		cancelled = FALSE;
    eapolClientRef 	client;

    client = eapolClientLookupInterface(if_name);
    if (client == NULL) {
	cancelled = FALSE;
    }
    else {
	cancelled = client->user_cancelled;
    }
    return (cancelled);
}

#endif /* ! TARGET_OS_IPHONE */

void
ControllerClientGetSession(pid_t pid, if_name_t if_name,
			 mach_port_t * bootstrap,
			 mach_port_t * au_session)
{
    eapolClientRef client;
    
    *bootstrap = MACH_PORT_NULL;
    *au_session = MACH_PORT_NULL;
    client = eapolClientLookupInterface(if_name);
    if (client == NULL) {
	goto failed;
    }
    if (pid != client->pid) {
	goto failed;
    }
    if (client->session_cfport != NULL) {
	goto failed;
    }
    if (client->ports_provided == FALSE) {
	*bootstrap = client->bootstrap;
	*au_session = client->au_session;
	client->ports_provided = TRUE;
    }

 failed:
    return;
}

int
ControllerClientAttach(pid_t pid, if_name_t if_name,
		       mach_port_t notify_port,
		       mach_port_t * session_port,
		       CFDictionaryRef * control_dict)
{
    CFMutableDictionaryRef	dict;
    CFNumberRef			command_cf;
    eapolClientRef		client;
    int				result = 0;
    CFRunLoopSourceRef		rls;

    *session_port = MACH_PORT_NULL;
    *control_dict = NULL;
    client = eapolClientLookupInterface(if_name);
    if (client == NULL) {
	result = ENOENT;
	goto failed;
    }
    if (pid != client->pid) {
	result = EPERM;
	goto failed;
    }
    if (client->session_cfport != NULL) {
	result = EEXIST;
	goto failed;
    }
    client->session_cfport
	= my_CFMachPortCreate(client, server_handle_request, NULL);
    if (client->session_cfport == NULL) {
	result = ENOMEM;
	goto failed;
    }
    client->notify_port = notify_port;
    *session_port = CFMachPortGetPort(client->session_cfport);
    rls = CFMachPortCreateRunLoopSource(NULL, client->session_cfport, 0);
    CFRunLoopAddSource(CFRunLoopGetCurrent(), rls, kCFRunLoopDefaultMode);
    CFRelease(rls);
    dict = CFDictionaryCreateMutable(NULL, 0,
				     &kCFTypeDictionaryKeyCallBacks,
				     &kCFTypeDictionaryValueCallBacks);
    if (client->state == kEAPOLControlStateStarting) {
	CFNumberRef			mode_cf;

	command_cf = make_number(kEAPOLClientControlCommandRun);
	if (client->config_dict != NULL) {
	    CFDictionarySetValue(dict, kEAPOLClientControlConfiguration,
				 client->config_dict);
	}
	mode_cf = make_number(client->mode);
	CFDictionarySetValue(dict, kEAPOLClientControlMode,
			     mode_cf);
	CFRelease(mode_cf);
#if ! TARGET_OS_IPHONE
	/* provide the identifier from the EAP Request Identity packet */
	if (client->packet_identifier != BAD_IDENTIFIER) {
	    CFNumberRef			packet_id;
	    
	    packet_id = make_number(client->packet_identifier);
	    CFDictionarySetValue(dict, kEAPOLClientControlPacketIdentifier,
				 packet_id);
	    CFRelease(packet_id);
	}
#endif /* ! TARGET_OS_IPHONE */
    }
    else {
	command_cf = make_number(kEAPOLClientControlCommandStop);
    }
    CFDictionarySetValue(dict, kEAPOLClientControlCommand, command_cf);
    CFRelease(command_cf);
    *control_dict = dict;
    eapolClientSetState(client, kEAPOLControlStateRunning);
#if ! TARGET_OS_IPHONE
    if (client->mode == kEAPOLControlModeLoginWindow) {
	set_loginwindow_config(client);
    }
#endif /* ! TARGET_OS_IPHONE */
    return (result);
 failed:
    (void)mach_port_deallocate(mach_task_self(), notify_port);
    return (result);
}

int
ControllerClientDetach(mach_port_t session_port)
{
    eapolClientRef	client;
    EAPOLControlMode	mode;
    int			result = 0;

    client = eapolClientLookupSession(session_port);
    if (client == NULL) {
	result = EINVAL;
	goto failed;
    }
    mode = client->mode;
    eapolClientInvalidate(client);
    eapolClientExited(client, mode);

 failed:
    return (result);
}

int
ControllerClientGetConfig(mach_port_t session_port,
			  CFDictionaryRef * control_dict)
{
    eapolClientRef		client;
    CFNumberRef			command_cf = NULL;
    CFMutableDictionaryRef	dict = NULL;
    int				result = 0;

    *control_dict = NULL;
    client = eapolClientLookupSession(session_port);
    if (client == NULL) {
	result = EINVAL;
	goto failed;
    }
    dict = CFDictionaryCreateMutable(NULL, 0,
				     &kCFTypeDictionaryKeyCallBacks,
				     &kCFTypeDictionaryValueCallBacks);
    if (client->state == kEAPOLControlStateRunning) {
	if (client->retry) {
	    command_cf = make_number(kEAPOLClientControlCommandRetry);
	    client->retry = FALSE;
	}
	else if (client->user_input_provided) {
	    command_cf
		= make_number(kEAPOLClientControlCommandTakeUserInput);
	    if (client->user_input_dict != NULL) {
		CFDictionarySetValue(dict, 
				     kEAPOLClientControlUserInput,
				     client->user_input_dict);
	    }
	    client->user_input_provided = FALSE;
	    my_CFRelease(&client->user_input_dict);
	}
	else {
	    command_cf = make_number(kEAPOLClientControlCommandRun);
	    if (client->config_dict != NULL) {
		CFDictionarySetValue(dict, kEAPOLClientControlConfiguration,
				     client->config_dict);
	    }
	}
    }
    else {
	command_cf = make_number(kEAPOLClientControlCommandStop);
    }
    CFDictionarySetValue(dict, kEAPOLClientControlCommand, command_cf);
    *control_dict = dict;
    client->notification_sent = FALSE;
    my_CFRelease(&command_cf);
 failed:
    return (result);
}

int
ControllerClientReportStatus(mach_port_t session_port,
			     CFDictionaryRef status_dict)
{
    eapolClientRef	client;
    int			result = 0;

    client = eapolClientLookupSession(session_port);
    if (client == NULL) {
	result = EINVAL;
	goto failed;
    }
    eapolClientPublishStatus(client, status_dict);
 failed:
    return (result);
}

int
ControllerClientForceRenew(mach_port_t session_port)
{
    eapolClientRef	client;
    int			result = 0;

    client = eapolClientLookupSession(session_port);
    if (client == NULL) {
	result = EINVAL;
	goto failed;
    }
    (void)eapolClientForceRenew(client);
 failed:
    return (result);
}

#if ! TARGET_OS_IPHONE
int
ControllerClientUserCancelled(mach_port_t session_port)
{
    eapolClientRef	client;
    int			result = 0;

    client = eapolClientLookupSession(session_port);
    if (client == NULL) {
	result = EINVAL;
	goto failed;
    }
    client->user_cancelled = TRUE;
    result = eapolClientStop(client);

 failed:
    return (result);
}
#endif /* ! TARGET_OS_IPHONE */

#include <net/ndrv.h>

#ifdef SEND_EAPOL_START
/*
 * Don't send an EAPOL Start packet on link up to avoid issues
 * authenticating with Cisco SG-300 (rdar://problem/20579502).
 */

static const struct ether_addr eapol_multicast = {
    EAPOL_802_1_X_GROUP_ADDRESS
};

static void
eapolClientTransmitStart(eapolClientRef client)
{
#define SEND_BUFSIZE	256
    ALIGNED_BUF(buf, SEND_BUFSIZE, uint32_t);
    EAPOLPacket *		eapol_p;
    struct ether_header *	eh_p;
    struct sockaddr_ndrv 	ndrv;
    unsigned int		size;

    size = sizeof(*eh_p) + sizeof(*eapol_p);
    bzero(buf, size);
    eh_p = (struct ether_header *)buf;
    eapol_p = (void *)(eh_p + 1);

    /* ethernet uses the multicast address */
    bcopy(&eapol_multicast, &eh_p->ether_dhost, sizeof(eh_p->ether_dhost));
    eh_p->ether_type = htons(EAPOL_802_1_X_ETHERTYPE);
    eapol_p->protocol_version = EAPOL_802_1_X_PROTOCOL_VERSION;
    eapol_p->packet_type = kEAPOLPacketTypeStart;

    /* the contents of ndrv are ignored */
    bzero(&ndrv, sizeof(ndrv));
    ndrv.snd_len = sizeof(ndrv);
    ndrv.snd_family = AF_NDRV;

    EAPLOG(LOG_DEBUG, "EAPOLController: %s Transmit EAPOL Start",
	   client->if_name);
    if (sendto(client->eapol_fd, eh_p, size,
	       0, (struct sockaddr *)&ndrv, sizeof(ndrv)) < size) {
	EAPLOG(LOG_NOTICE, "eapolClientTransmitStart: %s sendto failed, %s",
	       client->if_name, strerror(errno));
    }
    return;
}

#endif /* SEND_EAPOL_START */

static void
handle_link_changed(CFStringRef if_name)
{
    eapolClientRef	client;
    boolean_t		link_active;

    client = eapolClientLookupInterfaceCF(if_name);
    if (client == NULL) {
	return;
    }
    if (client->eapol_fd == -1) {
	/* we don't care about this interface */
	return;
    }
    link_active = S_if_get_link_active(client->if_name);
    EAPLOG(LOG_INFO, "EAPOLController: %s link %sactive",
	   client->if_name,
	   link_active ? "" : "in");
    if (link_active == FALSE) {
	client->packet_identifier = BAD_IDENTIFIER;
    } else {
	if (!client->is_wifi) {
	    /* enable the global system mode as the ethernet link is active */
	    client->autodetect_can_start_system_mode = TRUE;
	}
#ifdef SEND_EAPOL_START
	eapolClientTransmitStart(client);
#endif /* SEND_EAPOL_START */
    }
    return;
}

static CFStringRef
mySCNetworkInterfacePathCopyInterfaceName(CFStringRef path)
{
    CFArrayRef          arr;
    CFStringRef         ifname = NULL;

    arr = CFStringCreateArrayBySeparatingStrings(NULL, path, CFSTR("/"));
    if (arr == NULL) {
	goto done;
    }
    /* "domain:/Network/Interface/<ifname>[/<entity>]" =>
     * {"domain:","Network","Interface","<ifname>"[,"<entity>"]}
     */
    if (CFArrayGetCount(arr) < 4) {
	goto done;
    }
    ifname = CFRetain(CFArrayGetValueAtIndex(arr, 3));
 done:
    if (arr != NULL) {
	CFRelease(arr);
    }
    return (ifname);
}

typedef struct {
    EAPOLClientConfigurationRef cfg;
    CFMutableArrayRef		configured_ethernet;
    CFRange			configured_ethernet_range;
    CFMutableArrayRef		configured_wifi;
    CFRange			configured_wifi_range;
    CFMutableDictionaryRef	system_mode_configurations;
    CFMutableArrayRef		system_mode_iflist;
} EAPOLInterfaceInfo, * EAPOLInterfaceInfoRef;

static void
EAPOLInterfaceInfoProcess(const void * key, const void * value, void * context)
{
    EAPOLInterfaceInfoRef	info_p = (EAPOLInterfaceInfoRef)context;

    if (isA_CFDictionary(value) == NULL) {
	return;
    }
    if (CFStringHasSuffix(key, kSCEntNetEAPOL)) {
	CFStringRef		name;
	EAPOLClientProfileRef	profile = NULL;

	name = mySCNetworkInterfacePathCopyInterfaceName(key);
	if (info_p->cfg == NULL) {
	    info_p->cfg = EAPOLClientConfigurationCreate(NULL);
	}
#if ! TARGET_OS_IPHONE
	if (info_p->cfg != NULL) {
	    profile
		= EAPOLClientConfigurationGetSystemProfile(info_p->cfg, name);
	}
#endif /* ! TARGET_OS_IPHONE */
	if (profile != NULL) {
	    CFDictionaryRef		this_config = NULL;

	    this_config = S_profile_copy_itemID_dict(profile);
	    if (this_config != NULL) {
		CFDictionarySetValue(info_p->system_mode_configurations,
				     name, this_config);
		CFRelease(this_config);
		CFArrayAppendValue(info_p->system_mode_iflist, name);
	    }
	}
	my_CFRelease(&name);
    }
    else {
	int			ifm_type = 0;
	char			ifname[IFNAMSIZ];
	CFStringRef		name;
	CFStringRef		type;

	type = CFDictionaryGetValue(value, kSCPropNetInterfaceType);
	if (type == NULL
	    || CFEqual(type, kSCValNetInterfaceTypeEthernet) == FALSE) {
	    return;
	}
	name = CFDictionaryGetValue(value, kSCPropNetInterfaceDeviceName);
	if (isA_CFString(name) == NULL) {
	    return;
	}
	if (CFStringGetCString(name, ifname, sizeof(ifname),
			       kCFStringEncodingASCII) == FALSE) {
	    return;
	}
	ifm_type = get_ifm_type(ifname);
	switch (ifm_type) {
	case IFM_ETHER:
	    if (CFArrayContainsValue(info_p->configured_ethernet,
				     info_p->configured_ethernet_range, name)) {
		return;
	    }
	    CFArrayAppendValue(info_p->configured_ethernet, name);
	    info_p->configured_ethernet_range.length++;
	    break;
	case IFM_IEEE80211:
	    if (CFArrayContainsValue(info_p->configured_wifi,
				     info_p->configured_wifi_range, name)) {
		return;
	    }
	    CFArrayAppendValue(info_p->configured_wifi, name);
	    info_p->configured_wifi_range.length++;
	    break;
	default:
	    break;
	}
    }
    return;
}

static void
EAPOLInterfaceInfoInit(EAPOLInterfaceInfoRef info_p, boolean_t system_mode)
{
    int					count;
    int					i;
    CFStringRef				list[2];
    CFArrayRef				patterns;
    CFDictionaryRef			store_info = NULL;

    bzero(info_p, sizeof(*info_p));
    count = 0;
    list[count++]
	= SCDynamicStoreKeyCreateNetworkServiceEntity(NULL,
						      kSCDynamicStoreDomainSetup,
						      kSCCompAnyRegex,
						      kSCEntNetInterface);
    if (system_mode) {
	list[count++] = SCDynamicStoreKeyCreateNetworkInterfaceEntity(NULL,
								      kSCDynamicStoreDomainSetup,
								      kSCCompAnyRegex,
								      kSCEntNetEAPOL);
    }
    patterns = CFArrayCreate(NULL, (const void * *)list, count,
			     &kCFTypeArrayCallBacks);
    for (i = 0; i < count; i++) {
	CFRelease(list[i]);
    }
    store_info = SCDynamicStoreCopyMultiple(S_store, NULL, patterns);
    my_CFRelease(&patterns);
    if (store_info == NULL) {
	return;
    }

    /* build list of configured services and System mode configurations */
    info_p->configured_ethernet
	= CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    info_p->configured_wifi
	= CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    if (system_mode) {
	info_p->system_mode_configurations
	    = CFDictionaryCreateMutable(NULL, 0,
					&kCFTypeDictionaryKeyCallBacks,
					&kCFTypeDictionaryValueCallBacks);
	info_p->system_mode_iflist
	    = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    }
    CFDictionaryApplyFunction(store_info, EAPOLInterfaceInfoProcess,
			      (void *)info_p);
    CFRelease(store_info);
    return;
}

static void
EAPOLInterfaceInfoFree(EAPOLInterfaceInfoRef info_p)
{
    my_CFRelease(&info_p->cfg);
    my_CFRelease(&info_p->configured_ethernet);
    my_CFRelease(&info_p->configured_wifi);
    my_CFRelease(&info_p->system_mode_configurations);
    my_CFRelease(&info_p->system_mode_iflist);
    return;
}


#if TARGET_OS_IPHONE

/*
 * SIM removal notification
 */
static Boolean
accept_types_valid_aka_or_sim(CFArrayRef accept)
{
	CFIndex			count;
	CFNumberRef		type;
	int				eap_num;

	if (isA_CFArray(accept) == NULL) {
		return (FALSE);
	}
	count = CFArrayGetCount(accept);
	if (count == 0) {
		return (FALSE);
	}
	type = CFArrayGetValueAtIndex(accept, 0);
	if (isA_CFNumber(type) == NULL) {
		return (FALSE);
	}
	/* check if kEAPTypeEAPSIM or kEAPTypeEAPAKA */
	if (CFNumberGetValue(type, kCFNumberIntType, &eap_num) == TRUE) {
		if (eap_num == kEAPTypeEAPSIM || eap_num == kEAPTypeEAPAKA) {
			return TRUE;
		}
	}
	return FALSE;
}

static void
sim_status_handle_change(CFStringRef status)
{
    eapolClientRef	client;

    EAPLOG(LOG_DEBUG, "SIM status %@", status);
    if (CFEqual(status, kCTSIMSupportSIMStatusNotInserted) == FALSE) {
	return;
    }
    EAPLOG(LOG_INFO, "Handle SIM card eject");
    LIST_FOREACH(client, S_clientHead_p, link) {
	if (client->state == kEAPOLControlStateStarting ||
	    client->state == kEAPOLControlStateRunning) {
	    CFDictionaryRef cli_config = NULL;

	    cli_config = CFDictionaryGetValue(client->config_dict,
					      kEAPOLControlEAPClientConfiguration);
	    if (isA_CFDictionary(cli_config) != NULL) {
		CFArrayRef accept_types = NULL;
                                                
		accept_types = CFDictionaryGetValue(cli_config,
						    kEAPClientPropAcceptEAPTypes);
		if (accept_types_valid_aka_or_sim(accept_types) == TRUE) {
		    /* stop the eapolclient */
		    EAPLOG_FL(LOG_NOTICE, "stopping eapolclient.");
		    eapolClientStop(client);
		}
	    }
	}
   }

   /* increment the geration ID in SC prefs so eapclient would know
    * that SIM was removed and not to use the stored info.
    */
    EAPOLSIMGenerationIncrement();
}

static CFRunLoopRef	eapolRunLoop;

static void
sim_status_changed(CFTypeRef connection, CFStringRef status, void * info)
{
    if (status == NULL) {
	return;
    }
    CFRetain(status);
    CFRunLoopPerformBlock(eapolRunLoop, kCFRunLoopDefaultMode,
			  ^{ sim_status_handle_change(status);
			      CFRelease(status); });
    CFRunLoopWakeUp(eapolRunLoop);
}

static void
register_sim_status_change(void)
{
    CFTypeRef connection;

    eapolRunLoop = CFRunLoopGetCurrent();
    connection = _SIMAccessConnectionCreate(sim_status_changed, NULL);
    if (connection == NULL) {
	EAPLOG(LOG_NOTICE,
	       "_SIMAccessConnectionCreate() failed");
    }
    return;
}

static void
eapol_handle_change(SCDynamicStoreRef store, CFArrayRef changes, void * arg)
{
    boolean_t 		iflist_changed = FALSE;
    CFIndex 		count = 0;
    CFMutableArrayRef	link_changes = NULL;

    count = CFArrayGetCount(changes);
    for (CFIndex i = 0; i < count; i++) {
	CFStringRef cache_key = CFArrayGetValueAtIndex(changes, i);

	if (CFStringHasSuffix(cache_key, kSCCompInterface)) {
	    /* list of interfaces changed */
	    iflist_changed = TRUE;
	} else if (CFStringHasSuffix(cache_key, kSCEntNetLink)) {
	    CFStringRef	cf_if_name = NULL;

	    cf_if_name = my_CFStringCopyComponent(cache_key, CFSTR("/"), 3);
	    if (cf_if_name != NULL) {
		char ifname[IFNAMSIZ];
		if (CFStringGetCString(cf_if_name, ifname, sizeof(ifname),
				       kCFStringEncodingASCII) == FALSE) {
		    CFRelease(cf_if_name);
		    continue;
		}
		if (link_changes == NULL) {
		    link_changes = CFArrayCreateMutable(NULL,
							count,
							&kCFTypeArrayCallBacks);
		}
		/* make sure this is Ethernet */
		if (get_ifm_type(ifname) == IFM_ETHER) {
		    CFArrayAppendValue(link_changes, cf_if_name);
		}
		CFRelease(cf_if_name);
	    }
	}
    }
    if (iflist_changed) {
	handle_config_changed(FALSE);
    }
    if (link_changes != NULL) {
	count = CFArrayGetCount(link_changes);
	for (CFIndex i = 0; i < count; i++) {
	    CFStringRef if_name = CFArrayGetValueAtIndex(link_changes, i);
	    handle_link_changed(if_name);
	}
	CFRelease(link_changes);
    }
    return;
}

static SCDynamicStoreRef
dynamic_store_create(void)
{
    SCDynamicStoreRef		store;
    CFStringRef			list[2];
    CFArrayRef			keys = NULL;
    CFArrayRef			patterns = NULL;

    store = SCDynamicStoreCreate(NULL, CFSTR("EAPOLController"), eapol_handle_change, NULL);
    if (store == NULL) {
	EAPLOG(LOG_NOTICE, "EAPOLController: SCDynamicStoreCreate() failed, %s",
	       SCErrorString(SCError()));
    }
    list[0] = SCDynamicStoreKeyCreateNetworkInterface(NULL, kSCDynamicStoreDomainState);
    keys = CFArrayCreate(NULL, (const void * *)list, 1, &kCFTypeArrayCallBacks);
    CFRelease(list[0]);
    /* configured services */
    list[0]
	= SCDynamicStoreKeyCreateNetworkServiceEntity(NULL,
						      kSCDynamicStoreDomainSetup,
						      kSCCompAnyRegex,
						      kSCEntNetInterface);
    list[1]
	= SCDynamicStoreKeyCreateNetworkInterfaceEntity(NULL,
							kSCDynamicStoreDomainState,
							kSCCompAnyRegex,
							kSCEntNetLink);
    patterns = CFArrayCreate(NULL, (const void * *)list, 2, &kCFTypeArrayCallBacks);
    CFRelease(list[0]);
    CFRelease(list[1]);
    SCDynamicStoreSetNotificationKeys(store, keys, patterns);
    CFRelease(keys);
    CFRelease(patterns);
    return (store);
}

static void
handle_user_switch(void)
{
    eapolClientRef	scan;

    EAPLOG(LOG_NOTICE, "%s", __func__);
    LIST_FOREACH(scan, S_clientHead_p, link) {
	EAPLOG(LOG_NOTICE, "Stopping %s", scan->if_name);
	(void)eapolClientStop(scan);
    }
    return;
}

static void
notify_user_switch(int t, CFRunLoopRef rl)
{
    CFRunLoopPerformBlock(rl, kCFRunLoopDefaultMode,
			  ^{ handle_user_switch(); });
    CFRunLoopWakeUp(rl);
    return;
}

/* replace this once it is defined in a header file */
#define kUserWillChangeNotification				\
    "com.apple.mobile.usermanagerd.foregrounduser_willchange"

static void
register_user_switch(void)
{
    notify_handler_t	handler;
    int			status;
    int			token;
    CFRunLoopRef	rl;

    if (!os_feature_enabled(UserManagement, SystemSessionD1)) {
	return;
    }
    EAPLOG(LOG_INFO, "Registering user-switch handler");
    rl = CFRunLoopGetCurrent();
    handler = ^(int t) { notify_user_switch(t, rl); };
    status = notify_register_dispatch(kUserWillChangeNotification,
				      &token,
				      dispatch_get_main_queue(),
				      handler);
    if (status != NOTIFY_STATUS_OK) {
	EAPLOG(LOG_NOTICE, "notify_register_dispatch(%s) failed %d",
	       kUserWillChangeNotification, status);
    }
    return;
}

#else /* TARGET_OS_IPHONE */

static void
console_user_changed()
{
    eapolClientRef	scan;
    uid_t		uid = 0;
    CFStringRef		user;

    user = SCDynamicStoreCopyConsoleUser(S_store, &uid, NULL);
    LIST_FOREACH(scan, S_clientHead_p, link) {
	if (scan->console_user) {
	    if (user == NULL || scan->owner.uid != uid) {
		/* user logged out or fast-user switch */
		(void)eapolClientStop(scan);
		clear_loginwindow_config(scan);
		if (user == NULL && !scan->is_wifi) {
		    /* enable the global system mode in absence of console user */
		    scan->autodetect_can_start_system_mode = TRUE;
		}
	    }
	}
	else if (user == NULL) {
	    clear_loginwindow_config(scan);
	    if (!scan->is_wifi) {
		/* enable the global system mode in absence of console user */
		scan->autodetect_can_start_system_mode = TRUE;
	    }
	}
    }
    my_CFRelease(&user);
    return;
}

static CFArrayRef
copy_interface_list(void)
{
    CFDictionaryRef	dict;
    CFArrayRef		iflist = NULL;
    CFStringRef		key;

    key = SCDynamicStoreKeyCreateNetworkInterface(NULL,
						  kSCDynamicStoreDomainState);
    dict = SCDynamicStoreCopyValue(S_store, key);
    my_CFRelease(&key);

    if (isA_CFDictionary(dict) != NULL) {
	iflist = CFDictionaryGetValue(dict, kSCPropNetInterfaces);
	iflist = isA_CFArray(iflist);
    }
    if (iflist != NULL) {
	CFRetain(iflist);
    }
    else {
	iflist = CFArrayCreate(NULL, NULL, 0, &kCFTypeArrayCallBacks);
    }

    my_CFRelease(&dict);
    return (iflist);
}

static void
update_system_mode_interfaces(CFDictionaryRef system_mode_configurations,
			      CFArrayRef system_mode_iflist)
{
    CFArrayRef				current_iflist = NULL;
    int					i;
    CFRange				range;
    eapolClientRef			scan;
    int					status;

    /* get the current list of interfaces */
    current_iflist = copy_interface_list();
    range = CFRangeMake(0, CFArrayGetCount(current_iflist));

    /* change existing interface configurations */
    LIST_FOREACH(scan, S_clientHead_p, link) {
	CFDictionaryRef		this_config = NULL;

	if (CFArrayContainsValue(current_iflist,
				 range,
				 scan->if_name_cf) == FALSE) {
	    /* interface doesn't exist, stop it */
	    if (scan->state == kEAPOLControlStateIdle) {
		eapolClientStopMonitoring(scan);
	    }
	    else {
		(void)eapolClientStop(scan);
	    }
	    continue;
	}
	this_config
	    = CFDictionaryGetValue(system_mode_configurations,
				   scan->if_name_cf);
	if (scan->mode == kEAPOLControlModeSystem) {
	    /* interface is in System mode */
	    if (scan->config_dict == NULL) {
		/* we must be stopping, ignore it */
		continue;
	    }
	    if (CFDictionaryContainsKey(scan->config_dict,
					kSystemModeManagedExternally)) {
		/* this instance is managed externally, skip it */
		continue;
	    }
	    if (this_config == NULL) {
		if (scan->using_global_system_profile == FALSE) {
		    /* interface is no longer in System mode */
		    status = eapolClientStop(scan);
		    if (status != 0) {
			EAPLOG(LOG_NOTICE, "EAPOLController handle_config_changed:"
			       " eapolClientStop (%s) failed %d",
			       scan->if_name, status);
		    }
		}
	    }
	    else {
		if (CFEqual(this_config, scan->config_dict) == FALSE) {
		    status = eapolClientUpdate(scan, this_config);
		    if (status != 0) {
			EAPLOG(LOG_NOTICE, 
			       "EAPOLController handle_config_changed: "
			       "eapolClientUpdate (%s) failed %d",
			       scan->if_name, status);
		    } else {
			scan->using_global_system_profile = FALSE;
		    }
		}
	    }
	}
	else if (this_config != NULL) {
	    if (scan->state == kEAPOLControlStateIdle) {
		status = eapolClientStart(scan, 0, 0, 
					  this_config, MACH_PORT_NULL,
					  MACH_PORT_NULL);
		if (status != 0) {
		    EAPLOG(LOG_NOTICE, 
			   "EAPOLController handle_config_changed:"
			   " eapolClientStart (%s) failed %d",
			   scan->if_name, status);
		}
	    }
	}
    }

    /* start any that are missing */
    range = CFRangeMake(0, CFArrayGetCount(system_mode_iflist));
    for (i = 0; i < range.length; i++) {
	eapolClientRef		client;
	CFStringRef		if_name_cf;

	if_name_cf = CFArrayGetValueAtIndex(system_mode_iflist, i);
	client = eapolClientLookupInterfaceCF(if_name_cf);
	if (client == NULL) {
	    char *	if_name;

	    if_name = my_CFStringToCString(if_name_cf, kCFStringEncodingASCII);
	    client = eapolClientAdd(if_name, FALSE);
	    if (client == NULL) {
		EAPLOG(LOG_NOTICE, 
		       "EAPOLController handle_config_changed:"
		       " eapolClientAdd (%s) failed", if_name);
	    }
	    else {
		CFDictionaryRef		this_config;

		this_config
		    = CFDictionaryGetValue(system_mode_configurations,
					   if_name_cf);
		status = eapolClientStart(client, 0, 0,
					  this_config, MACH_PORT_NULL,
					  MACH_PORT_NULL);
		if (status != 0) {
		    EAPLOG(LOG_NOTICE, 
			   "EAPOLController handle_config_changed:"
			   " eapolClientStart (%s) failed %d",
			   client->if_name, status);
		} else {
		    client->using_global_system_profile = FALSE;
		}
	    }
	    free(if_name);
	}
    }
    my_CFRelease(&current_iflist);
    return;
}

static void
update_wifi_interfaces(CFArrayRef configured_wifi)
{
    CFRange			range;
    eapolClientRef		scan;

    /* stop client on interfaces that are no longer configured */
    range = CFRangeMake(0, CFArrayGetCount(configured_wifi));
    LIST_FOREACH(scan, S_clientHead_p, link) {
	if (!scan->is_wifi) {
	    /* not a Wi-Fi interface */
	    continue;
	}
	if (scan->state != kEAPOLControlStateIdle
	    && CFArrayContainsValue(configured_wifi,
				    range,
				    scan->if_name_cf) == FALSE) {
	    EAPLOG(LOG_NOTICE,
		   "EAPOLController: %s is no longer configured, stopping",
		   scan->if_name);
	    (void)eapolClientStop(scan);
	}
    }
    return;
}

static void
eapol_handle_change(SCDynamicStoreRef store, CFArrayRef changes, void * arg)
{
    boolean_t		config_changed = FALSE;
    CFStringRef		console_user_key;
    CFIndex		count;
    CFIndex		i;
    boolean_t		iflist_changed = FALSE;
    CFMutableArrayRef	link_changes = NULL;
    boolean_t		user_changed = FALSE;

    console_user_key = SCDynamicStoreKeyCreateConsoleUser(NULL);
    count = CFArrayGetCount(changes);
    if (count == 0) {
	goto done;
    }
    for (i = 0; i < count; i++) {
	CFStringRef	cache_key = CFArrayGetValueAtIndex(changes, i);

	if (CFEqual(cache_key, console_user_key)) {
	    user_changed = TRUE;
	}
	else if (CFStringHasPrefix(cache_key, kSCDynamicStoreDomainSetup)) {
	    config_changed = TRUE;
	}
	else if (CFStringHasSuffix(cache_key, kSCCompInterface)) {
	    /* list of interfaces changed */
	    iflist_changed = TRUE;
	}
	else if (CFStringHasSuffix(cache_key, kSCEntNetLink)) {
	    /* link status changed */
	    CFStringRef		if_name;

	    if_name = my_CFStringCopyComponent(cache_key, CFSTR("/"), 3);
	    if (if_name != NULL) {
		if (link_changes == NULL) {
		    link_changes
			= CFArrayCreateMutable(NULL,
					       count,
					       &kCFTypeArrayCallBacks);
		}
		CFArrayAppendValue(link_changes, if_name);
		CFRelease(if_name);
	    }
	}
    }

    if (iflist_changed || config_changed) {
	handle_config_changed(TRUE);
    }
    if (user_changed) {
	console_user_changed();
    }
    if (link_changes != NULL) {
	count = CFArrayGetCount(link_changes);
	for (i = 0; i < count; i++) {
	    CFStringRef		if_name;

	    if_name = CFArrayGetValueAtIndex(link_changes, i);
	    handle_link_changed(if_name);
	}
	CFRelease(link_changes);
    }

 done:
    my_CFRelease(&console_user_key);
    return;
}

static SCDynamicStoreRef
dynamic_store_create(void)
{
    CFArrayRef			keys = NULL;
    CFStringRef			list[3];
    CFArrayRef			patterns = NULL;
    SCDynamicStoreRef		store;

    store = SCDynamicStoreCreate(NULL, CFSTR("EAPOLController"), 
				 eapol_handle_change, NULL);
    if (store == NULL) {
	EAPLOG(LOG_NOTICE, "EAPOLController: SCDynamicStoreCreate() failed, %s",
	       SCErrorString(SCError()));
	return (NULL);
    }

    /* console user */
    list[0]
	= SCDynamicStoreKeyCreateConsoleUser(NULL);

    /* list of interfaces */
    list[1] 
	= SCDynamicStoreKeyCreateNetworkInterface(NULL,
						  kSCDynamicStoreDomainState);
    keys = CFArrayCreate(NULL, (const void * *)list, 2, &kCFTypeArrayCallBacks);
    CFRelease(list[0]);
    CFRelease(list[1]);
    
    /* requested EAPOL configurations */
    list[0] 
	= SCDynamicStoreKeyCreateNetworkInterfaceEntity(NULL,
							kSCDynamicStoreDomainSetup,
							kSCCompAnyRegex,
							kSCEntNetEAPOL);
    /* configured services */
    list[1]
	= SCDynamicStoreKeyCreateNetworkServiceEntity(NULL, 
						      kSCDynamicStoreDomainSetup,
						      kSCCompAnyRegex,
						      kSCEntNetInterface);
    list[2]
	= SCDynamicStoreKeyCreateNetworkInterfaceEntity(NULL, 
							kSCDynamicStoreDomainState,
							kSCCompAnyRegex,
							kSCEntNetLink);
    patterns = CFArrayCreate(NULL, (const void * *)list, 3,
			     &kCFTypeArrayCallBacks);
    CFRelease(list[0]);
    CFRelease(list[1]);
    CFRelease(list[2]);

    SCDynamicStoreSetNotificationKeys(store, keys, patterns);
    CFRelease(keys);
    CFRelease(patterns);
    return (store);
}

#endif /* TARGET_OS_IPHONE */

static void
update_ethernet_interfaces(CFArrayRef configured_ethernet)
{
    int				i;
    CFRange			range;
    eapolClientRef		scan;
#if TARGET_OS_OSX
    CFDictionaryRef 		auto_detected_interfaces = NULL;
    bool 			fv_unlock_mode = is_fvunlock_current_boot_mode();
    bool 			is_auto_detected = false;
#endif /* TARGET_OS_OSX */

    /*
     * stop monitoring/authenticating on any interfaces that are no longer
     * configured
     */
    range = CFRangeMake(0, CFArrayGetCount(configured_ethernet));
    LIST_FOREACH(scan, S_clientHead_p, link) {
	if (scan->is_wifi) {
	    /* don't handle Wi-Fi interfaces */
	    continue;
	}
	if (CFArrayContainsValue(configured_ethernet,
				 range,
				 scan->if_name_cf) == FALSE) {
	    if (scan->state == kEAPOLControlStateIdle) {
		EAPLOG(LOG_NOTICE,
		       "EAPOLController: %s is no longer configured, stopping to monitor",
		       scan->if_name);
		eapolClientStopMonitoring(scan);
	    }
	    else {
		EAPLOG(LOG_NOTICE,
		       "EAPOLController: %s is no longer configured, stopping",
		       scan->if_name);
		(void)eapolClientStop(scan);
	    }
	}
    }

#if TARGET_OS_OSX
    if (fv_unlock_mode == false) {
	auto_detected_interfaces = copy_interfaces_from_auto_detect_status();
	if (isA_CFDictionary(auto_detected_interfaces) != NULL &&
	    CFDictionaryGetCount(auto_detected_interfaces) > 0) {
	    is_auto_detected = true;
	    EAPLOG(LOG_DEBUG,
		   "EAPOLController: auto detected interfaces: %@",
		   auto_detected_interfaces);
	} else {
	    EAPLOG(LOG_DEBUG,
		   "EAPOLController: no auto detected interfaces found");
	}
    }
#endif /* TARGET_OS_OSX */

    /* start monitoring any interfaces that are configured */
    for (i = 0; i < range.length; i++) {
	eapolClientRef		client;
	CFStringRef		if_name_cf;

	if_name_cf
	    = (CFStringRef)CFArrayGetValueAtIndex(configured_ethernet, i);
	client = eapolClientLookupInterfaceCF(if_name_cf);
	if (client == NULL
	    || (client->state == kEAPOLControlStateIdle
		&& client->eapol_fd == -1)) {
	    char *	if_name;

	    if_name = my_CFStringToCString(if_name_cf, kCFStringEncodingASCII);
	    if (client == NULL) {
		client = eapolClientAdd(if_name, FALSE);
		if (client == NULL) {
		    EAPLOG(LOG_NOTICE,
			   "EAPOLController: monitor "
			   "eapolClientAdd (%s) failed", if_name);
		}
	    }
	    if (client != NULL) {
#if TARGET_OS_OSX
		if (is_auto_detected == false ||
		    handle_preboot_auto_detected_interface(auto_detected_interfaces, client) == false)
#endif /* TARGET_OS_OSX */
		eapolClientStartMonitoring(client);
	    }
	    free(if_name);
	}
    }
#if TARGET_OS_OSX
    my_CFRelease(&auto_detected_interfaces);
#endif /* TARGET_OS_OSX */
    return;
}

static void
handle_config_changed(boolean_t start_system_mode)
{
    EAPOLInterfaceInfo			info;

    if (S_store == NULL) {
	return;
    }

    /* get a snapshot of the configuration information */
    EAPOLInterfaceInfoInit(&info, start_system_mode);

    update_ethernet_interfaces(info.configured_ethernet);

#if ! TARGET_OS_IPHONE
    if (start_system_mode) {
	update_system_mode_interfaces(info.system_mode_configurations,
				      info.system_mode_iflist);
    }
    update_wifi_interfaces(info.configured_wifi);
#endif /* ! TARGET_OS_IPHONE */

    EAPOLInterfaceInfoFree(&info);
    return;
}

static void
dynamic_store_schedule(SCDynamicStoreRef store)
{
    CFRunLoopSourceRef		rls;

    rls = SCDynamicStoreCreateRunLoopSource(NULL, store, 0);
    CFRunLoopAddSource(CFRunLoopGetCurrent(), rls, kCFRunLoopDefaultMode);
    my_CFRelease(&rls);
    return;
}

static CFStringRef S_global_system_profile_id = NULL;
static SCPreferencesRef S_eap_prefs = NULL;

STATIC void
handle_system_ethernet_config_change(Boolean uninstalled)
{
    if (uninstalled == TRUE) {
	eapolClientRef	scan;
	/* should stop the eapolclient */
	LIST_FOREACH(scan, S_clientHead_p, link) {
	    if (scan->mode == kEAPOLControlModeSystem &&
		scan->using_global_system_profile == TRUE) {
		scan->using_global_system_profile = FALSE;
		(void)eapolClientStop(scan);
	    }
	}
    } else {
	eapolClientRef			scan;
	EAPOLClientConfigurationRef	eapol_client_cfg = NULL;
	EAPOLClientProfileRef		profile = NULL;
	CFDictionaryRef			config = NULL;

	eapol_client_cfg = EAPOLClientConfigurationCreate(NULL);
	if (eapol_client_cfg == NULL) {
	    return;
	}
	profile = EAPOLClientConfigurationGetSystemEthernetProfile(eapol_client_cfg);
	if (profile == NULL) {
	    return;
	}
	config = S_profile_copy_itemID_dict(profile);
	if (config == NULL) {
	    return;
	}
	LIST_FOREACH(scan, S_clientHead_p, link) {
	    if (scan->state == kEAPOLControlStateIdle
		&& scan->eapol_fd != -1
		&& scan->packet_identifier != BAD_IDENTIFIER) {
		int status = eapolClientStart(scan, 0, 0, config, MACH_PORT_NULL, MACH_PORT_NULL);
		if (status != 0) {
		    EAPLOG(LOG_NOTICE, " eapolClientStart (%s) failed %d", scan->if_name, status);
		} else {
		    scan->using_global_system_profile = TRUE;
		}
	    }
	}
	my_CFRelease(&eapol_client_cfg);
	my_CFRelease(&config);
    }
    return;
}

STATIC void
system_ethernet_prefs_changed(SCPreferencesRef prefs, SCPreferencesNotification type,
			      void * info)
{
    EAPOLClientConfigurationRef	    cfg = NULL;
    EAPOLClientProfileRef	    profile = NULL;

    cfg = EAPOLClientConfigurationCreate(NULL);
    if (cfg == NULL) {
	return;
    }
    profile = EAPOLClientConfigurationGetSystemEthernetProfile(cfg);
    if (profile == NULL) {
	if (S_global_system_profile_id != NULL) {
	    my_CFRelease(&S_global_system_profile_id);
	    EAPLOG(LOG_DEBUG, "system ethernet profile was uninstalled.");
	    handle_system_ethernet_config_change(TRUE);
	}
	goto done;
    }
    CFStringRef profile_id = EAPOLClientProfileGetID(profile);
    if (S_global_system_profile_id == NULL || my_CFEqual(profile_id, S_global_system_profile_id) == FALSE) {
	/* global system ethernet profile changed */
	EAPLOG(LOG_DEBUG, "global system ethernet profile %s", S_global_system_profile_id != NULL ? "changed" : "first time installed");
	my_CFRelease(&S_global_system_profile_id);
	S_global_system_profile_id = CFStringCreateCopy(NULL, profile_id);
	handle_system_ethernet_config_change(FALSE);
    }
done:
    my_CFRelease(&cfg);
    return;
}

static void
register_system_ethernet_prefs_change(void)
{
    EAPOLClientConfigurationRef	cfg = NULL;

    cfg = EAPOLClientConfigurationCreate(NULL);
    if (cfg != NULL) {
	EAPOLClientProfileRef profile = EAPOLClientConfigurationGetSystemEthernetProfile(cfg);
	if (profile != NULL) {
	    CFStringRef profile_id = EAPOLClientProfileGetID(profile);
	    if (profile_id != NULL){
		S_global_system_profile_id = CFStringCreateCopy(NULL, profile_id);
	    }
	}
	my_CFRelease(&cfg);
    }
#define kEAPOLClientConfigurationPrefsID    CFSTR("com.apple.network.eapolclient.configuration.plist")
    S_eap_prefs = SCPreferencesCreate(NULL, kPrefsName, kEAPOLClientConfigurationPrefsID);
    SCPreferencesSetCallback(S_eap_prefs, system_ethernet_prefs_changed, NULL);
    SCPreferencesScheduleWithRunLoop(S_eap_prefs, CFRunLoopGetCurrent(), kCFRunLoopCommonModes);
}

static void *
ControllerThread(void * arg)
{
    boolean_t start_system_mode = TRUE;
    EAPLOG(LOG_NOTICE, "%s", __func__);
    dynamic_store_schedule(S_store);
#if TARGET_OS_IPHONE
    start_system_mode = FALSE;
    register_sim_status_change();
    register_user_switch();
    EAPWiFiMonitorPowerStatus();
#endif /* TARGET_OS_IPHONE */
#if TARGET_OS_OSX
    if (is_fvunlock_current_boot_mode()) {
	cleanup_auto_detect_status();
    }
#endif /* TARGET_OS_OSX */
    handle_config_changed(start_system_mode);
    register_system_ethernet_prefs_change();
    server_start();
    CFRunLoopRun();
    return (arg);
}

static void
ControllerBegin(void)
{
    pthread_attr_t	attr;
    int			ret;
    pthread_t		thread;

    ret = pthread_attr_init(&attr);
    if (ret != 0) {
	EAPLOG(LOG_NOTICE, "EAPOLController: pthread_attr_init failed %d", ret);
	return;
    }
    ret = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (ret != 0) {
	EAPLOG(LOG_NOTICE, 
	       "EAPOLController: pthread_attr_setdetachstate failed %d", ret);
	goto done;
    }
    ret = pthread_create(&thread, &attr, ControllerThread, NULL);
    if (ret != 0) {
	EAPLOG(LOG_NOTICE, "EAPOLController: pthread_create failed %d", ret);
	goto done;
    }
    
 done:
    (void)pthread_attr_destroy(&attr);
    return;
}


/*
 * configd plugin-specific routines:
 */
void
load(CFBundleRef bundle, Boolean bundleVerbose)
{
    Boolean		ok;
    uint8_t		path[MAXPATHLEN];
    CFURLRef		url;

    /* Initialize logging category for EAPOL Controller */
    EAPLogInit(kEAPLogCategoryController);

    /* get a path to eapolclient */
    url = CFBundleCopyResourceURL(bundle, CFSTR("eapolclient"), NULL, NULL);
    if (url == NULL) {
	EAPLOG(LOG_NOTICE, 
	       "EAPOLController: failed to get URL for eapolclient");
	return;
    }
    ok = CFURLGetFileSystemRepresentation(url, TRUE, path, sizeof(path));
    CFRelease(url);
    if (ok == FALSE) {
	EAPLOG(LOG_NOTICE, 
	       "EAPOLController: failed to get path for eapolclient");
	return;
    }
    S_eapolclient_path = strdup((const char *)path);

    /* register the EAPOLController server port */
    server_register();
    return;
}

void
start(const char *bundleName, const char *bundleDir)
{
    if (S_eapolclient_path == NULL) {
	return;
    }
    LIST_INIT(S_clientHead_p);
    S_store = dynamic_store_create();
    return;
}

void
prime()
{
    if (S_eapolclient_path == NULL) {
	return;
    }
    ControllerBegin();
    return;
}

#ifdef TEST_AUTO_DETECT_STATUS

void
server_start(void)
{
}

void
server_register(void)
{
}

void
server_handle_request(__unused CFMachPortRef port, __unused void *msg, CFIndex size, __unused void *info)
{
}

int
main()
{
    CFDictionaryRef auto_detected_interfaces = NULL;

    {
	SCPrint(TRUE, stdout, CFSTR("cleaning up\n"));
	cleanup_auto_detect_status();
    }


    {
	SCPrint(TRUE, stdout, CFSTR("copying auto-detected interfaces\n"));
	auto_detected_interfaces = copy_interfaces_from_auto_detect_status();
	if (auto_detected_interfaces != NULL) {
	    SCPrint(TRUE, stdout, CFSTR("auto_detected_interfaces: %@\n"), auto_detected_interfaces);
	} else {
	    SCPrint(TRUE, stdout, CFSTR("no auto-detected interfaces found\n"));
	}
	my_CFRelease(&auto_detected_interfaces);
    }

    {
	int pkt_id = 1;
	const struct ether_addr	auth_mac = { {0xBA, 0x38, 0x2E, 0xBD, 0x21, 0x34 } };
	//u_char auth_mac[ETHER_ADDR_LEN] = {0xBA, 0x38, 0x2E, 0xBD, 0x21, 0x34};
	CFDataRef mac = CFDataCreate(NULL, (const UInt8 *)&auth_mac, sizeof(auth_mac));
	CFNumberRef identifier = CFNumberCreate(NULL, kCFNumberIntType, &pkt_id);
	SCPrint(TRUE, stdout, CFSTR("adding en0\n"));
	add_interface_to_auto_detect_status(CFSTR("en0"), mac, identifier);
	my_CFRelease(&mac);
	my_CFRelease(&identifier);
    }

    {
	SCPrint(TRUE, stdout, CFSTR("copying auto-detected interfaces\n"));
	auto_detected_interfaces = copy_interfaces_from_auto_detect_status();
	if (auto_detected_interfaces != NULL) {
	    SCPrint(TRUE, stdout, CFSTR("auto_detected_interfaces: %@\n"), auto_detected_interfaces);
	} else {
	    SCPrint(TRUE, stdout, CFSTR("no auto-detected interfaces found\n"));
	}
	my_CFRelease(&auto_detected_interfaces);
    }

    {
	int pkt_id = 2;
	const struct ether_addr	auth_mac = { {0xBB, 0x38, 0x2E, 0xBD, 0x21, 0x35 } };
	CFDataRef mac = CFDataCreate(NULL, (const UInt8 *)&auth_mac, sizeof(auth_mac));
	CFNumberRef identifier = CFNumberCreate(NULL, kCFNumberIntType, &pkt_id);
	SCPrint(TRUE, stdout, CFSTR("adding en0\n"));
	add_interface_to_auto_detect_status(CFSTR("en0"), mac, identifier);
	my_CFRelease(&mac);
	my_CFRelease(&identifier);
    }

    {
	int pkt_id = 3;
	const struct ether_addr	auth_mac = { {0xBC, 0x38, 0x2E, 0xBD, 0x21, 0x36 } };
	CFDataRef mac = CFDataCreate(NULL, (const UInt8 *)&auth_mac, sizeof(auth_mac));
	CFNumberRef identifier = CFNumberCreate(NULL, kCFNumberIntType, &pkt_id);
	SCPrint(TRUE, stdout, CFSTR("adding en7\n"));
	add_interface_to_auto_detect_status(CFSTR("en7"), mac, identifier);
	my_CFRelease(&mac);
	my_CFRelease(&identifier);
    }

    {
	SCPrint(TRUE, stdout, CFSTR("copying auto-detected interfaces\n"));
	auto_detected_interfaces = copy_interfaces_from_auto_detect_status();
	if (auto_detected_interfaces != NULL) {
	    SCPrint(TRUE, stdout, CFSTR("auto_detected_interfaces: %@\n"), auto_detected_interfaces);
	} else {
	    SCPrint(TRUE, stdout, CFSTR("no auto-detected interfaces found\n"));
	}
	my_CFRelease(&auto_detected_interfaces);
    }

    {
	int pkt_id = 4;
	const struct ether_addr	auth_mac = { {0xBD, 0x38, 0x2E, 0xBD, 0x21, 0x37 } };
	CFDataRef mac = CFDataCreate(NULL, (const UInt8 *)&auth_mac, sizeof(auth_mac));
	CFNumberRef identifier = CFNumberCreate(NULL, kCFNumberIntType, &pkt_id);
	SCPrint(TRUE, stdout, CFSTR("adding en8\n"));
	add_interface_to_auto_detect_status(CFSTR("en8"), mac, identifier);
	my_CFRelease(&mac);
	my_CFRelease(&identifier);
    }

    {
	SCPrint(TRUE, stdout, CFSTR("copying auto-detected interfaces\n"));
	auto_detected_interfaces = copy_interfaces_from_auto_detect_status();
	if (auto_detected_interfaces != NULL) {
	    SCPrint(TRUE, stdout, CFSTR("auto_detected_interfaces: %@\n"), auto_detected_interfaces);
	} else {
	    SCPrint(TRUE, stdout, CFSTR("no auto-detected interfaces found\n"));
	}
	my_CFRelease(&auto_detected_interfaces);
    }

    getchar();
    return 0;
}

#endif /* TEST_AUTO_DETECT_STATUS */
