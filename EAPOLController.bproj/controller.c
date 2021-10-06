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

/* 
 * Modification History
 *
 * November 8, 2001	Dieter Siegmund
 * - created
 */

#include <syslog.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/queue.h>
#include <mach/mach.h>
#include <mach/message.h>
#include <mach/mach_error.h>

#include <SystemConfiguration/SystemConfiguration.h>
#include <CoreFoundation/CFDictionary.h>
#include <CoreFoundation/CFMachPort.h>
#include <CoreFoundation/CFRunLoop.h>
#include <SystemConfiguration/SCDPlugin.h>

#include "mylog.h"
#include "myCFUtil.h"
#include "controller.h"
#include "server.h"
#include "ClientControlInterface.h"
#include <EAP8021X/EAPOLControlTypes.h>

#ifndef kSCEntNetRefreshConfiguration
#define kSCEntNetRefreshConfiguration	CFSTR("RefreshConfiguration")
#endif kSCEntNetRefreshConfiguration

#ifndef kSCEntNetEAPOL
#define kSCEntNetEAPOL		CFSTR("EAPOL")
#endif kSCEntNetEAPOL

static SCDynamicStoreRef	store = NULL;

typedef struct eapolClient_s {
    LIST_ENTRY(eapolClient_s)	link;

    EAPOLControlState		state;

    if_name_t			if_name;
    CFStringRef			notification_key;
    CFStringRef			force_renew_key;
    struct {
	uid_t			uid;
	gid_t			gid;
    } owner;

    pid_t			pid;
    mach_port_t			notify_port;
    mach_port_t			bootstrap;
    CFMachPortRef		session_cfport;
    CFRunLoopSourceRef		session_rls;
    boolean_t			notification_sent;
    boolean_t			retry;

    boolean_t			keep_it;
    boolean_t			console_user;	/* started by console user */
    CFDictionaryRef		config_dict;

    CFDictionaryRef		status_dict;
} eapolClient, *eapolClientRef;

static LIST_HEAD(clientHead, eapolClient_s)	S_head;
static struct clientHead * S_clientHead_p = &S_head;

static void
eapolClientSetState(eapolClientRef client, EAPOLControlState state);

eapolClientRef
eapolClientLookupInterface(if_name_t if_name)
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
eapolClientAdd(if_name_t if_name)
{
    eapolClientRef client;

    client = malloc(sizeof(*client));
    if (client == NULL) {
	return (NULL);
    }
    bzero(client, sizeof(*client));
    strcpy(client->if_name, if_name);
    client->pid = -1;
    LIST_INSERT_HEAD(S_clientHead_p, client, link);
    return (client);
}

void
eapolClientRemove(eapolClientRef client)
{
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
    client->keep_it = FALSE;
    client->retry = FALSE;
    client->notification_sent = FALSE;
    my_CFRelease(&client->notification_key);
    my_CFRelease(&client->force_renew_key);
    if (client->notify_port != MACH_PORT_NULL) {
	(void)mach_port_destroy(mach_task_self(), client->notify_port);
	client->notify_port = MACH_PORT_NULL;
    }
    if (client->bootstrap != MACH_PORT_NULL) {
	(void)mach_port_destroy(mach_task_self(), client->bootstrap);
	client->bootstrap = MACH_PORT_NULL;
    }
    if (client->session_cfport != NULL) {
	CFMachPortInvalidate(client->session_cfport);
	my_CFRelease(&client->session_cfport);
    }
    if (client->session_rls != NULL) {
	CFRunLoopRemoveSource(CFRunLoopGetCurrent(),
			      client->session_rls, kCFRunLoopDefaultMode);
	my_CFRelease(&client->session_rls);
    }
    my_CFRelease(&client->config_dict);
    my_CFRelease(&client->status_dict);
    return;
}

static void
eapolClientNotify(eapolClientRef client)
{
    mach_msg_empty_send_t	msg;
    mach_msg_option_t		options;
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
    options = MACH_SEND_TIMEOUT;
    status = mach_msg(&msg.header,			/* msg */
		      MACH_SEND_MSG | MACH_SEND_TIMEOUT,/* options */
		      msg.header.msgh_size,		/* send_size */
		      0,				/* rcv_size */
		      MACH_PORT_NULL,			/* rcv_name */
		      0,				/* timeout */
		      MACH_PORT_NULL);			/* notify */
    if (status != KERN_SUCCESS) {
	my_log(LOG_NOTICE,  "eapolClientNotify: mach_msg(%s) failed: %s",
	       client->if_name, mach_error_string(status));
    }
    client->notification_sent = TRUE;
    return;
}

static CFStringRef
eapolClientNotificationKey(eapolClientRef client)
{
    CFStringRef		if_name_cf;

    if (client->notification_key == NULL) {
	if_name_cf = CFStringCreateWithCString(NULL, client->if_name, 
					       kCFStringEncodingASCII);
	client->notification_key
	    = SCDynamicStoreKeyCreateNetworkInterfaceEntity(NULL,
							    kSCDynamicStoreDomainState,
							    if_name_cf,
							    kSCEntNetEAPOL);
	my_CFRelease(&if_name_cf);
    }
    return (client->notification_key);
}

static void
eapolClientSetState(eapolClientRef client, EAPOLControlState state)
{
    client->state = state;
    if (store == NULL) {
	return;
    }
    SCDynamicStoreNotifyValue(store, eapolClientNotificationKey(client));
    return;
}

static void
eapolClientPublishStatus(eapolClientRef client, CFDictionaryRef status_dict)

{
    if (store == NULL) {
	return;
    }
    CFRetain(status_dict);
    my_CFRelease(&client->status_dict);
    client->status_dict = status_dict;
    SCDynamicStoreNotifyValue(store, eapolClientNotificationKey(client));
    return;
}

static CFStringRef
eapolClientForceRenewKey(eapolClientRef client)
{
    CFStringRef		if_name_cf;

    if (client->force_renew_key == NULL) {
	if_name_cf = CFStringCreateWithCString(NULL, client->if_name, 
					       kCFStringEncodingASCII);
	client->force_renew_key
	    = SCDynamicStoreKeyCreateNetworkInterfaceEntity(NULL,
							    kSCDynamicStoreDomainState,
							    if_name_cf,
							    kSCEntNetRefreshConfiguration);
	my_CFRelease(&if_name_cf);
    }
    return (client->force_renew_key);
}

static void
eapolClientForceRenew(eapolClientRef client)

{
    if (store == NULL) {
	return;
    }
    SCDynamicStoreNotifyValue(store, eapolClientForceRenewKey(client));
    return;
}

static void 
exec_callback(pid_t pid, int status, struct rusage * rusage, void * context)
{
    eapolClientRef	client;
    boolean_t		keep_it;
    
    client = eapolClientLookupProcess(pid);
    if (client == NULL) {
	return;
    }
    if (client->state != kEAPOLControlStateIdle) {
	my_log(LOG_NOTICE, 
	       "EAPOLController: eapolclient(%s) pid=%d exited with status %d",
	       client->if_name,  pid, status);
    }
    keep_it = client->keep_it;
    eapolClientInvalidate(client);
    if (keep_it == FALSE) {
	eapolClientRemove(client);
    }
    return;
}

static CFNumberRef
make_command_number(EAPOLClientControlCommand command)
{
    return (CFNumberCreate(NULL, kCFNumberIntType, &command));
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

static boolean_t
is_console_user(uid_t check_uid)
{
    uid_t	uid;
    CFStringRef user;

    user = SCDynamicStoreCopyConsoleUser(store, &uid, NULL);
    if (user == NULL) {
	return (FALSE);
    }
    CFRelease(user);
    return (check_uid == uid);
}

int
ControllerStart(if_name_t if_name, uid_t uid, gid_t gid,
		CFDictionaryRef config_dict, mach_port_t bootstrap)
{
    eapolClientRef 	client;
    int			status = 0;

    client = eapolClientLookupInterface(if_name);
    if (client != NULL && client->state != kEAPOLControlStateIdle) {
	switch (client->state) {
	case kEAPOLControlStateRunning:
	    status = EEXIST;
	    break;
	default:
	    status = EBUSY;
	    break;
	}
    }
    else {
	char		gid_str[32];
	boolean_t	on_console;
	char 		uid_str[32];

	char * argv[] = { eapolclient_path, 
			  "-i", if_name,
			  "-u", 
			  NULL,		/* 4 */
			  "-g", 
			  NULL,		/* 6 */
			  NULL, 	/* 7 */
			  NULL };

	snprintf(uid_str, sizeof(uid_str), "%u", uid);
	snprintf(gid_str, sizeof(gid_str), "%u", gid);
	argv[4] = uid_str;
	argv[6] = gid_str;
	on_console = is_console_user(uid);
	if (on_console == FALSE) {
	    argv[7] = "-n";
	}
	if (client == NULL) {
	    client = eapolClientAdd(if_name);
	}
	if (client == NULL) {
	    status = ENOMEM;
	    goto failed;
	}
	client->pid = _SCDPluginExecCommand(exec_callback, NULL, 0, 0,
					    eapolclient_path, argv);
	if (client->pid == -1) {
	    status = errno;
	}
	else {
	    client->owner.uid = uid;
	    client->owner.gid = gid;
	    client->console_user = on_console;
	    client->config_dict = CFRetain(config_dict);
	    client->bootstrap = bootstrap;
	    eapolClientSetState(client, kEAPOLControlStateStarting);
	}
    }
 failed:
    if (status != 0) {
	(void)mach_port_destroy(mach_task_self(), bootstrap);
    }
    return (status);
}

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
    if (uid != 0 && uid != client->owner.uid) {
	status = EPERM;
	goto done;
    }
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
#endif 0

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
    client->config_dict = CFRetain(config_dict);
    client->retry = FALSE;

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

int
ControllerSetLogLevel(if_name_t if_name, uid_t uid, gid_t gid,
		      int32_t level)
{
    eapolClientRef 	client;
    int32_t		cur_level = -1;
    CFNumberRef		log_prop;
    int			status = 0;

    client = eapolClientLookupInterface(if_name);
    if (client == NULL || client->config_dict == NULL) {
	status = ENOENT;
	goto done;
    }
    if (uid != 0 && uid != client->owner.uid) {
	status = EPERM;
	goto done;
    }
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
    log_prop = CFDictionaryGetValue(client->config_dict, 
				    kEAPOLControlLogLevel);
    if (log_prop) {
	(void)CFNumberGetValue(log_prop, kCFNumberSInt32Type, &cur_level);
    }
    if (level < 0) {
	level = -1;
    }
    /* if the log level changed, update it and tell the client */
    if (cur_level != level) {
	int			count;
	CFMutableDictionaryRef	dict = NULL;

	count = CFDictionaryGetCount(client->config_dict);
	if (level >= 0) {
	    count++;
	}
	dict = CFDictionaryCreateMutableCopy(NULL, count,
					     client->config_dict);
	if (level >= 0) {
	    CFNumberRef		level_prop;
	    level_prop = CFNumberCreate(NULL, kCFNumberSInt32Type,
					&level);
	    CFDictionarySetValue(dict, kEAPOLControlLogLevel, level_prop);
	    my_CFRelease(&level_prop);
	}
	else {
	    CFDictionaryRemoveValue(dict, kEAPOLControlLogLevel);
	}
	my_CFRelease(&client->config_dict);
	client->config_dict = dict;

	if (client->state == kEAPOLControlStateRunning) {
	    /* tell the client to re-read */
	    eapolClientNotify(client);
	}
    }
 done:
    return (status);

}

int
ControllerClientAttach(pid_t pid, if_name_t if_name,
		       mach_port_t notify_port,
		       mach_port_t * session_port,
		       CFDictionaryRef * control_dict,
		       mach_port_t * bootstrap)
{
    CFMutableDictionaryRef	dict = NULL;
    CFNumberRef			command_cf = NULL;
    eapolClientRef		client;
    int				result = 0;

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
    client->notify_port = notify_port;
    client->session_cfport 
	= CFMachPortCreate(NULL, server_handle_request, NULL, NULL);
    *session_port = CFMachPortGetPort(client->session_cfport);
    client->session_rls
	= CFMachPortCreateRunLoopSource(NULL, client->session_cfport, 0);
    CFRunLoopAddSource(CFRunLoopGetCurrent(),
		       client->session_rls, kCFRunLoopDefaultMode);
    dict = CFDictionaryCreateMutable(NULL, 0,
				     &kCFTypeDictionaryKeyCallBacks,
				     &kCFTypeDictionaryValueCallBacks);
    if (client->state == kEAPOLControlStateStarting) {
	command_cf = make_command_number(kEAPOLClientControlCommandRun);
	if (client->config_dict != NULL) {
	    CFDictionarySetValue(dict, kEAPOLClientControlConfiguration,
				 client->config_dict);
	}
			     
    }
    else {
	command_cf = make_command_number(kEAPOLClientControlCommandStop);
    }
    CFDictionarySetValue(dict, kEAPOLClientControlCommand, command_cf);
    *control_dict = dict;
    eapolClientSetState(client, kEAPOLControlStateRunning);
    client->keep_it = TRUE;
    *bootstrap = client->bootstrap;
    return (result);
 failed:
    (void)mach_port_destroy(mach_task_self(), notify_port);
    return (result);

}

int
ControllerClientDetach(mach_port_t session_port)
{
    eapolClientRef	client;
    int			result = 0;

    client = eapolClientLookupSession(session_port);
    if (client == NULL) {
	result = EINVAL;
	goto failed;
    }
    my_log(LOG_DEBUG,  "detached port 0x%x", session_port);
    eapolClientInvalidate(client);
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
	    command_cf = make_command_number(kEAPOLClientControlCommandRetry);
	}
	else {
	    command_cf = make_command_number(kEAPOLClientControlCommandRun);
	    if (client->config_dict != NULL) {
		CFDictionarySetValue(dict, kEAPOLClientControlConfiguration,
				     client->config_dict);
	    }
	}
    }
    else {
	command_cf = make_command_number(kEAPOLClientControlCommandStop);
    }
    CFDictionarySetValue(dict, kEAPOLClientControlCommand, command_cf);
    *control_dict = dict;
    client->notification_sent = FALSE;
    client->retry = FALSE;
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
    (void)eapolClientPublishStatus(client, status_dict);
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

int
ControllerClientPortDead(mach_port_t session_port)
{
    eapolClientRef	client;
    int			result = 0;

    my_log(LOG_DEBUG,  "ControllerClientPortDead: port 0x%x died", 
	   session_port);
    client = eapolClientLookupSession(session_port);
    if (client == NULL) {
	result = ENOENT;
	goto failed;
    }
    eapolClientInvalidate(client);
    eapolClientRemove(client);
 failed:
    return (result);
}

static void
console_user_changed()
{
    eapolClientRef	scan;
    uid_t		uid = 0;
    CFStringRef		user;

    user = SCDynamicStoreCopyConsoleUser(store, &uid, NULL);
    LIST_FOREACH(scan, S_clientHead_p, link) {
	if (scan->console_user) {
	    if (user == NULL || scan->owner.uid != uid) {
		(void)ControllerStop(scan->if_name, scan->owner.uid,
				     scan->owner.gid);
	    }
	}
    }
    my_CFRelease(&user);
    return;
}

static void
handle_changes(SCDynamicStoreRef store, CFArrayRef changes, void * arg)
{
    console_user_changed();
    return;
}

static SCDynamicStoreRef
dynamic_store_create(SCDynamicStoreCallBack func, void * arg)
{
    CFMutableArrayRef		keys = NULL;
    CFStringRef			key;
    CFRunLoopSourceRef		rls;
    SCDynamicStoreRef		store;
    SCDynamicStoreContext	context;

    bzero(&context, sizeof(context));
    context.info = arg;
    store = SCDynamicStoreCreate(NULL, CFSTR("EAPOLController"), 
				 func, &context);
    if (store == NULL) {
	my_log(LOG_NOTICE, "EAPOLController: SCDynamicStoreCreate() failed, %s",
	       SCErrorString(SCError()));
	return (NULL);
    }
    keys = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    key = SCDynamicStoreKeyCreateConsoleUser(NULL);
    CFArrayAppendValue(keys, key);
    my_CFRelease(&key);
    SCDynamicStoreSetNotificationKeys(store, keys, NULL);
    my_CFRelease(&keys);

    rls = SCDynamicStoreCreateRunLoopSource(NULL, store, 0);
    CFRunLoopAddSource(CFRunLoopGetCurrent(), rls, kCFRunLoopDefaultMode);
    my_CFRelease(&rls);
    return (store);
}

void
ControllerInitialize()
{
    LIST_INIT(S_clientHead_p);
    store = dynamic_store_create(handle_changes, NULL);
    return;
}
