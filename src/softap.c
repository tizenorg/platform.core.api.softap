/*
* Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <dbus/dbus.h>
#include <gio/gio.h>
#include <vconf.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "softap_private.h"

static int retry = 0;

static int __get_common_ssid(char *ssid, unsigned int size)
{
	if (ssid == NULL) {
		ERR("ssid is null!!");
		return SOFTAP_ERROR_INVALID_PARAMETER;
	}

	char *device_name = NULL;
	char *end = NULL;

	device_name = vconf_get_str(VCONFKEY_SETAPPL_DEVICE_NAME_STR);
	if (device_name == NULL) {
		ERR("vconf_get_str is failed and set default ssid!!");
		g_strlcpy(ssid, SOFTAP_DEFAULT_SSID, size);
	} else
		g_strlcpy(ssid, device_name, size);

	if (!g_utf8_validate(ssid, -1, (const char **)&end))
		*end = '\0';

	return SOFTAP_ERROR_NONE;
}

static int __get_initial_passphrase(char *passphrase, unsigned int size)
{
	if (passphrase == NULL ||
			size == 0 || size < SOFTAP_KEY_MIN_LEN + 1)
		return 0;

	guint32 rand_int = 0;
	int index = 0;

	for (index = 0; index < SOFTAP_KEY_MIN_LEN; index++) {
		rand_int = g_random_int_range('a', 'z');
		passphrase[index] = rand_int;
	}
	passphrase[index] = '\0';

	return index;
}

static softap_error_e __get_error(int agent_error)
{
	softap_error_e err = SOFTAP_ERROR_NONE;

	switch (agent_error) {
	case MOBILE_AP_ERROR_NONE:
		err = SOFTAP_ERROR_NONE;
		break;

	case MOBILE_AP_ERROR_RESOURCE:
		err = SOFTAP_ERROR_OUT_OF_MEMORY;
		break;

	case MOBILE_AP_ERROR_INTERNAL:
		err = SOFTAP_ERROR_OPERATION_FAILED;
		break;

	case MOBILE_AP_ERROR_INVALID_PARAM:
		err = SOFTAP_ERROR_INVALID_PARAMETER;
		break;

	case MOBILE_AP_ERROR_ALREADY_ENABLED:
		err = SOFTAP_ERROR_OPERATION_FAILED;
		break;

	case MOBILE_AP_ERROR_NET_OPEN:
		err = SOFTAP_ERROR_OPERATION_FAILED;
		break;

	case MOBILE_AP_ERROR_NET_CLOSE:
		err = SOFTAP_ERROR_OPERATION_FAILED;
		break;

	case MOBILE_AP_ERROR_DHCP:
		err = SOFTAP_ERROR_OPERATION_FAILED;
		break;

	case MOBILE_AP_ERROR_IN_PROGRESS:
		err = SOFTAP_ERROR_OPERATION_FAILED;
		break;

	case MOBILE_AP_ERROR_NOT_PERMITTED:
		err = SOFTAP_ERROR_NOT_PERMITTED;
		break;

	case MOBILE_AP_ERROR_PERMISSION_DENIED:
		err = SOFTAP_ERROR_PERMISSION_DENIED;
		break;

	default:
		ERR("Not defined error : %d\n", agent_error);
		err = SOFTAP_ERROR_OPERATION_FAILED;
		break;
	}

	return err;
}

static void __enabled_cfm_cb(GObject *source_object, GAsyncResult *res,
		gpointer user_data)
{
	DBG("+");
	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");
	__softap_h *sa = (__softap_h *)user_data;
	GError *g_error = NULL;
	GVariant *g_var;
	guint info;
	softap_error_e error;

	g_var  = g_dbus_proxy_call_finish(sa->client_bus_proxy, res, &g_error);
	if (g_error) {
		ERR("DBus error [%s]", g_error->message);
		if (g_error->code == G_DBUS_ERROR_NO_REPLY &&
				++retry < SOFTAP_ERROR_RECOVERY_MAX) {
			g_error_free(g_error);
			softap_enable((softap_h)sa);
			DBG("-");
			return;
		}

		if (g_error->code == G_DBUS_ERROR_ACCESS_DENIED)
			error = SOFTAP_ERROR_PERMISSION_DENIED;
		else
			error = SOFTAP_ERROR_OPERATION_FAILED;
		g_error_free(g_error);
	} else {
		g_variant_get(g_var, "(u)", &info);
		g_variant_unref(g_var);
		error = __get_error(info);
		if (error != SOFTAP_ERROR_NONE)
			ERR("Fail to enable Soft AP (%d)!!", error);
	}
	
		retry = 0;
		DBG("-");
	
		return;
}

static void __disabled_cfm_cb(GObject *source_object, GAsyncResult *res,
		gpointer user_data)
{
	DBG("+");
	__softap_h *sa = (__softap_h *)user_data;
	GError *g_error = NULL;
	GVariant *g_var;
	guint info;
	softap_error_e error;

	g_var = g_dbus_proxy_call_finish(sa->client_bus_proxy, res, &g_error);
	if (g_error) {
		ERR("DBus error [%s]", g_error->message);
		g_error_free(g_error);
		DBG("-");
		return;
	} else {
		g_variant_get(g_var, "(u)", &info);
		g_variant_unref(g_var);
		error = __get_error(info);
		if (error != SOFTAP_ERROR_NONE)
			ERR("Fail to disable Soft AP (%d)!!", error);
	}

	DBG("-");
	return;
}

static int __prepare_softap_settings(softap_h softap, _softap_settings_t *set)
{
	DBG("+");

	__softap_h *sa = (__softap_h *) softap;

	if (sa == NULL || set == NULL) {
		ERR("Parameter is NULL!!");
		return SOFTAP_ERROR_INVALID_PARAMETER;
	}

	g_strlcpy(set->ssid, sa->ssid, sizeof(set->ssid));
	set->sec_type = sa->sec_type;
	set->visibility = sa->visibility;

	if (set->sec_type == SOFTAP_SECURITY_TYPE_NONE)
		g_strlcpy(set->key, "", sizeof(set->key));
	else
		g_strlcpy(set->key, sa->passphrase, sizeof(set->key));

	DBG("-");
	return SOFTAP_ERROR_NONE;
}

API int softap_create(softap_h *softap)
{
	DBG("+");

	__softap_h *sa = NULL;
	GError *error = NULL;
	char ssid[SOFTAP_SSID_MAX_LEN + 1] = {0, };

	sa = (__softap_h *) malloc(sizeof(__softap_h));

	memset(sa, 0x00, sizeof(__softap_h));

	sa->visibility = true;
	sa->sec_type = SOFTAP_SECURITY_TYPE_WPA2_PSK;

	if (__get_common_ssid(ssid, sizeof(ssid)) != SOFTAP_ERROR_NONE) {
		ERR("Fail to get default ssid!!");
		free(sa);
		return SOFTAP_ERROR_OPERATION_FAILED;
	}
	
	if (__get_initial_passphrase(sa->passphrase, sizeof(sa->passphrase)) == 0) {
		ERR("Fail to generate random passphrase!!");
		free(sa);
		return SOFTAP_ERROR_OPERATION_FAILED;
	}

	sa->ssid = g_strdup(ssid);
	if (sa->ssid == NULL) {
		ERR("Fail to get default ssid!!");
		free(sa);
		return SOFTAP_ERROR_OPERATION_FAILED;
	}

	/* GDbus Setting */
#if !GLIB_CHECK_VERSION(2, 36, 0)
	g_type_init();
#endif
	GCancellable *cancellable = g_cancellable_new();
	sa->client_bus = g_bus_get_sync(DBUS_BUS_SYSTEM, cancellable, &error);
	if (error) {
		ERR("Couldn't connect to the System bus[%s]", error->message);
		g_error_free(error);
		g_cancellable_cancel(cancellable);
		g_object_unref(cancellable);
		free(sa);
		return SOFTAP_ERROR_OPERATION_FAILED;
	}
	sa->cancellable = cancellable;

	sa->client_bus_proxy = g_dbus_proxy_new_sync(sa->client_bus, G_DBUS_PROXY_FLAGS_NONE,
			NULL, SOFTAP_SERVICE_NAME, SOFTAP_SERVICE_OBJECT_PATH,
			SOFTAP_SERVICE_INTERFACE, sa->cancellable, &error);
	if (!sa->client_bus_proxy) {
		ERR("Fail to create the proxy object because of %s", error->message);
		g_cancellable_cancel(sa->cancellable);
		g_object_unref(sa->cancellable);
		free(sa);
		return SOFTAP_ERROR_OPERATION_FAILED;
	}

	*softap = (softap_h) sa;
	DBG("SoftAP Handle[0x%X] SSID[%s] Passphrase[%s] Security[%d] Visibilit[%d]", 
			sa, sa->ssid, sa->passphrase, sa->sec_type, sa->visibility);
	DBG("-");

	return SOFTAP_ERROR_NONE;
}

API int softap_destroy(softap_h softap)
{
	DBG("+");

	_retvm_if(softap == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(softap) is NULL\n");

	__softap_h *sa = (__softap_h *)softap;

	DBG("SoftAP Handle : 0x%X\n", sa);

	if (sa->ssid)
		free(sa->ssid);

	g_object_unref(sa->cancellable);
	g_object_unref(sa->client_bus_proxy);
	g_object_unref(sa->client_bus);
	memset(sa, 0x00, sizeof(__softap_h));
	free(sa);

	DBG("-");
	return SOFTAP_ERROR_NONE;
}

API int softap_enable(softap_h softap)
{
	DBG("+");
	 _retvm_if(softap == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			 "parameter(softap) is NULL");

	 softap_error_e ret = SOFTAP_ERROR_NONE;
	 __softap_h *sa = (__softap_h *) softap;
	 GDBusProxy *proxy = sa->client_bus_proxy;
	 //GDBusConnection *connection = sa->client_bus;
	 
	 g_dbus_proxy_set_default_timeout(proxy, DBUS_TIMEOUT_INFINITE);

	_softap_settings_t set = {"", "", 0, false};

	ret = __prepare_softap_settings(softap, &set);
	if (ret != SOFTAP_ERROR_NONE) {
		ERR("Fail to initialize softap settings\n");
		return SOFTAP_ERROR_OPERATION_FAILED;
	}

	//g_dbus_connection_signal_unsubscribe(connection,
	//sigs[E_SIGNAL_WIFI_AP_ON].sig_id);

	g_dbus_proxy_call(proxy, "enable",
	g_variant_new("(ssii)", set.ssid, set.key, set.visibility, set.sec_type),
		G_DBUS_CALL_FLAGS_NONE, -1, sa->cancellable, (GAsyncReadyCallback) __enabled_cfm_cb, (gpointer)softap);

	g_dbus_proxy_set_default_timeout(proxy, DBUS_TIMEOUT_USE_DEFAULT);
	DBG("-");

	return SOFTAP_ERROR_NONE;
}

API int softap_disable(softap_h softap)
{
	DBG("+");
	_retvm_if(softap == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(softap) is NULL");

	__softap_h *sa = (__softap_h *) softap;
	GDBusProxy *proxy = sa->client_bus_proxy;

	g_dbus_proxy_call(proxy, "disable",
			NULL, G_DBUS_CALL_FLAGS_NONE, -1, sa->cancellable,
			(GAsyncReadyCallback) __disabled_cfm_cb, (gpointer)softap);

	DBG("-");
	return SOFTAP_ERROR_NONE;
}
