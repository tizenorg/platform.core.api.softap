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

static void __handle_softap_on(GDBusConnection *connection, const gchar *sender_name,
			const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
			GVariant *parameters, gpointer user_data);

static void __handle_softap_off(GDBusConnection *connection, const gchar *sender_name,
		const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
		GVariant *parameters, gpointer user_data);

static void __handle_low_battery_mode(GDBusConnection *connection, const gchar *sender_name,
		const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
		GVariant *parameters, gpointer user_data);

static void __handle_flight_mode(GDBusConnection *connection, const gchar *sender_name,
		const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
		GVariant *parameters, gpointer user_data);

static void __handle_security_type_changed(GDBusConnection *connection, const gchar *sender_name,
		const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
		GVariant *parameters, gpointer user_data);

static void __handle_ssid_visibility_changed(GDBusConnection *connection, const gchar *sender_name,
		const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
		GVariant *parameters, gpointer user_data);

static void __handle_passphrase_changed(GDBusConnection *connection, const gchar *sender_name,
		const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
		GVariant *parameters, gpointer user_data);

static void __handle_dhcp(GDBusConnection *connection, const gchar *sender_name,
		const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
		GVariant *parameters, gpointer user_data);

static __softap_sig_t sigs[] = {
	{0, SIGNAL_NAME_LOW_BATTERY_MODE, __handle_low_battery_mode},
	{0, SIGNAL_NAME_FLIGHT_MODE, __handle_flight_mode},
	{0, SIGNAL_NAME_SECURITY_TYPE_CHANGED, __handle_security_type_changed},
	{0, SIGNAL_NAME_SSID_VISIBILITY_CHANGED, __handle_ssid_visibility_changed},
	{0, SIGNAL_NAME_PASSPHRASE_CHANGED, __handle_passphrase_changed},
	{0, SIGNAL_NAME_DHCP_STATUS, __handle_dhcp},
	{0, SIGNAL_NAME_SOFTAP_ON, __handle_softap_on},
	{0, SIGNAL_NAME_SOFTAP_OFF, __handle_softap_off},
	{0, "", NULL} };

static int retry = 0;

static void __send_dbus_signal(GDBusConnection *conn, const char *signal_name, const char *arg)
{
	if (conn == NULL || signal_name == NULL)
		return;

	GVariant *message = NULL;
	GError *error = NULL;

	if (arg)
		message = g_variant_new("(s)", arg);

	g_dbus_connection_emit_signal(conn, NULL, SOFTAP_SERVICE_OBJECT_PATH,
					SOFTAP_SERVICE_INTERFACE, signal_name, message, &error);
	if (error) {
		ERR("g_dbus_connection_emit_signal is failed because  %s\n", error->message);
		g_error_free(error);
	}
	g_variant_unref(message);
}

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

static softap_error_e __get_security_type(softap_security_type_e *security_type)
{
	if (security_type == NULL) {
		ERR("Invalid param\n");
		return SOFTAP_ERROR_INVALID_PARAMETER;
	}

	if (vconf_get_int(VCONFKEY_SOFTAP_SECURITY,
				(int *)security_type) < 0) {
		ERR("vconf_get_int is failed\n");
		return SOFTAP_ERROR_OPERATION_FAILED;
	}

	return SOFTAP_ERROR_NONE;
}

static softap_error_e __set_visibility(bool visible)
{
	if (vconf_set_int(VCONFKEY_SOFTAP_HIDE, visible ? 0 : 1) < 0) {
			ERR("vconf_set_int is failed\n");
			return SOFTAP_ERROR_OPERATION_FAILED;
		}

		return SOFTAP_ERROR_NONE;
}

static softap_error_e __get_visibility(bool *visible)
{
	if (visible == NULL) {
		ERR("Invalid param\n");
		return SOFTAP_ERROR_INVALID_PARAMETER;
	}

	int hide = 0;

	if (vconf_get_int(VCONFKEY_SOFTAP_HIDE, &hide) < 0) {
		ERR("vconf_get_int is failed\n");
		return SOFTAP_ERROR_OPERATION_FAILED;
	}

	if (hide)
		*visible = false;
	else
		*visible = true;

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

static void __handle_dhcp(GDBusConnection *connection, const gchar *sender_name,
		const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
		GVariant *parameters, gpointer user_data)
{
	DBG("+");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	__softap_h *sa = (__softap_h *)user_data;
	bool opened = false;
	softap_client_connection_state_changed_cb ccb = NULL;
	__softap_client_h client;
	void *data = NULL;
	char *buf = NULL;
	char *name = NULL;
	char *mac = NULL;
	char *ip = NULL;
	guint timestamp;

	memset(&client, 0, sizeof(__softap_client_h));
	g_variant_get(parameters, "(ssssu)", &buf, &ip, &mac, &name, &timestamp);

	if (!g_strcmp0(buf, "DhcpConnected")) {
		opened = true;
	} else if (!g_strcmp0(buf, "DhcpLeaseDeleted")) {
		opened = false;
	} else {
		ERR("Unknown event [%s]", buf);
		goto DONE;
	}

	ccb = sa->changed_cb;
	if (ccb == NULL)
		goto DONE;
	data = sa->changed_user_data;

	g_strlcpy(client.ip, ip, sizeof(client.ip));
	g_strlcpy(client.mac, mac, sizeof(client.mac));
	if (name != NULL)
		client.hostname = g_strdup(name);
	client.tm = (time_t)timestamp;

	ccb((softap_client_h)&client, opened, data);
	g_free(client.hostname);
DONE:
	g_free(buf);
	g_free(ip);
	g_free(mac);
	g_free(name);
	DBG("-");
}

static void __handle_softap_on(GDBusConnection *connection, const gchar *sender_name,
			const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
			GVariant *parameters, gpointer user_data)
{
	DBG("+");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL");

	__softap_h *sa = (__softap_h *)user_data;
	bool is_requested = false;
	softap_enabled_cb ecb = NULL;
	void *data = NULL;

	ecb = sa->enabled_cb;
	if (ecb == NULL)
		return;
	data = sa->enabled_user_data;
	ecb(SOFTAP_ERROR_NONE, is_requested, data);
	DBG("-");
}

static void __handle_softap_off(GDBusConnection *connection, const gchar *sender_name,
			const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
			GVariant *parameters, gpointer user_data)
{
	DBG("+");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL");

	__softap_h *sa = (__softap_h *)user_data;
	softap_disabled_cause_e code = SOFTAP_DISABLED_BY_OTHERS;
	softap_disabled_cb dcb = NULL;
	void *data = NULL;
	char *buf = NULL;

	dcb = sa->disabled_cb;
	if (dcb == NULL)
		return;
	data = sa->disabled_user_data;
	g_variant_get(parameters, "(s)", &buf);
	if (!g_strcmp0(buf, SIGNAL_MSG_NOT_AVAIL_INTERFACE))
		code = SOFTAP_DISABLED_BY_WIFI_ON;
	else if (!g_strcmp0(buf, SIGNAL_MSG_TIMEOUT))
		code = SOFTAP_DISABLED_BY_TIMEOUT;

	g_free(buf);
	dcb(SOFTAP_ERROR_NONE, code, data);

	DBG("-");
}

static void __handle_low_battery_mode(GDBusConnection *connection, const gchar *sender_name,
			const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
			GVariant *parameters, gpointer user_data)
{
	DBG("+");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL");

	__softap_h *sa = (__softap_h *)user_data;
	softap_disabled_cb dcb = NULL;
	void *data = NULL;
	softap_disabled_cause_e code = SOFTAP_DISABLED_BY_LOW_BATTERY;

	dcb = sa->disabled_cb;
	if (dcb == NULL)
		return;

	data = sa->disabled_user_data;

	dcb(SOFTAP_ERROR_NONE, code, data);
	DBG("-");
}

static void __handle_flight_mode(GDBusConnection *connection, const gchar *sender_name,
			const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
			GVariant *parameters, gpointer user_data)
{
	DBG("+");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	__softap_h *sa = (__softap_h *)user_data;
	softap_disabled_cb dcb = NULL;
	void *data = NULL;
	softap_disabled_cause_e code = SOFTAP_DISABLED_BY_FLIGHT_MODE;

	dcb = sa->disabled_cb;
	if (dcb == NULL)
		return;
	data = sa->disabled_user_data;

	dcb(SOFTAP_ERROR_NONE, code, data);
	DBG("-");
}

static void __handle_security_type_changed(GDBusConnection *connection, const gchar *sender_name,
		const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
		GVariant *parameters, gpointer user_data)

{
	DBG("+");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL");
	__softap_h *sa = (__softap_h *)user_data;

	softap_security_type_changed_cb scb = NULL;
	void *data = NULL;
	softap_security_type_e security_type;
	char *buf = NULL;

	scb = sa->security_type_changed_cb;
	if (scb == NULL)
		return;

	g_variant_get(parameters, "(s)", &buf);
	data = sa->security_type_user_data;
	if (g_strcmp0(buf, SOFTAP_SECURITY_TYPE_OPEN_STR) == 0)
		security_type = SOFTAP_SECURITY_TYPE_NONE;
	else if (g_strcmp0(buf, SOFTAP_SECURITY_TYPE_WPA2_PSK_STR) == 0)
		security_type = SOFTAP_SECURITY_TYPE_WPA2_PSK;
	else {
		SERR("Unknown type : %s", buf);
		g_free(buf);
		return;
	}
	g_free(buf);
	scb(security_type, data);

	return;
}

static void __handle_ssid_visibility_changed(GDBusConnection *connection, const gchar *sender_name,
		const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
		GVariant *parameters, gpointer user_data)
{
	DBG("+");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL");
	__softap_h *sa = (__softap_h *)user_data;

	softap_ssid_visibility_changed_cb scb = NULL;
	void *data = NULL;
	bool visible = false;
	char *buf = NULL;

	scb = sa->ssid_visibility_changed_cb;
	if (scb == NULL) {
		DBG("-");
		return;
	}
	g_variant_get(parameters, "(s)", &buf);
	data = sa->ssid_visibility_user_data;
	if (g_strcmp0(buf, SIGNAL_MSG_SSID_VISIBLE) == 0)
		visible = true;

	scb(visible, data);
	g_free(buf);
	DBG("-");
}

static void __handle_passphrase_changed(GDBusConnection *connection, const gchar *sender_name,
		const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
		GVariant *parameters, gpointer user_data)
{
	DBG("+");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");
	__softap_h *sa = (__softap_h *)user_data;

	softap_passphrase_changed_cb pcb = NULL;
	void *data = NULL;

	pcb = sa->passphrase_changed_cb;
	if (pcb == NULL)
		return;

	data = sa->passphrase_user_data;

	pcb(data);
	DBG("-");
}

static void __enabled_cfm_cb(GObject *source_object, GAsyncResult *res,
		gpointer user_data)
{
	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");
	__softap_h *sa = (__softap_h *)user_data;
	GError *g_error = NULL;
	GVariant *g_var;
	guint info;
	softap_error_e error;
	softap_enabled_cb ecb = sa->enabled_cb;
	void *data = sa->enabled_user_data;

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

	sigs[E_SIGNAL_SOFTAP_ON].sig_id = g_dbus_connection_signal_subscribe(sa->client_bus,
			NULL, SOFTAP_SERVICE_INTERFACE, sigs[E_SIGNAL_SOFTAP_ON].name,
			SOFTAP_SERVICE_OBJECT_PATH, NULL, G_DBUS_SIGNAL_FLAGS_NONE,
			sigs[E_SIGNAL_SOFTAP_ON].cb, (gpointer)sa, NULL);

	DBG("[DBG] sig.id for softap on (%d)", sigs[E_SIGNAL_SOFTAP_ON].sig_id);

	if (ecb)
		ecb(error, true, data);

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
	softap_disabled_cause_e code = SOFTAP_DISABLED_BY_REQUEST;
	softap_disabled_cb dcb = sa->disabled_cb;
	void *data = sa->disabled_user_data;

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

	sigs[E_SIGNAL_SOFTAP_OFF].sig_id = g_dbus_connection_signal_subscribe(sa->client_bus,
			NULL, SOFTAP_SERVICE_INTERFACE, sigs[E_SIGNAL_SOFTAP_OFF].name,
			SOFTAP_SERVICE_OBJECT_PATH, NULL, G_DBUS_SIGNAL_FLAGS_NONE,
			sigs[E_SIGNAL_SOFTAP_OFF].cb, (gpointer)sa, NULL);

	if (dcb)
		dcb(error, code, data);

	DBG("-");
	return;
}


static void __settings_reloaded_cb(GObject *source_object, GAsyncResult *res,
		gpointer user_data)
{
	DBG("+\n");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");
	GError *g_error = NULL;
	GVariant *g_var;
	guint info;
	__softap_h *sa = (__softap_h *)user_data;
	softap_error_e softap_error;

	g_var  = g_dbus_proxy_call_finish(sa->client_bus_proxy, res, &g_error);
	if (g_error) {
		ERR("DBus fail [%s]\n", g_error->message);
		if (g_error->code == G_DBUS_ERROR_ACCESS_DENIED)
			softap_error = SOFTAP_ERROR_PERMISSION_DENIED;
		else
			softap_error = SOFTAP_ERROR_OPERATION_FAILED;
		g_error_free(g_error);
	}
	if (sa->settings_reloaded_cb == NULL) {
		DBG("There is no settings_reloaded_cb\n-\n");
		return;
	}
	g_variant_get(g_var, "(u)", &info);
	softap_error = __get_error(info);
	g_variant_unref(g_var);

	sa->settings_reloaded_cb(softap_error,
			sa->settings_reloaded_user_data);

	sa->settings_reloaded_cb = NULL;
	sa->settings_reloaded_user_data = NULL;
	DBG("-\n");
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

static void __connect_signals(softap_h softap)
{
	DBG("+");
	_retm_if(softap == NULL, "parameter(softap) is NULL");

	__softap_h *sa = (__softap_h *)softap;
	GDBusConnection *connection = sa->client_bus;
	int i = 0;

	for (i = E_SIGNAL_SOFTAP_ON; i < E_SIGNAL_MAX; i++) {
		sigs[i].sig_id = g_dbus_connection_signal_subscribe(connection,
				NULL, SOFTAP_SERVICE_INTERFACE, sigs[i].name,
				SOFTAP_SERVICE_OBJECT_PATH, NULL, G_DBUS_SIGNAL_FLAGS_NONE,
				sigs[i].cb, softap, NULL);
	}
	DBG("-");
}

static void __disconnect_signals(softap_h softap)
{
	DBG("+");

	_retm_if(softap == NULL, "parameter(softap) is NULL\n");

	__softap_h *sa = (__softap_h *)softap;
	GDBusConnection *connection = sa->client_bus;

	int i = 0;

	for (i = E_SIGNAL_SOFTAP_ON; i < E_SIGNAL_MAX; i++)
		g_dbus_connection_signal_unsubscribe(connection, sigs[i].sig_id);
	DBG("-");
}

static softap_error_e __set_security_type(const softap_security_type_e security_type)
{
	if (security_type != SOFTAP_SECURITY_TYPE_NONE &&
			security_type != SOFTAP_SECURITY_TYPE_WPA2_PSK) {
		ERR("Invalid param\n");
		return SOFTAP_ERROR_INVALID_PARAMETER;
	}

	if (vconf_set_int(VCONFKEY_SOFTAP_SECURITY, security_type) < 0) {
		ERR("vconf_set_int is failed\n");
		return SOFTAP_ERROR_OPERATION_FAILED;
	}

	return SOFTAP_ERROR_NONE;
}

static bool __get_ssid_from_vconf(const char *path, char *ssid, unsigned int size)
{
	if (path == NULL || ssid == NULL || size == 0)
		return false;

	char *ptr = NULL;
	char *ptr_tmp = NULL;

	ptr = vconf_get_str(path);
	if (ptr == NULL)
		return false;

	if (!g_utf8_validate(ptr, -1, (const char **)&ptr_tmp))
		*ptr_tmp = '\0';

	g_strlcpy(ssid, ptr, size);
	free(ptr);

	return true;
}

API int softap_create(softap_h *softap)
{
	DBG("+");
	_retvm_if(softap == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(softap) is NULL\n");

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
		if (error) {
			ERR("Fail to create the proxy object because of %s", error->message);
			g_error_free(error);
		}
		g_cancellable_cancel(sa->cancellable);
		g_object_unref(sa->cancellable);
		free(sa);
		return SOFTAP_ERROR_OPERATION_FAILED;
	}

	 __connect_signals((softap_h)sa);

	DBG("[DBG] create sig.id for softap on (%d)", sigs[E_SIGNAL_SOFTAP_ON].sig_id);

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
	__disconnect_signals(softap);

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

	 g_dbus_proxy_set_default_timeout(proxy, DBUS_TIMEOUT_INFINITE);

	_softap_settings_t set = {"", "", 0, false};

	ret = __prepare_softap_settings(softap, &set);
	if (ret != SOFTAP_ERROR_NONE) {
		ERR("Fail to initialize softap settings\n");
		return SOFTAP_ERROR_OPERATION_FAILED;
	}

	g_dbus_connection_signal_unsubscribe(sa->client_bus, sigs[E_SIGNAL_SOFTAP_ON].sig_id);
	DBG("[DBG] unsubscribe sig.id for softap on (%d)", sigs[E_SIGNAL_SOFTAP_ON].sig_id);

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
	GDBusConnection *connection = sa->client_bus;

	g_dbus_connection_signal_unsubscribe(connection, sigs[E_SIGNAL_SOFTAP_OFF].sig_id);

	g_dbus_proxy_call(proxy, "disable",
			NULL, G_DBUS_CALL_FLAGS_NONE, -1, sa->cancellable,
			(GAsyncReadyCallback) __disabled_cfm_cb, (gpointer)softap);

	DBG("-");
	return SOFTAP_ERROR_NONE;
}

API int softap_reload_settings(softap_h softap, softap_settings_reloaded_cb callback, void *user_data)

{
	_retvm_if(softap == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(softap) is NULL\n");
	_retvm_if(callback == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(callback) is NULL\n");

	__softap_h *sa = (__softap_h *)softap;
	_softap_settings_t set = {"", "", 0, false};
	GDBusProxy *proxy = sa->client_bus_proxy;
	int ret = 0;

	DBG("+");

	if (sa->settings_reloaded_cb) {
		ERR("Operation in progress\n");
		return SOFTAP_ERROR_OPERATION_FAILED;
	}

	ret = __prepare_softap_settings(softap, &set);
	if (ret != SOFTAP_ERROR_NONE) {
		ERR("softap settings initialization failed\n");
		return SOFTAP_ERROR_OPERATION_FAILED;
	}

	sa->settings_reloaded_cb = callback;
	sa->settings_reloaded_user_data = user_data;

	g_dbus_proxy_call(proxy, "reload_settings",
			g_variant_new("(ssii)", set.ssid, set.key, set.visibility, set.sec_type),
			G_DBUS_CALL_FLAGS_NONE, -1, sa->cancellable,
			(GAsyncReadyCallback) __settings_reloaded_cb, (gpointer)softap);

	return SOFTAP_ERROR_NONE;
}

API int softap_is_enabled(softap_h softap, bool *enable)
{
	DBG("+");
	_retvm_if(softap == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(softap) is NULL");
	_retvm_if(enable == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(enable) is NULL");

	int is_on = 0;
	int vconf_type = VCONFKEY_MOBILE_HOTSPOT_MODE_WIFI_AP;

	if (vconf_get_int(VCONFKEY_MOBILE_HOTSPOT_MODE, &is_on) != 0) {
		ERR("Fail to get vconf key!!");
		return SOFTAP_ERROR_OPERATION_FAILED;
	}

	*enable = is_on & vconf_type ? true : false;

	DBG("-");
	return SOFTAP_ERROR_NONE;
}

API int softap_get_mac_address(softap_h softap, char **mac_address)
{
	DBG("+");
	_retvm_if(softap == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(softap) is NULL\n");
	_retvm_if(mac_address == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(mac_address) is NULL\n");

	struct ifreq ifr;
	int ret = SOFTAP_ERROR_NONE;
	int s = 0;
	char *macbuf = NULL;
	bool enabled = false;

	ret = softap_is_enabled(softap, &enabled);
	_retvm_if(ret != SOFTAP_ERROR_NONE, SOFTAP_ERROR_OPERATION_FAILED, "Fail to check softap is enabled!!\n");
	_retvm_if(enabled == false, SOFTAP_ERROR_NOT_PERMITTED, "Soft AP is not enabled\n");

	g_strlcpy(ifr.ifr_name, SOFTAP_IF, sizeof(ifr.ifr_name));
	s = socket(AF_INET, SOCK_DGRAM, 0);
	_retvm_if(s < 0, SOFTAP_ERROR_OPERATION_FAILED,
			"Fail to get socket!!\n");

	if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
		ERR("Fail to get mac address!!");
		close(s);
		return SOFTAP_ERROR_OPERATION_FAILED;
	}

	close(s);

	macbuf = (char *)malloc(SOFTAP_STR_INFO_LEN);
	_retvm_if(macbuf == NULL, SOFTAP_ERROR_OUT_OF_MEMORY, "Not enough memory\n");

	snprintf(macbuf, SOFTAP_STR_INFO_LEN, "%02X:%02X:%02X:%02X:%02X:%02X",
			(unsigned char)ifr.ifr_hwaddr.sa_data[0],
			(unsigned char)ifr.ifr_hwaddr.sa_data[1],
			(unsigned char)ifr.ifr_hwaddr.sa_data[2],
			(unsigned char)ifr.ifr_hwaddr.sa_data[3],
			(unsigned char)ifr.ifr_hwaddr.sa_data[4],
			(unsigned char)ifr.ifr_hwaddr.sa_data[5]);

	*mac_address = macbuf;

	DBG("-");
	return SOFTAP_ERROR_NONE;
}

API int softap_get_network_interface_name(softap_h softap, char **interface_name)
{
	DBG("+");
	_retvm_if(softap == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(softap) is NULL\n");
	_retvm_if(interface_name == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(interface_name) is NULL\n");

	int ret = SOFTAP_ERROR_NONE;
	bool enabled = false;

	ret = softap_is_enabled(softap, &enabled);
	_retvm_if(ret != SOFTAP_ERROR_NONE, SOFTAP_ERROR_OPERATION_FAILED, "Fail to check softap is enabled!!\n");
	_retvm_if(enabled == false, SOFTAP_ERROR_NOT_PERMITTED, "Soft AP is not enabled\n");

	*interface_name = strdup(SOFTAP_IF);
	_retvm_if(*interface_name == NULL, SOFTAP_ERROR_OUT_OF_MEMORY,
			"Not enough memory!!\n");

	DBG("-");
	return SOFTAP_ERROR_NONE;
}

API int softap_get_ip_address(softap_h softap, softap_address_family_e address_family,  char **ip_address)
{
	DBG("+");
	_retvm_if(softap == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(softap) is NULL\n");
	_retvm_if(ip_address == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(ip_address) is NULL\n");

	struct ifreq ifr;
	int ret = SOFTAP_ERROR_NONE;
	int s = 0;
	bool enabled = false;
	char *ipbuf = NULL;

	ret = softap_is_enabled(softap, &enabled);
	_retvm_if(ret != SOFTAP_ERROR_NONE, SOFTAP_ERROR_OPERATION_FAILED, "Fail to check softap is enabled!!\n");
	_retvm_if(enabled == false, SOFTAP_ERROR_NOT_PERMITTED, "Soft AP is not enabled\n");

	g_strlcpy(ifr.ifr_name, SOFTAP_IF, sizeof(ifr.ifr_name));
	s = socket(AF_INET, SOCK_DGRAM, 0);
	_retvm_if(s < 0, SOFTAP_ERROR_OPERATION_FAILED, "Fail to get socket!!\n");

	if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
		ERR("Fail to get interface name!!");
		close(s);
		return SOFTAP_ERROR_OPERATION_FAILED;
	}

	close(s);

	ipbuf = inet_ntoa(((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr);
	*ip_address = strdup(ipbuf);
	_retvm_if(*ip_address == NULL, SOFTAP_ERROR_OUT_OF_MEMORY,
			"Not enough memory\n");

	DBG("-");
	return SOFTAP_ERROR_NONE;
}

API int softap_get_gateway_address(softap_h softap, softap_address_family_e address_family, char **gateway_address)
{
	DBG("+");
	_retvm_if(softap == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(softap) is NULL\n");
	_retvm_if(gateway_address == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(gateway_address) is NULL\n");

	int ret = SOFTAP_ERROR_NONE;
	bool enabled = false;

	ret = softap_is_enabled(softap, &enabled);
	_retvm_if(ret != SOFTAP_ERROR_NONE, SOFTAP_ERROR_OPERATION_FAILED, "Fail to check softap is enabled!!\n");
	_retvm_if(enabled == false, SOFTAP_ERROR_NOT_PERMITTED, "Soft AP is not enabled\n");

	*gateway_address = strdup(SOFTAP_GATEWAY);

	DBG("-");
	return SOFTAP_ERROR_NONE;
}

API int softap_get_subnet_mask(softap_h softap, softap_address_family_e address_family, char **subnet_mask)
{
	DBG("+");
	_retvm_if(softap == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(softap) is NULL\n");
	_retvm_if(subnet_mask == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(subnet_mask) is NULL\n");

	int ret = SOFTAP_ERROR_NONE;
	bool enabled = false;

	ret = softap_is_enabled(softap, &enabled);
	_retvm_if(ret != SOFTAP_ERROR_NONE, SOFTAP_ERROR_OPERATION_FAILED, "Fail to check softap is enabled!!\n");
	_retvm_if(enabled == false, SOFTAP_ERROR_NOT_PERMITTED, "Soft AP is not enabled\n");

	*subnet_mask = strdup(SOFTAP_SUBNET_MASK);

	DBG("-");
	return SOFTAP_ERROR_NONE;
}

API int softap_foreach_connected_clients(softap_h softap, softap_connected_client_cb callback, void *user_data)
{
	DBG("+\n");
	_retvm_if(softap == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(softap) is NULL\n");
	_retvm_if(callback == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(callback) is NULL\n");

	__softap_h *sa = (__softap_h *)softap;
	__softap_client_h client = {"", };
	gchar *ip = NULL;
	gchar *mac = NULL;
	gchar *hostname = NULL;
	guint timestamp = 0;
	GError *error = NULL;
	GVariant *result = NULL;
	GVariantIter *outer_iter = NULL;
	GVariantIter *inner_iter = NULL;
	GVariant *station = NULL;
	GVariant *value = NULL;
	gchar *key = NULL;
	int interface = 0;

	result = g_dbus_proxy_call_sync(sa->client_bus_proxy, "get_station_info",
			NULL, G_DBUS_CALL_FLAGS_NONE,
			-1, sa->cancellable, &error);
	if (error)
		ERR("g_dbus_proxy_call_sync is failed and error is %s\n", error->message);
	g_variant_get(result, "(a(a{sv}))", &outer_iter);

	while (g_variant_iter_loop(outer_iter, "(@a{sv})", &station)) {
		g_variant_get(station, "a{sv}", &inner_iter);

		while (g_variant_iter_loop(inner_iter, "{sv}", &key, &value)) {
			if (g_strcmp0(key, "Type") == 0) {
				interface = g_variant_get_int32(value);
				if (interface != 3) {
					g_free(key);
					g_variant_unref(value);
					break;
				}
			}
			if (g_strcmp0(key, "IP") == 0) {
				g_variant_get(value, "s", &ip);
				SDBG("ip is %s\n", ip);
				g_strlcpy(client.ip, ip, sizeof(client.ip));
			} else if (g_strcmp0(key, "MAC") == 0) {
				g_variant_get(value, "s", &mac);
				SDBG("mac is %s\n", mac);
				g_strlcpy(client.mac, mac, sizeof(client.mac));
			} else if (g_strcmp0(key, "Name") == 0) {
				g_variant_get(value, "s", &hostname);
				SDBG("hsotname is %s\n", hostname);
				if (hostname)
					client.hostname = g_strdup(hostname);
			} else if (g_strcmp0(key, "Time") == 0) {
				timestamp = g_variant_get_int32(value);
				DBG("timestamp is %d\n", timestamp);
				client.tm = (time_t)timestamp;
			} else {
				ERR("Key %s not required\n", key);
			}
		}
		g_free(hostname);
		g_free(ip);
		g_free(mac);
		g_variant_iter_free(inner_iter);
		if (callback((softap_client_h)&client, user_data) == false) {
			DBG("iteration is stopped\n");
			g_free(client.hostname);
			g_variant_iter_free(outer_iter);
			g_variant_unref(station);
			g_variant_unref(result);
			DBG("-\n");
			return SOFTAP_ERROR_OPERATION_FAILED;
		}
		g_free(client.hostname);
	}
	g_variant_iter_free(outer_iter);
	g_variant_unref(station);
	g_variant_unref(result);
	DBG("-\n");
	return SOFTAP_ERROR_NONE;
}

API int softap_set_enabled_cb(softap_h softap, softap_enabled_cb callback, void *user_data)
{
	_retvm_if(softap == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(softap) is NULL\n");
	_retvm_if(callback == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(callback) is NULL\n");

	__softap_h *sa = (__softap_h *) softap;

	sa->enabled_cb = callback;
	sa->enabled_user_data = user_data;

	return SOFTAP_ERROR_NONE;
}

API int softap_unset_enabled_cb(softap_h softap)
{
	_retvm_if(softap == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(softap) is NULL\n");

	__softap_h *sa = (__softap_h *) softap;

	sa->enabled_cb = NULL;
	sa->enabled_user_data = NULL;

	return SOFTAP_ERROR_NONE;
}

API int softap_set_disabled_cb(softap_h softap, softap_disabled_cb callback, void *user_data)
{
	_retvm_if(softap == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(softap) is NULL\n");
	_retvm_if(callback == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(callback) is NULL\n");

	__softap_h *sa = (__softap_h *) softap;

	sa->disabled_cb = callback;
	sa->disabled_user_data = user_data;

	return SOFTAP_ERROR_NONE;
}

API int softap_unset_disabled_cb(softap_h softap)
{
	_retvm_if(softap == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(softap) is NULL\n");

	__softap_h *sa = (__softap_h *) softap;

	sa->disabled_cb = NULL;
	sa->disabled_user_data = NULL;

	return SOFTAP_ERROR_NONE;
}

API int softap_set_client_connection_state_changed_cb(softap_h softap, softap_client_connection_state_changed_cb callback, void *user_data)
{
	_retvm_if(softap == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(softap) is NULL\n");
	_retvm_if(callback == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(callback) is NULL\n");

	__softap_h *sa = (__softap_h *)softap;

	sa->changed_cb = callback;
	sa->changed_user_data = user_data;

	return SOFTAP_ERROR_NONE;
}

API int softap_unset_client_connection_state_changed_cb(softap_h softap)
{
	_retvm_if(softap == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(softap) is NULL\n");

	__softap_h *sa = (__softap_h *)softap;

	sa->changed_cb = NULL;
	sa->changed_user_data = NULL;

	return SOFTAP_ERROR_NONE;
}


API int softap_set_security_type_changed_cb(softap_h softap, softap_security_type_changed_cb callback, void *user_data)
{
	_retvm_if(softap == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(softap) is NULL\n");
	_retvm_if(callback == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(callback) is NULL\n");

	__softap_h *sa = (__softap_h *)softap;

	sa->security_type_changed_cb = callback;
	sa->security_type_user_data = user_data;

	return SOFTAP_ERROR_NONE;
}

API int softap_unset_security_type_changed_cb(softap_h softap)
{
	_retvm_if(softap == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(softap) is NULL\n");

	__softap_h *sa = (__softap_h *)softap;

	sa->security_type_changed_cb = NULL;
	sa->security_type_user_data = NULL;

	return SOFTAP_ERROR_NONE;
}

API int softap_set_ssid_visibility_changed_cb(softap_h softap, softap_ssid_visibility_changed_cb callback, void *user_data)
{
	_retvm_if(softap == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(softap) is NULL\n");
	_retvm_if(callback == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(callback) is NULL\n");

	__softap_h *sa = (__softap_h *)softap;

	sa->ssid_visibility_changed_cb = callback;
	sa->ssid_visibility_user_data = user_data;

	return SOFTAP_ERROR_NONE;
}

API int softap_unset_ssid_visibility_changed_cb(softap_h softap)
{
	_retvm_if(softap == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(softap) is NULL\n");

	__softap_h *sa = (__softap_h *)softap;

	sa->ssid_visibility_changed_cb = NULL;
	sa->ssid_visibility_user_data = NULL;

	return SOFTAP_ERROR_NONE;
}

API int softap_set_passphrase_changed_cb(softap_h softap, softap_passphrase_changed_cb callback, void *user_data)
{
	_retvm_if(softap == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(softap) is NULL\n");
	_retvm_if(callback == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(callback) is NULL\n");

	__softap_h *sa = (__softap_h *)softap;

	sa->passphrase_changed_cb = callback;
	sa->passphrase_user_data = user_data;

	return SOFTAP_ERROR_NONE;
}

API int softap_unset_passphrase_changed_cb(softap_h softap)
{
	_retvm_if(softap == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(softap) is NULL\n");

	__softap_h *sa = (__softap_h *)softap;

	sa->passphrase_changed_cb = NULL;
	sa->passphrase_user_data = NULL;

	return SOFTAP_ERROR_NONE;
}

API int softap_set_security_type(softap_h softap, softap_security_type_e type)
{
	_retvm_if(softap == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(softap) is NULL\n");

	__softap_h *sa = (__softap_h *) softap;
	softap_error_e ret = SOFTAP_ERROR_NONE;

	ret = __set_security_type(type);
	if (ret == SOFTAP_ERROR_NONE) {

		__send_dbus_signal(sa->client_bus,
				SIGNAL_NAME_SECURITY_TYPE_CHANGED,
				type == SOFTAP_SECURITY_TYPE_NONE ?
				SOFTAP_SECURITY_TYPE_OPEN_STR :
				SOFTAP_SECURITY_TYPE_WPA2_PSK_STR);
	}
	return ret;
}


API int softap_get_security_type(softap_h softap, softap_security_type_e *type)
{
	_retvm_if(softap == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
				"parameter(softap) is NULL\n");
	_retvm_if(type == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
				"parameter(type) is NULL\n");

	return __get_security_type(type);
}

API int softap_set_ssid(softap_h softap, const char *ssid)
{
	_retvm_if(softap == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(softap) is NULL\n");
	_retvm_if(ssid == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(ssid) is NULL\n");

	__softap_h *sa = (__softap_h *) softap;
	char *p_ssid = NULL;
	int ssid_len = 0;

	ssid_len = strlen(ssid);
	if (ssid_len > SOFTAP_SSID_MAX_LEN) {
		ERR("parameter(ssid) is too long");
		return SOFTAP_ERROR_INVALID_PARAMETER;
	}

	p_ssid = strdup(ssid);
	if (p_ssid == NULL) {
		ERR("strdup failed\n");
		return SOFTAP_ERROR_OUT_OF_MEMORY;
	}

	if (sa->ssid)
		g_free(sa->ssid);
	sa->ssid = p_ssid;

	return SOFTAP_ERROR_NONE;
}

API int softap_get_ssid(softap_h softap, char **ssid)
{
	_retvm_if(softap == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(softap) is NULL\n");
	_retvm_if(ssid == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(ssid) is NULL\n");

	__softap_h *sa = (__softap_h *) softap;

	char val[SOFTAP_SSID_MAX_LEN + 1] = {0, };
	bool enable;

	softap_is_enabled(softap, &enable);

	if (!enable) {
		if (sa->ssid != NULL) {
			DBG("Private SSID is set\n");
			*ssid = strdup(sa->ssid);
		} else {
			if (__get_ssid_from_vconf(VCONFKEY_SETAPPL_DEVICE_NAME_STR,
						val, sizeof(val)) == false) {
				return SOFTAP_ERROR_OPERATION_FAILED;
			}
			*ssid = strdup(val);
		}
	} else {
		if (__get_ssid_from_vconf(VCONFKEY_SOFTAP_SSID,
					val, sizeof(val)) == false) {
			return SOFTAP_ERROR_OPERATION_FAILED;
		}
		*ssid = strdup(val);
	}
	if (*ssid == NULL) {
		ERR("strdup is failed\n");
		return SOFTAP_ERROR_OUT_OF_MEMORY;
	}

	return SOFTAP_ERROR_NONE;
}

API int softap_set_ssid_visibility(softap_h softap, bool visible)
{
	_retvm_if(softap == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(softap) is NULL\n");

	__softap_h *sa = (__softap_h *) softap;
	softap_error_e ret = SOFTAP_ERROR_NONE;

	ret = __set_visibility(visible);
	if (ret == SOFTAP_ERROR_NONE) {
		__send_dbus_signal(sa->client_bus,
				SIGNAL_NAME_SSID_VISIBILITY_CHANGED,
				visible ? SIGNAL_MSG_SSID_VISIBLE :
				SIGNAL_MSG_SSID_HIDE);
	}

	return ret;
}

API int softap_get_ssid_visibility(softap_h softap, bool *visible)
{
	_retvm_if(softap == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(softap) is NULL\n");
	_retvm_if(visible == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(visible) is NULL\n");

	return __get_visibility(visible);
}

API int softap_set_passphrase(softap_h softap, const char *passphrase)
{
	_retvm_if(softap == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(softap) is NULL\n");
	_retvm_if(passphrase == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(passphrase) is NULL\n");

	__softap_h *sa = (__softap_h *)softap;
	int passphrase_len = 0;

	DBG("+");
	passphrase_len = strlen(passphrase);
	if (passphrase_len < SOFTAP_KEY_MIN_LEN ||
			passphrase_len > SOFTAP_KEY_MAX_LEN) {
		ERR("parameter(passphrase) is too short or long\n");
		return SOFTAP_ERROR_INVALID_PARAMETER;
	}

	g_strlcpy(sa->passphrase, passphrase, sizeof(sa->passphrase));

	DBG("-");
	return SOFTAP_ERROR_NONE;
}

API int softap_get_passphrase(softap_h softap, char **passphrase)
{
	_retvm_if(softap == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(softap) is NULL\n");
	_retvm_if(passphrase == NULL, SOFTAP_ERROR_INVALID_PARAMETER,
			"parameter(passphrase) is NULL\n");

	char val[SOFTAP_KEY_MAX_LEN + 1] = {0, };
	bool enable;

	softap_is_enabled(softap, &enable);

	g_strlcpy(val, vconf_get_str(VCONFKEY_SOFTAP_KEY), sizeof(val));
	*passphrase = strdup(val);

	if (*passphrase == NULL) {
		ERR("strdup is failed\n");
		return SOFTAP_ERROR_OUT_OF_MEMORY;
	}

	return SOFTAP_ERROR_NONE;
}
