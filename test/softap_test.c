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
#include <unistd.h>
#include <glib.h>
#include <glib-object.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <vconf.h>
#include <time.h>

#include "softap.h"

#define DISABLE_REASON_TEXT_LEN	64
#define COMMON_STR_BUF_LEN	32

gboolean test_thread(GIOChannel *source, GIOCondition condition, gpointer data);

softap_h sa = NULL;

static const char *__convert_disabled_code_to_string(const softap_disabled_cause_e code)
{
	static char str_buf[DISABLE_REASON_TEXT_LEN] = {0, };

	switch (code) {
	case SOFTAP_DISABLED_BY_FLIGHT_MODE:
		strncpy(str_buf, "disabled due to flight mode on", sizeof(str_buf));
		break;

	case SOFTAP_DISABLED_BY_LOW_BATTERY:
		strncpy(str_buf, "disabled due to low battery", sizeof(str_buf));
		break;

	case SOFTAP_DISABLED_BY_NETWORK_CLOSE:
		strncpy(str_buf, "disabled due to pdp network close", sizeof(str_buf));
		break;

	case SOFTAP_DISABLED_BY_TIMEOUT:
		strncpy(str_buf, "disabled due to timeout", sizeof(str_buf));
		break;

	case SOFTAP_DISABLED_BY_OTHERS:
		strncpy(str_buf, "disabled by other apps", sizeof(str_buf));
		break;

	case SOFTAP_DISABLED_BY_REQUEST:
		strncpy(str_buf, "disabled by my request", sizeof(str_buf));
		break;

	case SOFTAP_DISABLED_BY_WIFI_ON:
		strncpy(str_buf, "disabled by Wi-Fi station on", sizeof(str_buf));
		break;

	default:
		strncpy(str_buf, "disabled by unknown reason", sizeof(str_buf));
		break;
	}

	return str_buf;
}

/* Callback functions */
static void __enabled_cb(softap_error_e error, bool is_requested, void *data)
{
	if (error != SOFTAP_ERROR_NONE) {
		if (!is_requested)
			return;

		printf("Soft AP is not enabled. error code[0x%X]\n", error);
		return;
	}

	if (is_requested)
		printf("Soft AP is enabled successfully\n");
	else
		printf("Soft AP is enabled by other app\n");

	return;
}

static void __disabled_cb(softap_error_e error, softap_disabled_cause_e code, void *data)
{
	if (error != SOFTAP_ERROR_NONE) {
		if (code != SOFTAP_DISABLED_BY_REQUEST)
			return;

		printf("Soft AP is not disabled. error code[0x%X]\n", error);
		return;
	}

	printf("Soft AP is %s\n", __convert_disabled_code_to_string(code));

	return;
}

static void __settings_reloaded_cb(softap_error_e result, void *user_data)
{
	g_print("__settings_reloaded_cb\n");

	if (result != SOFTAP_ERROR_NONE) {
		g_print("softap_reload_settings is failed. error[0x%X]\n", result);
		return;
	}

	printf("## Soft AP setting is reloaded\n");

	return;
}

static void __security_changed_cb(softap_security_type_e changed_type, void *user_data)
{
	g_print("Security type is changed to [%s]\n",
			changed_type == SOFTAP_SECURITY_TYPE_NONE ?
				"open" : "wpa2-psk");
		return;
}

static void __ssid_visibility_changed_cb(bool changed_visible, void *user_data)
{
	g_print("SSID visibility forSoftap changed to [%s]\n",
			changed_visible ? "visible" : "invisible");
	return;
}

static bool __clients_foreach_cb(softap_client_h client, void *data)
{
	softap_client_h clone = NULL;
	char *ip_address = NULL;
	char *mac_address = NULL;
	char *hostname = NULL;
	time_t timestamp;
	struct tm *t;

	/* Clone internal information */
	if (softap_client_clone(&clone, client) != SOFTAP_ERROR_NONE) {
		g_print("softap_client_clone is failed\n");
		return false;
	}

	/* Get information */
	if (softap_client_get_ip_address(clone, SOFTAP_ADDRESS_FAMILY_IPV4, &ip_address) != SOFTAP_ERROR_NONE)
		g_print("softap_client_get_ip_address is failed\n");

	if (softap_client_get_mac_address(clone, &mac_address) != SOFTAP_ERROR_NONE)
		g_print("softap_client_get_mac_address is failed\n");

	if (softap_client_get_name(clone, &hostname) != SOFTAP_ERROR_NONE)
		g_print("softap_client_get_hostname is failed\n");

	if (softap_client_get_time(clone, &timestamp) != SOFTAP_ERROR_NONE)
		g_print("softap_client_get_hostname is failed\n");
	/* End of getting information */

	t = localtime(&timestamp);

	g_print("\n< Client Info. >\n");
	g_print("\tIP Address %s\n", ip_address);
	g_print("\tMAC Address : %s\n", mac_address);
	g_print("\tHostname : %s\n", hostname);
	g_print("\tTime stamp : %04d-%02d-%02d %02d:%02d:%02d",
			t->tm_year + 1900, t->tm_mon + 1,
			t->tm_mday, t->tm_hour,
			t->tm_min, t->tm_sec);

	/* Destroy cloned objects */
	if (ip_address)
		free(ip_address);
	if (mac_address)
		free(mac_address);
	if (hostname)
		free(hostname);

	softap_client_destroy(clone);

	/* Continue iteration */
	return true;
}

static void __connection_state_changed_cb(softap_client_h client, bool open, void *data)
{
	softap_client_h clone = NULL;
	char *ip_address = NULL;
	char *mac_address = NULL;
	char *hostname = NULL;

	softap_client_clone(&clone, client);
	if (clone == NULL) {
		g_print("tetheirng_client_clone is failed\n");
		return;
	}

	softap_client_get_ip_address(clone,
			SOFTAP_ADDRESS_FAMILY_IPV4, &ip_address);
	softap_client_get_mac_address(clone, &mac_address);
	softap_client_get_name(clone, &hostname);

	if (open) {
		g_print("## New station IP [%s], MAC [%s], hostname [%s]\n",
				ip_address, mac_address, hostname);
	} else {
		g_print("## Disconnected station IP [%s], MAC [%s], hostname [%s]\n",
				ip_address, mac_address, hostname);
	}

	if (ip_address)
		free(ip_address);
	if (mac_address)
		free(mac_address);
	if (hostname)
		free(hostname);

	softap_client_destroy(clone);

	return;
}

static void __register_cbs(void)
{
	int ret = SOFTAP_ERROR_NONE;

	ret = softap_set_enabled_cb(sa, __enabled_cb, NULL);
	if (ret != SOFTAP_ERROR_NONE)
		printf("Fail to set enabled callback!!\n");

	ret = softap_set_disabled_cb(sa, __disabled_cb, NULL);
	if (ret != SOFTAP_ERROR_NONE)
		printf("Fail to set disabled callback!!\n");

	ret = softap_set_security_type_changed_cb(sa, __security_changed_cb, NULL);
	if (ret != SOFTAP_ERROR_NONE)
		printf("Fail to set security changed callback!!\n");

	ret = softap_set_ssid_visibility_changed_cb(sa, __ssid_visibility_changed_cb, NULL);
	if (ret != SOFTAP_ERROR_NONE)
		printf("Fail to set visibility changed callback!!\n");

	ret = softap_set_client_connection_state_changed_cb(sa, __connection_state_changed_cb, NULL);
	if (ret != SOFTAP_ERROR_NONE)
		printf("Fail to set visibility changed callback!!\n");

	return;
}

static void __deregister_cbs(void)
{
	int ret = SOFTAP_ERROR_NONE;

	ret = softap_unset_enabled_cb(sa);
	if (ret != SOFTAP_ERROR_NONE)
		printf("Fail to unset enabled callback!!\n");

	ret = softap_unset_disabled_cb(sa);
	if (ret != SOFTAP_ERROR_NONE)
		printf("Fail to unset disabled callback!!\n");

	ret = softap_unset_security_type_changed_cb(sa);
	if (ret != SOFTAP_ERROR_NONE)
		printf("Fail to unset security changed callback!!\n");

	ret = softap_unset_ssid_visibility_changed_cb(sa);
	if (ret != SOFTAP_ERROR_NONE)
		printf("Fail to unset visibility changed callback!!\n");

	ret = softap_unset_client_connection_state_changed_cb(sa);
	if (ret != SOFTAP_ERROR_NONE)
		printf("Fail to unset visibility changed callback!!\n");

	return;
}


static int test_softap_create(void)
{
	softap_create(&sa);
	__register_cbs();

	return 1;
}

static int test_softap_destroy(void)
{
	softap_destroy(sa);
	__deregister_cbs();

	return 1;
}

static int test_softap_enable(void)
{
	int ret = SOFTAP_ERROR_NONE;

	ret = softap_enable(sa);
	if (ret != SOFTAP_ERROR_NONE)
		return 0;

	return 1;
}

static int test_softap_disable(void)
{
	int ret = SOFTAP_ERROR_NONE;

	ret = softap_disable(sa);
	if (ret != SOFTAP_ERROR_NONE)
		return 0;

	return 1;
}

static int test_softap_is_enabled(void)
{
	int ret = SOFTAP_ERROR_NONE;
	bool enabled = false;

	ret = softap_is_enabled(sa, &enabled);
	if (ret != SOFTAP_ERROR_NONE)
		return 0;

	printf("Soft AP is %s\n", enabled ? "enabled" : "disabled");

	return 1;
}

static int test_softap_get_settings(void)
{
	int ret = SOFTAP_ERROR_NONE;
	char *ssid = NULL;
	char *passphrase = NULL;
	char *mac_address = NULL;
	char *interface_name = NULL;
	char *ip_address = NULL;
	char *gateway_address = NULL;
	char *subnet_mask = NULL;
	bool visible = 0;
	softap_security_type_e security_type = SOFTAP_SECURITY_TYPE_NONE;

	ret = softap_get_ssid(sa, &ssid);
	if (ret != SOFTAP_ERROR_NONE)
		return 0;

	ret = softap_get_passphrase(sa, &passphrase);
	if (ret != SOFTAP_ERROR_NONE)
		return 0;

	ret = softap_get_ssid_visibility(sa, &visible);
	if (ret != SOFTAP_ERROR_NONE)
		return 0;

	ret = softap_get_security_type(sa, &security_type);
	if (ret != SOFTAP_ERROR_NONE)
		return 0;

	ret = softap_get_mac_address(sa, &mac_address);
	if (ret != SOFTAP_ERROR_NONE)
		return 0;

	ret = softap_get_network_interface_name(sa, &interface_name);
	if (ret != SOFTAP_ERROR_NONE)
		return 0;

	ret = softap_get_ip_address(sa, SOFTAP_ADDRESS_FAMILY_IPV4, &ip_address);
	if (ret != SOFTAP_ERROR_NONE)
		return 0;

	ret = softap_get_gateway_address(sa, SOFTAP_ADDRESS_FAMILY_IPV4, &gateway_address);
	if (ret != SOFTAP_ERROR_NONE)
		return 0;

	ret = softap_get_subnet_mask(sa, SOFTAP_ADDRESS_FAMILY_IPV4, &subnet_mask);
	if (ret != SOFTAP_ERROR_NONE)
		return 0;


	printf("* SSID: %s\n", ssid);
	printf("* SSID visibility: %d\n", visible);
	printf("* Security type: %d\n", security_type);
	printf("* Passphrase: %s\n", passphrase);
	printf("* MAC address: %s\n", mac_address);
	printf("* Network Interface: %s\n", interface_name);
	printf("* IP address: %s\n", ip_address);
	printf("* gateway_address: %s\n", gateway_address);
	printf("* subnet_mask: %s\n", subnet_mask);

	if (ssid)	g_free(ssid);
	if (passphrase)	g_free(passphrase);
	if (mac_address)	g_free(mac_address);
	if (interface_name)	g_free(interface_name);
	if (ip_address)		g_free(ip_address);
	if (gateway_address)	g_free(gateway_address);
	if (subnet_mask)	g_free(subnet_mask);

	return 1;
}

static int test_softap_set_ssid(void)
{
	int ret;
	char ssid[100];

	printf("Input SSID for Softap: ");
	ret = scanf("%99s", ssid);
	if (ret < 0) {
		printf("scanf is failed!!\n");
		return 0;
	}

	ret = softap_set_ssid(sa, ssid);
	if (ret != SOFTAP_ERROR_NONE)
		return 0;

	return 1;
}

static int test_softap_set_ssid_visibility(void)
{
	int ret;
	int visibility;

	printf("Input visibility for Soft AP (0:invisible, 1:visible)");
	ret = scanf("%9d", &visibility);
	if (ret < 0) {
		printf("scanf is failed!!\n");
		return 0;
	}

	ret = softap_set_ssid_visibility(sa, visibility);
	if (ret != SOFTAP_ERROR_NONE)
		return 0;

	return 1;
}

static int test_softap_set_security_type(void)
{
	int ret;
	int security_type;

	printf("Input security type for Soft AP (0:NONE, 1:WPA2_PSK)");
	ret = scanf("%9d", &security_type);
	if (ret < 0) {
		printf("scanf is failed!!\n");
		return -1;
	}

	ret = softap_set_security_type(sa, security_type);
	if (ret != SOFTAP_ERROR_NONE)
		return 0;

	return 1;
}

static int test_softap_set_passphrase(void)
{
	int ret;
	char passphrase[65];

	printf("Input passphrase for Softap: ");
	ret = scanf("%64s", passphrase);
	if (ret < 0) {
		printf("scanf is failed!!\n");
		return 0;
	}

	ret = softap_set_passphrase(sa, passphrase);
	if (ret != SOFTAP_ERROR_NONE)
		return 0;

	return 1;
}

static int test_softap_reload_settings(void)
{
	int ret = softap_reload_settings(sa, __settings_reloaded_cb, NULL);

	if (ret != SOFTAP_ERROR_NONE)
		return 0;

	return 1;
}

static int test_softap_get_client_info(void)
{
	int ret;

	ret = softap_foreach_connected_clients(sa, __clients_foreach_cb, NULL);

	if (ret != SOFTAP_ERROR_NONE)
			return 0;

	return 1;
}

int main(int argc, char **argv)
{
	GMainLoop *mainloop;

#if !GLIB_CHECK_VERSION(2, 36, 0)
	g_type_init();
#endif
	mainloop = g_main_loop_new(NULL, false);

	GIOChannel *channel = g_io_channel_unix_new(0);
	g_io_add_watch(channel, (G_IO_IN|G_IO_ERR|G_IO_HUP|G_IO_NVAL), test_thread, NULL);
	printf("Test Thread created...\n");
	g_main_loop_run(mainloop);

	return 0;
}

gboolean test_thread(GIOChannel *source, GIOCondition condition, gpointer data)
{
	int rv;
	char a[10];

	printf("Event received from stdin\n");

	rv = read(0, a, 10);

	if (rv <= 0 || a[0] == '0')
		exit(1);

	if (a[0] == '\n' || a[0] == '\r') {
		printf("\n\n Network Connection API Test App\n\n");
		printf("Options..\n");
		printf("1       - SoftAP create and set callbacks\n");
		printf("2       - SoftAP destroy\n");
		printf("3       - SoftAP enable\n");
		printf("4       - SoftAP disable\n");
		printf("5       - Is Soft AP enabled?\n");
		printf("6       - Get Soft AP settings\n");
		printf("7       - Set Soft AP SSID\n");
		printf("8       - Set Soft AP SSID visibility\n");
		printf("9       - Set Soft AP security type\n");
		printf("a       - Set Soft AP passpharse\n");
		printf("b       - Get Soft AP client information\n");
		printf("c       - SoftAP reload settings\n");
		printf("0       - Exit \n");
		printf("ENTER  - Show options menu.......\n");
	}

	switch (a[0]) {
	case '1':
		rv = test_softap_create();
		break;
	case '2':
		rv = test_softap_destroy();
		break;
	case '3':
		rv = test_softap_enable();
		break;
	case '4':
		rv = test_softap_disable();
		break;
	case '5':
		rv = test_softap_is_enabled();
		break;
	case '6':
		rv = test_softap_get_settings();
		break;
	case '7':
		rv = test_softap_set_ssid();
		break;
	case '8':
		rv = test_softap_set_ssid_visibility();
		break;
	case '9':
		rv = test_softap_set_security_type();
		break;
	case 'a':
		rv = test_softap_set_passphrase();
		break;
	case 'b':
		rv = test_softap_get_client_info();
		break;
	case 'c':
		rv = test_softap_reload_settings();
		break;
	}

	if (rv == 1)
		printf("Operation succeeded!\n");
	else
		printf("Operation failed!\n");

	return true;
}
