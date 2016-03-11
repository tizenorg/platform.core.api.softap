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

static void __register_cbs(void)
{
	int ret = SOFTAP_ERROR_NONE;

	ret = softap_set_enabled_cb(sa, __enabled_cb, NULL);
	if (ret != SOFTAP_ERROR_NONE)
		printf("Fail to set enabled callback!!\n");

	ret = softap_set_disabled_cb(sa, __disabled_cb, NULL);
	if (ret != SOFTAP_ERROR_NONE)
		printf("Fail to set disabled callback!!\n");

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
		printf("Fail to set disabled callback!!\n");

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
	char *mac_address = NULL;
	char *interface_name = NULL;
	char *ip_address = NULL;
	char *gateway_address = NULL;
	char *subnet_mask = NULL;

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


	printf("* MAC address: %s\n", mac_address);
	printf("* Network Interface: %s\n", interface_name);
	printf("* IP address: %s\n", ip_address);
	printf("* gateway_address: %s\n", gateway_address);
	printf("* subnet_mask: %s\n", subnet_mask);

	if (mac_address)	g_free(mac_address);
	if (interface_name)	g_free(interface_name);
	if (ip_address)		g_free(ip_address);
	if (gateway_address)	g_free(gateway_address);
	if (subnet_mask)	g_free(subnet_mask);

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
	}

	if (rv == 1)
		printf("Operation succeeded!\n");
	else
		printf("Operation failed!\n");

	return true;
}
