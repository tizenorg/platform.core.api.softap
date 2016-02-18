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

#ifndef __SOFTAP_PRIVATE_H__
#define __SOFTAP_PRIVATE_H__

#define LOG_TAG	"CAPI_NETWORK_SOFTAP"

#include <glib.h>
#include <dlog.h>
#include <gio/gio.h>
#include "softap.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef API
#define API __attribute__ ((visibility("default")))
#endif

#ifndef DEPRECATED_API
#define DEPRECATED_API __attribute__ ((deprecated))
#endif

#define DBG(fmt, args...)	LOGD(fmt, ##args)
#define WARN(fmt, args...)	LOGW(fmt, ##args)
#define ERR(fmt, args...)	LOGE(fmt, ##args)
#define SDBG(fmt, args...)	SECURE_LOGD(fmt, ##args)
#define SERR(fmt, args...)	SECURE_LOGE(fmt, ##args)

#define _warn_if(expr, fmt, arg...) do { \
		if (expr) { \
			WARN(fmt, ##arg); \
		} \
	} while (0)

#define _ret_if(expr) do { \
		if (expr) { \
			return; \
		} \
	} while (0)

#define _retv_if(expr, val) do { \
		if (expr) { \
			return (val); \
		} \
	} while (0)

#define _retm_if(expr, fmt, arg...) do { \
		if (expr) { \
			ERR(fmt, ##arg); \
			return; \
		} \
	} while (0)

#define _retvm_if(expr, val, fmt, arg...) do { \
		if (expr) { \
			ERR(fmt, ##arg); \
			return (val); \
		} \
	} while (0)

#define CHECK_FEATURE_SUPPORTED(...) \
	do { \
		int rv = _softap_check_feature_supported(__VA_ARGS__, NULL); \
		if(rv != SOFTAP_ERROR_NONE) { \
			return rv; \
		} \
	} while (0)

int _softap_check_feature_supported(const char* feature, ...);

/**
* Start of mobileap-agent common values
* When these values are changed, mobileap-agent should be also changed.
* But some of those will be removed.
*/

/*
* from mobileap_lib.h
*/

/**
* Common configuration
*/
#define SOFTAP_STR_INFO_LEN		20	/**< length of the ip or mac address */

/**
* Mobile AP error code
*/
typedef enum {
	MOBILE_AP_ERROR_NONE,			/**< No error */
	MOBILE_AP_ERROR_RESOURCE,		/**< Socket creation error, file open error */
	MOBILE_AP_ERROR_INTERNAL,		/**< Driver related error */
	MOBILE_AP_ERROR_INVALID_PARAM,		/**< Invalid parameter */
	MOBILE_AP_ERROR_ALREADY_ENABLED,	/**< Mobile AP is already ON */
	MOBILE_AP_ERROR_NOT_ENABLED,		/**< Mobile AP is not ON, so cannot be disabled */
	MOBILE_AP_ERROR_NET_OPEN,		/**< PDP network open error */
	MOBILE_AP_ERROR_NET_CLOSE,		/**< PDP network close error */
	MOBILE_AP_ERROR_DHCP,			/**< DHCP error */
	MOBILE_AP_ERROR_IN_PROGRESS,		/**< Request is in progress */
	MOBILE_AP_ERROR_NOT_PERMITTED,		/**< Operation is not permitted */
	MOBILE_AP_ERROR_PERMISSION_DENIED,  /**< Permission Denied */

	MOBILE_AP_ERROR_MAX
} mobile_ap_error_code_e;

/**
* Event type on callback
*/
typedef enum {
	MOBILE_AP_ENABLE_CFM = 0,
	MOBILE_AP_DISABLE_CFM = 1,

	MOBILE_AP_ENABLE_WIFI_AP_CFM = 9,
	MOBILE_AP_DISABLE_WIFI_AP_CFM,

	MOBILE_AP_GET_STATION_INFO_CFM,
	MOBILE_AP_GET_DATA_PACKET_USAGE_CFM
} mobile_ap_event_e;

typedef enum {
	E_SIGNAL_LOW_BATTERY_MODE = 12,
	E_SIGNAL_FLIGHT_MODE,
	E_SIGNAL_SECURITY_TYPE_CHANGED,
	E_SIGNAL_SSID_VISIBILITY_CHANGED,
	E_SIGNAL_PASSPHRASE_CHANGED,
	E_SIGNAL_DHCP_STATUS,
	E_SIGNAL_SOFTAP_ON,
	E_SIGNAL_SOFTAP_OFF,
	E_SIGNAL_MAX
} mobile_ap_sig_e;

#define SOFTAP_SERVICE_OBJECT_PATH	"/MobileapAgent"
#define SOFTAP_SERVICE_NAME		"org.tizen.MobileapAgent"
#define SOFTAP_SERVICE_INTERFACE	"org.tizen.softap"

#define SOFTAP_SIGNAL_MATCH_RULE	"type='signal',interface='org.tizen.softap'"
#define SOFTAP_SIGNAL_NAME_LEN	64

#define SIGNAL_NAME_STA_CONNECT		"sta_connected"
#define SIGNAL_NAME_STA_DISCONNECT	"sta_disconnected"
#define SIGNAL_NAME_SOFTAP_ON		"softap_on"
#define SIGNAL_NAME_SOFTAP_OFF		"softap_off"
#define SIGNAL_NAME_NO_DATA_TIMEOUT	"no_data_timeout"
#define SIGNAL_NAME_LOW_BATTERY_MODE	"low_batt_mode"
#define SIGNAL_NAME_FLIGHT_MODE		"flight_mode"
#define SIGNAL_NAME_SECURITY_TYPE_CHANGED	"security_type_changed"
#define SIGNAL_NAME_SSID_VISIBILITY_CHANGED	"ssid_visibility_changed"
#define SIGNAL_NAME_PASSPHRASE_CHANGED		"passphrase_changed"
#define SIGNAL_NAME_DHCP_STATUS		"dhcp_status"

#define SIGNAL_MSG_NOT_AVAIL_INTERFACE	"Interface is not available"
#define SIGNAL_MSG_TIMEOUT		"There is no connection for a while"
#define SIGNAL_MSG_SSID_VISIBLE		"ssid_visible"
#define SIGNAL_MSG_SSID_HIDE		"ssid_hide"

/* Network Interface */
#define SOFTAP_SUBNET_MASK		"255.255.255.0"

#define SOFTAP_IF		"wlan0"
#define SOFTAP_GATEWAY		"192.168.43.1"

#define SOFTAP_SSID_MAX_LEN	32	/**< Maximum length of ssid */
#define SOFTAP_KEY_MIN_LEN	8	/**< Minimum length of wifi key */
#define SOFTAP_KEY_MAX_LEN	64	/**< Maximum length of wifi key */
#define SOFTAP_HASH_KEY_MAX_LEN	64

#define SOFTAP_MODE_MAX_LEN 10  /**< Maximum length of mode */

#define VCONFKEY_MOBILE_HOTSPOT_SSID	"memory/private/mobileap-agent/ssid"
#define MAX_ALIAS_LEN	256

/**
* End of mobileap-agent common values
*/

#define SOFTAP_DEFAULT_SSID	"Tizen"
#define SOFTAP_SECURITY_TYPE_OPEN_STR		"open"
#define SOFTAP_SECURITY_TYPE_WPA2_PSK_STR	"wpa2-psk"
#define SOFTAP_ERROR_RECOVERY_MAX			3
#define SECURITY_TYPE_LEN	32
#define PSK_ITERATION_COUNT	4096

typedef void(*__handle_cb_t)(GDBusConnection *connection, const gchar *sender_name,
		const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
		GVariant *parameters, gpointer user_data);

typedef struct {
	int sig_id;
	char name[SOFTAP_SIGNAL_NAME_LEN];
	__handle_cb_t cb;
} __softap_sig_t;

typedef struct {
	/* GDBus */
	GDBusConnection *client_bus;
	GDBusProxy *client_bus_proxy;
	GCancellable *cancellable;

	/* Callbacks*/
	softap_enabled_cb enabled_cb;
	void *enabled_user_data;
	softap_disabled_cb disabled_cb;
	void *disabled_user_data;
	softap_client_connection_state_changed_cb changed_cb;
	void *changed_user_data;
	softap_security_type_changed_cb security_type_changed_cb;
	void *security_type_user_data;
	softap_ssid_visibility_changed_cb ssid_visibility_changed_cb;
	void *ssid_visibility_user_data;
	softap_passphrase_changed_cb passphrase_changed_cb;
	void *passphrase_user_data;
	softap_settings_reloaded_cb settings_reloaded_cb;
	void *settings_reloaded_user_data;

	/* Settings */
	char *ssid;
	char passphrase[SOFTAP_KEY_MAX_LEN + 1];
	bool visibility;
	softap_security_type_e sec_type;
} __softap_h;

typedef struct {
	char ssid[SOFTAP_SSID_MAX_LEN];
	char key[SOFTAP_KEY_MAX_LEN + 1];
	softap_security_type_e sec_type;
	bool visibility;
} _softap_settings_t;

#ifdef __cplusplus
}
#endif

#endif /* __SOFTAP_PRIVATE_H__ */
