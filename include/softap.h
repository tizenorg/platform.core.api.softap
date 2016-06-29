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

#ifndef __TIZEN_NETWORK_SOFTAP_H__
#define __TIZEN_NETWORK_SOFTAP_H__

#include <tizen.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file softap.h
 */

/**
 * @addtogroup CAPI_NETWORK_SOFTAP_MANAGER_MODULE
 * @{
 */

/**
 * @brief The softap handle.
 * @since_tizen 3.0
 */
typedef void * softap_h;

#ifndef TIZEN_ERROR_SOFTAP
#define TIZEN_ERROR_SOFTAP -0x03200000
#endif

/**
 * @brief Enumeration for the softap.
 * @since_tizen 3.0
 */
typedef enum {
    SOFTAP_ERROR_NONE = TIZEN_ERROR_NONE,  /**< Successful */
    SOFTAP_ERROR_NOT_PERMITTED = TIZEN_ERROR_NOT_PERMITTED,  /**< Operation not permitted */
    SOFTAP_ERROR_INVALID_PARAMETER = TIZEN_ERROR_INVALID_PARAMETER,  /**< Invalid parameter */
    SOFTAP_ERROR_OUT_OF_MEMORY = TIZEN_ERROR_OUT_OF_MEMORY,  /**< Out of memory */
    SOFTAP_ERROR_RESOURCE_BUSY = TIZEN_ERROR_RESOURCE_BUSY,  /**< Resource busy */
    SOFTAP_ERROR_OPERATION_FAILED = TIZEN_ERROR_SOFTAP | 0x0501,  /**< Operation failed */
    SOFTAP_ERROR_INVALID_OPERATION = TIZEN_ERROR_INVALID_OPERATION, /**< Invalid operation */
    SOFTAP_ERROR_NOT_SUPPORTED = TIZEN_ERROR_NOT_SUPPORTED, /**< API is not supported */
    SOFTAP_ERROR_PERMISSION_DENIED = TIZEN_ERROR_PERMISSION_DENIED,  /**< Permission denied */
} softap_error_e;

/**
 * @brief Enumeration for the cause of disabling the softap.
 * @since_tizen 3.0
 */
typedef enum
{
    SOFTAP_DISABLED_BY_FLIGHT_MODE = 0,  /**< Disabled due to flight mode */
    SOFTAP_DISABLED_BY_LOW_BATTERY,  /**< Disabled due to low battery */
    SOFTAP_DISABLED_BY_NETWORK_CLOSE,  /**< Disabled due to pdp network close */
    SOFTAP_DISABLED_BY_TIMEOUT,  /**< Disabled due to timeout */
    SOFTAP_DISABLED_BY_OTHERS,  /**< Disabled by other apps */
    SOFTAP_DISABLED_BY_REQUEST,  /**< Disabled by your request */
    SOFTAP_DISABLED_BY_WIFI_ON,  /**< Disabled due to Wi-Fi on */
} softap_disabled_cause_e;

/**
 * @}
 */


/**
 * @addtogroup CAPI_NETWORK_SOFTAP_MANAGER_MODULE
 * @{
 */

/**
 * @brief Enumeration for the Wi-Fi security.
 * @since_tizen 3.0
 */
typedef enum {
    SOFTAP_SECURITY_TYPE_NONE = 0,  /**< No Security type */
    SOFTAP_SECURITY_TYPE_WPA2_PSK,  /**< WPA2_PSK */
} softap_security_type_e;

/**
 * @}
 */


/**
 * @addtogroup CAPI_NETWORK_SOFTAP_CLIENT_MODULE
 * @{
 */

/**
 * @brief The softap client handle.
 * @since_tizen 3.0
 */
typedef void * softap_client_h;

/**
 * @brief Enumeration for address family.
 * @since_tizen 3.0
 */
typedef enum {
    SOFTAP_ADDRESS_FAMILY_IPV4 = 0,  /**< IPV4 Address type */
} softap_address_family_e;

/**
 * @}
 */


/**
 * @addtogroup CAPI_NETWORK_SOFTAP_MANAGER_MODULE
 * @{
 */

/**
 * @brief Called when the softap is enabled.
 * @since_tizen 3.0
 * @param[in]  result  The result of enabling the softap
 * @param[in]  is_requested  Indicates whether this change is requested
 * @param[in]  user_data  The user data passed from softap_set_enabled_cb()
 * @pre  If you register callback function using softap_set_enabled_cb(), this will be invoked when the softap is enabled.
 * @see	softap_enable()
 * @see	softap_unset_enabled_cb()
 */
typedef void (*softap_enabled_cb)(softap_error_e result, bool is_requested, void *user_data);

/**
 * @brief Called when the softap is disabled.
 * @since_tizen 3.0
 * @param[in]  result  The result of disabling the softap
 * @param[in]  cause  The cause of disabling
 * @param[in]  user_data  The user data passed from softap_set_disabled_cb()
 * @pre  If you register callback function using softap_set_disabled_cb(), this will be invoked when the softap is disabled.
 * @see	softap_set_disabled_cb()
 * @see	softap_unset_disabled_cb()
 */
typedef void (*softap_disabled_cb)(softap_error_e result, softap_disabled_cause_e cause, void *user_data);

/**
 * @brief Called when the connection state is changed.
 * @since_tizen 3.0
 * @remarks @a client is valid only in this function. In order to use it outside this function, a user must copy the client with softap_client_clone().
 * @param[in]  client  The client of which connection state is changed
 * @param[in]  opened  @c true when connection is opened, otherwise false
 * @param[in]  user_data  The user data passed from softap_set_client_connection_state_changed_cb()
 * @pre  If you register callback function using softap_set_client_connection_state_changed_cb(), this will be invoked when the connection state is changed.
 * @see	softap_set_client_connection_state_changed_cb()
 * @see	softap_unset_client_connection_state_changed_cb()
 */
typedef void (*softap_client_connection_state_changed_cb)(softap_client_h client, bool opened, void *user_data);

/**
 * @brief Called when you get the connected client repeatedly.
 * @since_tizen 3.0
 * @remarks @a client is valid only in this function. In order to use the client outside this function, a user must copy the client with softap_client_clone().
 * @param[in]  client  The connected client
 * @param[in]  user_data  The user data passed from the request function
 * @return  @c true to continue with the next iteration of the loop, \n @c false to break out of the loop
 * @pre  softap_foreach_connected_clients() will invoke this callback.
 * @see  softap_foreach_connected_clients()
 */
typedef bool(*softap_connected_client_cb)(softap_client_h client, void *user_data);

/**
 * @brief Called when the security type of Soft AP is changed.
 * @since_tizen 3.0
 * @param[in]  changed_type  The changed security type
 * @param[in]  user_data  The user data passed from the register function
 * @see	softap_set_security_type_changed_cb()
 * @see	softap_unset_security_type_changed_cb()
 */
typedef void (*softap_security_type_changed_cb)(softap_security_type_e changed_type, void *user_data);

/**
 * @brief Called when the visibility of SSID is changed.
 * @since_tizen 3.0
 * @param[in]  changed_visible  The changed visibility of SSID
 * @param[in]  user_data  The user data passed from the register function
 * @see	softap_set_ssid_visibility_changed_cb()
 * @see	softap_unset_ssid_visibility_changed_cb()
 */
typedef void (*softap_ssid_visibility_changed_cb)(bool changed_visible, void *user_data);

/**
 * @brief Called when the passphrase
 * @since_tizen 3.0
 * @param[in]  user_data  The user data passed from the register function
 * @see	softap_set_passphrase_changed_cb()
 * @see	softap_unset_passphrase_changed_cb()
 */
typedef void (*softap_passphrase_changed_cb)(void *user_data);

/**
 * @brief Called when Soft AP settings are reloaded.
 * @since_tizen 3.0
 * @param[in]  result  The result of reloading the settings
 * @param[in]  user_data  The user data passed from the request function
 * @pre  softap_reload_settings() will invoke this callback.
 */
typedef void (*softap_settings_reloaded_cb)(softap_error_e result, void *user_data);

/**
 * @brief Creates the handle for softap.
 * @since_tizen 3.0
 * @privlevel public
 * @privilege %http://tizen.org/privilege/softap
 * @remarks The @a softap must be released using softap_destroy().
 * @param[out]  softap A handle of a new mobile ap handle on success
 * @return  0 on success, otherwise a negative error value
 * @retval  #SOFTAP_ERROR_NONE  Successful
 * @retval  #SOFTAP_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #SOFTAP_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval  #SOFTAP_ERROR_NOT_SUPPORTED  API is not supported
 * @retval  #SOFTAP_ERROR_PERMISSION_DENIED  Permission denied
 * @see  softap_destroy()
 */
int softap_create(softap_h *softap);

/**
 * @brief Destroys the handle for softap.
 * @since_tizen 3.0
 * @param[in]  softap  The softap handle
 * @return  0 on success, otherwise a negative error value
 * @retval  #SOFTAP_ERROR_NONE  Successful
 * @retval  #SOFTAP_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #SOFTAP_ERROR_NOT_SUPPORTED  API is not supported
 * @see  softap_create()
 */
int softap_destroy(softap_h softap);

/**
 * @brief Enables the softap, asynchronously.
 * @since_tizen 3.0
 * @param[in]  softap  The softap handle
 * @return 0 on success, otherwise negative error value
 * @retval  #SOFTAP_ERROR_NONE  Successful
 * @retval  #SOFTAP_ERROR_NOT_PERMITTED  Operation not permitted
 * @retval  #SOFTAP_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #SOFTAP_ERROR_INVALID_OPERATION  Invalid operation
 * @retval  #SOFTAP_ERROR_RESOURCE_BUSY Device or resource busy
 * @retval  #SOFTAP_ERROR_NOT_SUPPORTED  API is not supported
 * @post softap_enabled_cb() will be invoked.
 * @see  softap_is_enabled()
 * @see  softap_disable()
 */
int softap_enable(softap_h softap);
/**
 * @brief Disables the softap, asynchronously.
 * @since_tizen 3.0
 * @param[in]  softap  The softap handle
 * @return 0 on success, otherwise negative error value
 * @retval  #SOFTAP_ERROR_NONE  Successful
 * @retval  #SOFTAP_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #SOFTAP_ERROR_INVALID_OPERATION  Invalid operation
 * @retval  #SOFTAP_ERROR_NOT_SUPPORTED  API is not supported
 * @post softap_disabled_cb() will be invoked.
 * @see  softap_is_enabled()
 * @see  softap_enable()
 */
int softap_disable(softap_h softap);

/**
 * @brief Checks whether the softap is enabled or not.
 * @since_tizen 3.0
 * @param[in]  softap  The softap handle
 * @param[out] enable  @c true if softap is enabled, \n @c false if softap is disabled
 * @return 0 on success, otherwise negative error value
 * @retval  #SOFTAP_ERROR_NONE  Successful
 * @retval  #SOFTAP_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #SOFTAP_ERROR_NOT_SUPPORTED  API is not supported
 */
int softap_is_enabled(softap_h softap, bool *enable);

/**
 * @brief Gets the MAC address of local device as "FC:A1:3E:D6:B1:B1".
 * @since_tizen 3.0
 * @remarks @a mac_address must be released using free().
 * @param[in]  softap  The softap handle
 * @param[out]  mac_address  The MAC address
 * @return  0 on success, otherwise a negative error value
 * @retval  #SOFTAP_ERROR_NONE  Successful
 * @retval  #SOFTAP_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #SOFTAP_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval  #SOFTAP_ERROR_OPERATION_FAILED  Operation failed
 * @retval  #SOFTAP_ERROR_INVALID_OPERATION  Invalid operation
 * @retval  #SOFTAP_ERROR_NOT_SUPPORTED  API is not supported
 * @pre  The softap must be enabled.
 * @see  softap_is_enabled()
 * @see  softap_enable()
 */
int softap_get_mac_address(softap_h softap, char **mac_address);

/**
 * @brief Gets the name of network interface (e.g. wlan0).
 * @since_tizen 3.0
 * @remarks @a interface_name must be released using free().
 * @param[in]  softap  The softap handle
 * @param[out]  interface_name  The name of the network interface
 * @return 0 on success, otherwise negative error value
 * @retval  #SOFTAP_ERROR_NONE  Successful
 * @retval  #SOFTAP_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #SOFTAP_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval  #SOFTAP_ERROR_OPERATION_FAILED  Operation failed
 * @retval  #SOFTAP_ERROR_INVALID_OPERATION  Invalid operation
 * @retval  #SOFTAP_ERROR_NOT_SUPPORTED  API is not supported
 * @pre  The softap must be enabled.
 * @see  softap_is_enabled()
 * @see  softap_enable()
 */
int softap_get_network_interface_name(softap_h softap, char **interface_name);

/**
 * @brief Gets the local IP address.
 * @since_tizen 3.0
 * @remarks @a ip_address must be released using free().
 * @param[in]  softap  The softap handle
 * @param[in]  address_family  The address family of IP address (currently, #SOFTAP_ADDRESS_FAMILY_IPV4 is only supported)
 * @param[out]  ip_address  The local IP address
 * @return 0 on success, otherwise negative error value
 * @retval  #SOFTAP_ERROR_NONE  Successful
 * @retval  #SOFTAP_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #SOFTAP_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval  #SOFTAP_ERROR_OPERATION_FAILED  Operation failed
 * @retval  #SOFTAP_ERROR_INVALID_OPERATION  Invalid operation
 * @retval  #SOFTAP_ERROR_NOT_SUPPORTED  API is not supported
 * @pre  The softap must be enabled.
 * @see  softap_is_enabled()
 * @see  softap_enable()
 */
int softap_get_ip_address(softap_h softap, softap_address_family_e address_family, char **ip_address);

/**
 * @brief Gets the Gateway address.
 * @since_tizen 3.0
 * @remarks @a gateway_address must be released using free().
 * @param[in]  softap  The softap handle
 * @param[in]  address_family  The address family of IP address (currently, #SOFTAP_ADDRESS_FAMILY_IPV4 is only supported)
 * @param[out]  gateway_address  Gateway address
 * @return 0 on success, otherwise negative error value
 * @retval  #SOFTAP_ERROR_NONE  Successful
 * @retval  #SOFTAP_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #SOFTAP_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval  #SOFTAP_ERROR_OPERATION_FAILED  Operation failed
 * @retval  #SOFTAP_ERROR_INVALID_OPERATION  Invalid operation
 * @retval  #SOFTAP_ERROR_NOT_SUPPORTED  API is not supported
 * @pre  The softap must be enabled.
 * @see  softap_is_enabled()
 * @see  softap_enable()
 */
int softap_get_gateway_address(softap_h softap, softap_address_family_e address_family, char **gateway_address);

/**
 * @brief Gets the Subnet Mask.
 * @since_tizen 3.0
 * @remarks @a subnet_mask must be released using free().
 * @param[in]  softap  The softap handle
 * @param[in]  address_family  The address family of IP address (currently, #SOFTAP_ADDRESS_FAMILY_IPV4 is only supported)
 * @param[out]  subnet_mask  Subnet mask
 * @return 0 on success, otherwise negative error value
 * @retval  #SOFTAP_ERROR_NONE  Successful
 * @retval  #SOFTAP_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #SOFTAP_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval  #SOFTAP_ERROR_OPERATION_FAILED  Operation failed
 * @retval  #SOFTAP_ERROR_INVALID_OPERATION  Invalid operation
 * @retval  #SOFTAP_ERROR_NOT_SUPPORTED  API is not supported
 * @pre  The softap must be enabled.
 * @see  softap_is_enabled()
 * @see  softap_enable()
 */
int softap_get_subnet_mask(softap_h softap, softap_address_family_e address_family, char **subnet_mask);

/**
 * @brief Gets the clients which are connected.
 * @since_tizen 3.0
 * @param[in]  softap  The softap handle
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @retval  #SOFTAP_ERROR_NONE  Successful
 * @retval  #SOFTAP_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #SOFTAP_ERROR_INVALID_OPERATION  Invalid operation
 * @retval  #SOFTAP_ERROR_OPERATION_FAILED  Operation failed
 * @retval  #SOFTAP_ERROR_NOT_SUPPORTED  API is not supported
 * @pre  The softap must be enabled.
 * @see  softap_is_enabled()
 * @see  softap_enable()
 */
int softap_foreach_connected_clients(softap_h softap, softap_connected_client_cb callback, void *user_data);

/**
 * @brief Registers the callback function, which is called when softap is enabled.
 * @since_tizen 3.0
 * @param[in]  softap The softap handle
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @retval  #SOFTAP_ERROR_NONE  Successful
 * @retval  #SOFTAP_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #SOFTAP_ERROR_NOT_SUPPORTED  API is not supported
 * @see  softap_unset_enabled_cb()
 */
int softap_set_enabled_cb(softap_h softap, softap_enabled_cb callback, void *user_data);

/**
 * @brief Unregisters the callback function, which is called when softap is enabled.
 * @since_tizen 3.0
 * @param[in]  softap  The softap handle
 * @retval  #SOFTAP_ERROR_NONE  Successful
 * @retval  #SOFTAP_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #SOFTAP_ERROR_NOT_SUPPORTED  API is not supported
 * @see  softap_set_enabled_cb()
 */
int softap_unset_enabled_cb(softap_h softap);

/**
 * @brief Registers the callback function called when softap is disabled.
 * @since_tizen 3.0
 * @param[in]  softap  The softap handle
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @retval  #SOFTAP_ERROR_NONE  Successful
 * @retval  #SOFTAP_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #SOFTAP_ERROR_NOT_SUPPORTED  API is not supported
 * @see  softap_unset_disabled_cb()
 */
int softap_set_disabled_cb(softap_h softap,  softap_disabled_cb callback, void *user_data);

/**
 * @brief Unregisters the callback function, which is called when softap is disabled.
 * @since_tizen 3.0
 * @param[in]  softap  The softap handle
 * @retval  #SOFTAP_ERROR_NONE  Successful
 * @retval  #SOFTAP_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #SOFTAP_ERROR_NOT_SUPPORTED  API is not supported
 * @see  softap_set_disabled_cb()
 */
int softap_unset_disabled_cb(softap_h softap);

/**
 * @brief Registers the callback function, which is called when the state of connection is changed.
 * @since_tizen 3.0
 * @param[in]  softap  The softap handle
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @retval  #SOFTAP_ERROR_NONE  Successful
 * @retval  #SOFTAP_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #SOFTAP_ERROR_NOT_SUPPORTED  API is not supported
 * @see  softap_unset_client_connection_state_changed_cb()
 */
int softap_set_client_connection_state_changed_cb(softap_h softap, softap_client_connection_state_changed_cb callback, void *user_data);

/**
 * @brief Unregisters the callback function, which is called when the state of connection is changed.
 * @since_tizen 3.0
 * @param[in]  softap  The softap handle
 * @retval  #SOFTAP_ERROR_NONE  Successful
 * @retval  #SOFTAP_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #SOFTAP_ERROR_NOT_SUPPORTED  API is not supported
 * @see  softap_set_client_connection_state_changed_cb()
 */
int softap_unset_client_connection_state_changed_cb(softap_h softap);

/**
 * @brief Registers the callback function, which is called when the security type of softap is changed.
 * @since_tizen 3.0
 * @param[in]  softap  The softap handle
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @retval  #SOFTAP_ERROR_NONE  Successful
 * @retval  #SOFTAP_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #SOFTAP_ERROR_NOT_SUPPORTED  API is not supported
 * @see  softap_unset_security_type_changed_cb()
 */
int softap_set_security_type_changed_cb(softap_h softap, softap_security_type_changed_cb callback, void *user_data);

/**
 * @brief Unregisters the callback function, which is called when the security type of softap is changed.
 * @since_tizen 3.0
 * @param[in]  softap  The softap handle
 * @param[in]  type  The softap type
 * @retval  #SOFTAP_ERROR_NONE  Successful
 * @retval  #SOFTAP_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #SOFTAP_ERROR_NOT_SUPPORTED  API is not supported
 * @see  softap_set_security_type_changed_cb()
 */
int softap_unset_security_type_changed_cb(softap_h softap);

/**
 * @brief Registers the callback function , which iscalled when the visibility of SSID is changed.
 * @since_tizen 3.0
 * @param[in]  softap  The softap handle
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @retval  #SOFTAP_ERROR_NONE  Successful
 * @retval  #SOFTAP_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #SOFTAP_ERROR_NOT_SUPPORTED  API is not supported
 * @see  softap_unset_ssid_visibility_changed_cb_cb()
 */
int softap_set_ssid_visibility_changed_cb(softap_h softap, softap_ssid_visibility_changed_cb callback, void *user_data);

/**
 * @brief Unregisters the callback function, which is called when the visibility of SSID is changed.
 * @since_tizen 3.0
 * @param[in]  softap  The softap handle
 * @retval  #SOFTAP_ERROR_NONE  Successful
 * @retval  #SOFTAP_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #SOFTAP_ERROR_NOT_SUPPORTED  API is not supported
 * @see  softap_wifi_set_ssid_visibility_changed_cb()
 */
int softap_unset_ssid_visibility_changed_cb(softap_h softap);

/**
 * @brief Registers the callback function, which is called when the passphrase of softap is changed.
 * @since_tizen 3.0
 * @param[in]  softap  The softap handle
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @retval  #SOFTAP_ERROR_NONE  Successful
 * @retval  #SOFTAP_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #SOFTAP_ERROR_NOT_SUPPORTED  API is not supported
 * @see  softap_unset_passphrase_changed_cb()
 */
int softap_set_passphrase_changed_cb(softap_h softap, softap_passphrase_changed_cb callback, void *user_data);

/**
 * @brief Unregisters the callback function, which is called when the passphrase of softap is changed.
 * @since_tizen 3.0
 * @param[in]  softap  The softap handle
 * @retval  #SOFTAP_ERROR_NONE  Successful
 * @retval  #SOFTAP_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #SOFTAP_ERROR_NOT_SUPPORTED  API is not supported
 * @see  softap_set_passphrase_changed_cb()
 */
int softap_unset_passphrase_changed_cb(softap_h softap);

/**
 * @}
 */

/**
 * @addtogroup CAPI_NETWORK_SOFTAP_MANAGER_MODULE
 * @{
 */

/**
 * @brief Sets the security type of softap.
 * @details If security type is not set, WPA2_PSK is used.
 * @since_tizen 3.0
 * @remarks This change is applied next time softap is enabled. \
 *			You can use softap_enable() or softap_reload_settings() to enable softap.
 * @param[in]  softap  The softap handle
 * @param[in]  type  The security type
 * @return 0 on success, otherwise negative error value
 * @retval  #SOFTAP_ERROR_NONE  Successful
 * @retval  #SOFTAP_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #SOFTAP_ERROR_OPERATION_FAILED  Operation failed
 * @retval  #SOFTAP_ERROR_NOT_SUPPORTED  API is not supported
 * @see  softap_wifi_ap_get_security_type()
 */
int softap_set_security_type(softap_h softap, softap_security_type_e type);

/**
 * @brief Gets the security type of Soft AP.
 * @details If security type is not set, WPA2_PSK is used.
 * @since_tizen 3.0
 * @param[in]  softap  The softap handle
 * @param[out]  type  The security type
 * @return 0 on success, otherwise negative error value
 * @retval  #SOFTAP_ERROR_NONE  Successful
 * @retval  #SOFTAP_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #SOFTAP_ERROR_NOT_SUPPORTED  API is not supported
 * @see  softap_wifi_ap_set_security_type()
 */
int softap_get_security_type(softap_h softap, softap_security_type_e *type);

/**
 * @brief Sets the SSID (service set identifier) for Soft AP.
 * @details The SSID cannot exceed 32 bytes. If SSID is not set, device name is used as SSID.
 * @since_tizen 3.0
 * @remarks This change is applied next time softap is enabled. \
 *          You can use softap_enable() or softap_reload_settings() to enable softap.
 * @param[in]  softap  The softap handle
 * @param[in]  ssid  The SSID
 * @return 0 on success, otherwise negative error value
 * @retval  #SOFTAP_ERROR_NONE  Successful
 * @retval  #SOFTAP_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #SOFTAP_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval  #SOFTAP_ERROR_NOT_SUPPORTED  API is not supported
 */
int softap_set_ssid(softap_h softap, const char *ssid);

/**
 * @brief Gets the SSID (service set identifier) for Soft AP.
 * @details If SSID is not set, Device name is used as SSID.
 * @since_tizen 3.0
 * @remarks @a ssid must be released using free().
 * @param[in]  softap  The softap handle
 * @param[out]  ssid  The SSID
 * @return 0 on success, otherwise negative error value
 * @retval  #SOFTAP_ERROR_NONE  Successful
 * @retval  #SOFTAP_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #SOFTAP_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval  #SOFTAP_ERROR_NOT_SUPPORTED  API is not supported
 */
int softap_get_ssid(softap_h softap, char **ssid);

/**
 * @brief Sets the visibility of SSID (service set identifier) for Soft AP.
 * @details If you set the visibility to invisible, then the SSID of this device is hidden and Wi-Fi scan won't find your device.
 * @details By default visibility is set to @c true.
 * @since_tizen 3.0
 * @remarks This change is applied next time softap is enabled. \
 *          You can use softap_enable() or softap_reload_settings() to enable softap.
 * @param[in]  softap  The softap handle
 * @param[in]  visible  The visibility of SSID: (@c true = visible, @c false = invisible)
 * @return 0 on success, otherwise negative error value
 * @retval  #SOFTAP_ERROR_NONE  Successful
 * @retval  #SOFTAP_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #SOFTAP_ERROR_OPERATION_FAILED  Operation failed
 * @retval  #SOFTAP_ERROR_NOT_SUPPORTED  API is not supported
 * @see  softap_get_ssid_visibility()
 */
int softap_set_ssid_visibility(softap_h softap, bool visible);

/**
 * @brief Gets the visibility of SSID (service set identifier) for Soft AP.
 * @details If the visibility is set to invisible, then the SSID of this device is hidden and Wi-Fi scan won't find your device.
 * @details By default visibility is set to @c true.
 * @since_tizen 3.0
 * @param[in]  softap  The softap handle
 * @param[out]  visible  The visibility of SSID: (@c true = visible, @c false = invisible)
 * @return 0 on success, otherwise negative error value
 * @retval  #SOFTAP_ERROR_NONE  Successful
 * @retval  #SOFTAP_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #SOFTAP_ERROR_NOT_SUPPORTED  API is not supported
 * @see  softap_set_ssid_visibility()
 */
int softap_get_ssid_visibility(softap_h softap, bool *visible);

/**
 * @brief Sets the passphrase for Soft AP.
 * @details If the passphrase is not set, random string of 8 characters will be used.
 * @since_tizen 3.0
 * @remarks This change is applied next time softap is enabled. \
 *          You can use softap_enable() or softap_reload_settings() to enable softap.
 * @param[in]  softap  The softap handle
 * @param[in]  passphrase  The passphrase
 * @return 0 on success, otherwise negative error value
 * @retval  #SOFTAP_ERROR_NONE  Successful
 * @retval  #SOFTAP_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #SOFTAP_ERROR_NOT_SUPPORTED  API is not supported
 * @see  softap_get_passphrase()
 */
int softap_set_passphrase(softap_h softap, const char *passphrase);

/**
 * @brief Gets the passphrase for Soft AP.
 * @details If the passphrase is not set, random string of 8 characters will be used.
 * @since_tizen 3.0
 * @remarks @a passphrase must be released using free().
 * @param[in]  softap  The softap handle
 * @param[out]  passphrase  The passphrase
 * @return 0 on success, otherwise negative error value
 * @retval  #SOFTAP_ERROR_NONE  Successful
 * @retval  #SOFTAP_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #SOFTAP_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval  #SOFTAP_ERROR_NOT_SUPPORTED  API is not supported
 * @see  softap_set_passphrase()
 */
int softap_get_passphrase(softap_h softap, char **passphrase);

/**
 * @brief Reloads the settings (SSID / Passphrase / Security type / SSID visibility) for Soft AP.
 * @since_tizen 3.0
 * @remarks Devices connected via MobileAP will be disconnected when the settings are reloaded.
 * @param[in]  softap  The softap handle
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @return 0 on success, otherwise negative error value
 * @retval  #SOFTAP_ERROR_NONE  Successful
 * @retval  #SOFTAP_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #SOFTAP_ERROR_OPERATION_FAILED  Operation failed
 * @retval  #SOFTAP_ERROR_RESOURCE_BUSY Device or resource busy
 * @retval  #SOFTAP_ERROR_NOT_SUPPORTED  API is not supported
 */
int softap_reload_settings(softap_h softap, softap_settings_reloaded_cb callback, void *user_data);
/**
 * @}
 */


/**
 * @addtogroup CAPI_NETWORK_SOFTAP_CLIENT_MODULE
 * @{
 */

/**
 * @brief Clones the handle of a client.
 * @since_tizen 3.0
 * @privlevel public
 * @privilege %http://tizen.org/privilege/softap
 * @remarks @a dest must be release using softap_client_destroy().
 * @param[out]  dest  The cloned client handle
 * @param[in]  origin  The origin client handle
 * @return  0 on success, otherwise a negative error value
 * @retval  #SOFTAP_ERROR_NONE  Successful
 * @retval  #SOFTAP_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #SOFTAP_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval  #SOFTAP_ERROR_PERMISSION_DENIED  Permission denied
 * @retval  #SOFTAP_ERROR_NOT_SUPPORTED  API is not supported
 * @see  softap_client_destroy()
 */
int softap_client_clone(softap_client_h *dest, softap_client_h origin);

/**
 * @brief Destroys the handle of a client.
 * @since_tizen 3.0
 * @param[in]  client  The client handle
 * @return  0 on success, otherwise a negative error value
 * @retval  #SOFTAP_ERROR_NONE  Successful
 * @retval  #SOFTAP_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #SOFTAP_ERROR_NOT_SUPPORTED  API is not supported
 * @see  softap_client_clone()
 */
int softap_client_destroy(softap_client_h client);

/**
 * @brief Gets the name of a client.
 * @since_tizen 3.0
 * @remarks @a name must be released using free().
 * @param[in]  client  The client handle
 * @param[out]  name  The name of the client
 * @return  0 on success, otherwise a negative error value
 * @retval  #SOFTAP_ERROR_NONE  Successful
 * @retval  #SOFTAP_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #SOFTAP_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval  #SOFTAP_ERROR_NOT_SUPPORTED  API is not supported
 * @see  softap_client_connection_state_changed_cb()
 */
int softap_client_get_name(softap_client_h client, char **name);

/**
 * @brief Gets the IP address of a client.
 * @since_tizen 3.0
 * @remarks @a ip_address must be released using free().
 * @param[in]  client  The client handle
 * @param[in]  address_family  The address family of IP address. Currently, #SOFTAP_ADDRESS_FAMILY_IPV4 is only supported
 * @param[out]  ip_address  The IP address
 * @return  0 on success, otherwise a negative error value
 * @retval  #SOFTAP_ERROR_NONE  Successful
 * @retval  #SOFTAP_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #SOFTAP_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval  #SOFTAP_ERROR_NOT_SUPPORTED  API is not supported
 * @see  softap_client_connection_state_changed_cb()
 */
int softap_client_get_ip_address(softap_client_h client, softap_address_family_e address_family, char **ip_address);

/**
 * @brief Gets the MAC address of a client such as "FC:A1:3E:D6:B1:B1".
 * @since_tizen 3.0
 * @remarks @a mac_address must be released using free().
 * @param[in]  client  The client handle
 * @param[out]  mac_address  The MAC address
 * @return  0 on success, otherwise a negative error value
 * @retval  #SOFTAP_ERROR_NONE  Successful
 * @retval  #SOFTAP_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #SOFTAP_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval  #SOFTAP_ERROR_NOT_SUPPORTED  API is not supported
 * @see  softap_client_connection_state_changed_cb()
 */
int softap_client_get_mac_address(softap_client_h client, char **mac_address);

/**
 * @brief Gets the connection time of a client.
 * @since_tizen 3.0
 * @param[in] client The client handle
 * @param[out]  time  The connected time of the client
 * @return  0 on success, otherwise a negative error value
 * @retval  #SOFTAP_ERROR_NONE  Successful
 * @retval  #SOFTAP_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #SOFTAP_ERROR_NOT_SUPPORTED  API is not supported
 * @see  softap_client_connection_state_changed_cb()
 */
int softap_client_get_time(softap_client_h client, time_t *timestamp);

/**
 * @}
 */

#ifdef __cplusplus
 }
#endif

#endif /* __TIZEN_NETWORK_SOFTAP_H__ */


