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

#ifndef __TIZEN_NETWORK_SOFTAP_INTERNAL_H__
#define __TIZEN_NETWORK_SOFTAP_INTERNAL_H__

#include <tizen.h>
#include <time.h>
#include "softap.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file softap_internal.h
 */

/**
 * @addtogroup CAPI_NETWORK_SOFTAP_MANAGER_MODULE
 * @{
 */

/**
 * @brief Enables the softap, asynchronously.
 * @since_tizen 3.0
 * @privlevel platform
 * @privilege http://tizen.org/privilege/softap.admin
 * @param[in]  softap  The softap handle
 * @return 0 on success, otherwise negative error value
 * @retval  #SOFTAP_ERROR_NONE  Successful
 * @retval	#SOFTAP_ERROR_NOT_PERMITTED  Operation not permitted
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
 * @privlevel platform
 * @privilege http://tizen.org/privilege/softap.admin
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
 * @brief Reloads the settings (SSID / Passphrase / Security type / SSID visibility) for Soft AP.
 * @since_tizen 3.0
 * @privlevel platform
 * @privilege http://tizen.org/privilege/softap.admin
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

#ifdef __cplusplus
 }
#endif

#endif /* __TIZEN_NETWORK_SOFTAP_INTERNAL_H__ */
