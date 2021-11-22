/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef AT_CUSTOM_CMD_H_
#define AT_CUSTOM_CMD_H_

/**
 * @file at_custom_cmd.h
 *
 * @defgroup at_custom_cmd Custom AT commands
 *
 * @{
 *
 * @brief Public APIs for adding custom AT commands using filters with application callback
 * in modem library.
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <kernel.h>
#include <sys/util_macro.h>
#include <toolchain/common.h>

/**
 * @brief Initialize custom AT commands.
 */
int at_custom_cmd_init(void);

/**
 * @brief Deinitialize custom AT commands.
 */
int at_custom_cmd_deinit(void);

/**
 * @brief Fill response buffer.
 *
 * @param buf Buffer to put receive response into.
 * @param len Buffer length.
 * @param content Response format.
 * @param ... Format arguments.
 */
int at_custom_cmd_response_buffer_fill(char *buf, size_t len,
		const char *content, ...);

/**
 * @brief Define an AT filter.
 *
 * @param name The filter name.
 * @param _cmd The AT command on which the filter should triger.
 * @param _callback Filtered AT commands callback function.
 */
#define AT_FILTER(name, _cmd, _callback) \
	STRUCT_SECTION_ITERABLE(nrf_modem_at_cmd_filter, nrf_modem_at_cmd_filter_##name) = { \
		.cmd = _cmd, \
		.callback = _callback \
	}

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* AT_CUSTOM_CMD_H_ */
