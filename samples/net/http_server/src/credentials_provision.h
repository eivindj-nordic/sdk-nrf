/*
 * Copyright (c) 2024 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */
#include <zephyr/net/tls_credentials.h>

/* Document that this function provisions credentials using the correct API depending on if
 * it is the modem of the ZEPHYR NET stack that is used
 */
int credentials_provision(void);
