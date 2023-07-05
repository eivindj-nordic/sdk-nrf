/*
 * Copyright (c) 2020-2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */
#include <stdio.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/toolchain.h>
#include <zephyr/net/socket.h>
#include <zephyr/sys/reboot.h>
#include <zephyr/shell/shell.h>

#include <nrf_modem.h>
#include <nrf_modem_at.h>
#include <nrf_socket.h>
#include <modem/lte_lc.h>
#include <modem/modem_key_mgmt.h>
#include <modem/modem_info.h>
#include <modem/nrf_modem_lib.h>
#include <net/fota_download.h>

#define FOTA_TEST "FOTA-TEST"

#define TLS_SEC_TAG 42

#ifdef CONFIG_USE_HTTPS
#define SEC_TAG (TLS_SEC_TAG)
#else
#define SEC_TAG (-1)
#endif

/* We assume that modem version strings (not UUID) will not be more than this */
#define MAX_MODEM_VERSION_LEN 256
static char modem_version[MAX_MODEM_VERSION_LEN];

enum fota_state { IDLE, CONNECTED, UPDATE_DOWNLOAD, UPDATE_APPLY };
static enum fota_state state = IDLE;

static const struct gpio_dt_spec led0 = GPIO_DT_SPEC_GET(DT_ALIAS(led0), gpios);
static const struct gpio_dt_spec led1 = GPIO_DT_SPEC_GET(DT_ALIAS(led1), gpios);
static const struct gpio_dt_spec sw0 = GPIO_DT_SPEC_GET(DT_ALIAS(sw0), gpios);
static struct gpio_callback sw0_cb;
static struct k_work fota_work;

BUILD_ASSERT(strlen(CONFIG_SUPPORTED_BASE_VERSION), "CONFIG_SUPPORTED_BASE_VERSION not set");
BUILD_ASSERT(strlen(CONFIG_DOWNLOAD_FILE_FOTA_TEST_TO_BASE),
	     "CONFIG_DOWNLOAD_FILE_FOTA_TEST_TO_BASE not set");
BUILD_ASSERT(strlen(CONFIG_DOWNLOAD_FILE_BASE_TO_FOTA_TEST),
	     "CONFIG_DOWNLOAD_FILE_BASE_TO_FOTA_TEST not set");

static int apply_state(enum fota_state new_state);

static bool is_test_firmware(void)
{
	return strstr(modem_version, FOTA_TEST) != NULL;
}

static void lte_lc_handler(const struct lte_lc_evt *const evt)
{
	static bool connected;

	switch (evt->type) {
	case LTE_LC_EVT_NW_REG_STATUS:
		if ((evt->nw_reg_status != LTE_LC_NW_REG_REGISTERED_HOME) &&
		    (evt->nw_reg_status != LTE_LC_NW_REG_REGISTERED_ROAMING)) {
			if (!connected) {
				break;
			}

			printk("LTE network is disconnected.\n");
			connected = false;
			if (state == CONNECTED) {
				apply_state(IDLE);
			}
			break;
		}

		connected = true;

		if (state == IDLE) {
			printk("LTE Link Connected!\n");
			apply_state(CONNECTED);
		}
		break;
	default:
		break;
	}
}

static int leds_init(void)
{
	if (!device_is_ready(led0.port)) {
		printk("Led0 GPIO port not ready\n");
		return -ENODEV;
	}

	if (!device_is_ready(led1.port)) {
		printk("Led1 GPIO port not ready\n");
		return -ENODEV;
	}

	return 0;
}

static int leds_set(int num)
{
	switch (num) {
	case 0:
		gpio_pin_configure_dt(&led0, GPIO_OUTPUT_INACTIVE);
		gpio_pin_configure_dt(&led0, GPIO_OUTPUT_INACTIVE);
		break;
	case 1:
		gpio_pin_configure_dt(&led0, GPIO_OUTPUT_ACTIVE);
		gpio_pin_configure_dt(&led0, GPIO_OUTPUT_INACTIVE);
		break;
	case 2:
		gpio_pin_configure_dt(&led0, GPIO_OUTPUT_ACTIVE);
		gpio_pin_configure_dt(&led0, GPIO_OUTPUT_ACTIVE);
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static void dfu_button_irq_disable(void)
{
	gpio_pin_interrupt_configure_dt(&sw0, GPIO_INT_DISABLE);
}

static void dfu_button_irq_enable(void)
{
	gpio_pin_interrupt_configure_dt(&sw0, GPIO_INT_EDGE_TO_ACTIVE);
}

static void dfu_button_pressed(const struct device *gpiob, struct gpio_callback *cb,
			uint32_t pins)
{
	k_work_submit(&fota_work);
	apply_state(UPDATE_DOWNLOAD);
}

static int button_init(void)
{
	int err;

	if (!device_is_ready(sw0.port)) {
		printk("SW0 GPIO port device not ready\n");
		return -ENODEV;
	}

	err = gpio_pin_configure_dt(&sw0, GPIO_INPUT);
	if (err < 0) {
		return err;
	}

	gpio_init_callback(&sw0_cb, dfu_button_pressed, BIT(sw0.pin));

	err = gpio_add_callback(sw0.port, &sw0_cb);
	if (err < 0) {
		printk("Unable to configure SW0 GPIO pin!\n");
		return err;
	}

	return 0;
}

static void current_version_display(void)
{
	int err;
	int num_leds;

	err = modem_info_string_get(MODEM_INFO_FW_VERSION, modem_version,
				    MAX_MODEM_VERSION_LEN);
	if (err < 0) {
		printk("Failed to get modem version\n");
		return;
	}

	num_leds = is_test_firmware() ? 1 : 2;
	leds_set(num_leds);
	printk("Current modem firmware version: %s\n", modem_version);
}

void fota_dl_handler(const struct fota_download_evt *evt)
{
	switch (evt->id) {
	case FOTA_DOWNLOAD_EVT_ERROR:
		printk("Received error from fota_download\n");
		apply_state(CONNECTED);
		break;

	case FOTA_DOWNLOAD_EVT_FINISHED:
		apply_state(UPDATE_APPLY);
		k_work_submit(&fota_work);
		break;

	default:
		break;
	}
}

#if defined(CONFIG_USE_HTTPS)
static int cert_provision(void)
{
	static const char cert[] = {
		#include "../cert/AmazonRootCA1"
	};
	BUILD_ASSERT(sizeof(cert) < KB(4), "Certificate too large");

	int err;
	bool exists;

	err = modem_key_mgmt_exists(TLS_SEC_TAG,
				    MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN, &exists);
	if (err) {
		printk("Failed to check for certificates err %d\n", err);
		return err;
	}

	if (exists) {
		/* For the sake of simplicity we delete what is provisioned
		 * with our security tag and reprovision our certificate.
		 */
		err = modem_key_mgmt_delete(TLS_SEC_TAG,
					    MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN);
		if (err) {
			printk("Failed to delete existing certificate, err %d\n",
			       err);
		}
	}

	printk("Provisioning certificate\n");

	/*  Provision certificate to the modem */
	err = modem_key_mgmt_write(TLS_SEC_TAG,
				   MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN, cert,
				   sizeof(cert) - 1);
	if (err) {
		printk("Failed to provision certificate, err %d\n", err);
		return err;
	}

	return 0;
}
#endif /* CONFIG_USE_HTTPS */

/**
 * @brief Configures modem to provide LTE link.
 */
static int modem_configure_and_connect(void)
{
	BUILD_ASSERT(!IS_ENABLED(CONFIG_LTE_AUTO_INIT_AND_CONNECT),
			"This sample does not support auto init and connect");
	int err;

#if defined(CONFIG_USE_HTTPS)
	err = cert_provision();
	if (err) {
		printk("Could not provision root CA to %d", TLS_SEC_TAG);
		return err;
	}

#endif /* CONFIG_USE_HTTPS */

	printk("LTE Link Connecting ...\n");
	err = lte_lc_init_and_connect_async(lte_lc_handler);
	if (err) {
		printk("LTE link could not be established.");
		return err;
	}

	return 0;
}

static int update_download(void)
{
	int err;
	const char *file;

	err = modem_info_string_get(MODEM_INFO_FW_VERSION, modem_version,
				    MAX_MODEM_VERSION_LEN);
	if (err < 0) {
		printk("Failed to get modem version\n");
		return false;
	}

	if (is_test_firmware()) {
		file = CONFIG_DOWNLOAD_FILE_FOTA_TEST_TO_BASE;
	} else {
		file = CONFIG_DOWNLOAD_FILE_BASE_TO_FOTA_TEST;
	}

	err = fota_download_init(fota_dl_handler);
	if (err != 0) {
		printk("fota_download_init() failed, err %d\n", err);
		return err;
	}

	/* Functions for getting the host and file */
	err = fota_download_start(CONFIG_DOWNLOAD_HOST, file, SEC_TAG, 0, 0);
	if (err != 0) {
		printk("fota_download_start() failed, err %d\n", err);
		return err;
	}

	return 0;
}

static int apply_state(enum fota_state new_state)
{
	__ASSERT(state != new_state, "State already set: %d", state);

	switch (new_state) {
	case IDLE:
		dfu_button_irq_disable();
		modem_configure_and_connect();
		break;
	case CONNECTED:
		dfu_button_irq_enable();
		printk("Press Button 1 or enter 'download' to download firmware update\n");
		break;
	case UPDATE_DOWNLOAD:
		__ASSERT(state != UPDATE_APPLY,
			 "Invalid transition: UPDATE_APPLY to UPDATE_DOWNLOAD\n");
		dfu_button_irq_disable();
		break;
	case UPDATE_APPLY:
		dfu_button_irq_disable();
		lte_lc_deinit();
		break;
	}
	state = new_state;

	return 0;
}

static int shell_download(const struct shell *shell, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	apply_state(UPDATE_DOWNLOAD);
	k_work_submit(&fota_work);

	return 0;
}

SHELL_CMD_REGISTER(download, NULL, "For downloading modem  firmware", shell_download);

static int dfu_apply(void)
{
	int err;

	err = nrf_modem_lib_init();
	switch (err) {
	case NRF_MODEM_DFU_RESULT_OK:
		printk("Modem firmware update successful!\n");
		printk("Modem will run the new firmware after modem reboot\n");
		return 0;
	case NRF_MODEM_DFU_RESULT_UUID_ERROR:
	case NRF_MODEM_DFU_RESULT_AUTH_ERROR:
		printk("Modem firmware update failed\n");
		return err;
	case NRF_MODEM_DFU_RESULT_HARDWARE_ERROR:
	case NRF_MODEM_DFU_RESULT_INTERNAL_ERROR:
		printk("Modem firmware update failed\n");
		printk("Fatal error.\n");
		return err;
	case NRF_MODEM_DFU_RESULT_VOLTAGE_LOW:
		printk("Modem firmware update failed\n");
		printk("Please reboot once you have sufficient power for the DFU.\n");
		return err;
	case -1:
		printk("Could not initialize momdem library.\n");
		printk("Fatal error.\n");
		return err;
	}

	return -EINVAL;
}


static void fota_work_cb(struct k_work *work)
{
	int err;

	ARG_UNUSED(work);

	switch (state) {
	case IDLE:
	case CONNECTED:
		break;
	case UPDATE_DOWNLOAD:
		err = update_download();
		if (err) {
			apply_state(CONNECTED);
		}
		break;
	case UPDATE_APPLY:
		err = nrf_modem_lib_shutdown();
		if (err) {
			printk("Failed to shutdown modem, err %d\n", err);
		}

		/* Modem firmware will be updated on modem library init */
		err = dfu_apply();
		if (err) {
			printk("Failed applying FOTA\n");
		}

		/* Initialize again to start modem in normal mode. */
		err = nrf_modem_lib_init();
		if (err) {
			printk("Modem initialization failed, err %d\n", err);
		}

		current_version_display();

		apply_state(IDLE);
		break;
	}
}

NRF_MODEM_LIB_ON_DFU_RES(main_dfu_hook, on_modem_lib_dfu, NULL);

int main(void)
{
	int err;

	printk("HTTP delta modem update sample started\n");

	printk("Initializing modem library\n");

	err = nrf_modem_lib_init();
	if (err) {
		printk("Modem library initialization failed, err %d\n", err);
		return err;
	}
	printk("Initialized modem library\n");

	k_work_init(&fota_work, fota_work_cb);

	err = button_init();
	if (err != 0) {
		return err;
	}

	err = leds_init();
	if (err != 0) {
		return err;
	}

	err = modem_info_init();
	if (err != 0) {
		printk("modem_info_init failed: %d\n", err);
		return err;
	}

	current_version_display();

	if (strstr(modem_version, CONFIG_SUPPORTED_BASE_VERSION) == NULL) {
		printk("Unsupported base modem version: %s\n", modem_version);
		printk("Supported base version (set in prj.conf): %s\n",
		       CONFIG_SUPPORTED_BASE_VERSION);
		return -EINVAL;
	}

	err = modem_configure_and_connect();
	if (err) {
		printk("Modem configuration failed: %d\n", err);
		return err;
	}

	return 0;
}
