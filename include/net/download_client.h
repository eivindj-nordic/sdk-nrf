/*
 * Copyright (c) 2019 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

/**@file download_client.h
 *
 * @defgroup dl_client Download client
 * @{
 * @brief Client for downloading an object.
 *
 * @details The download client provides APIs for:
 *  - connecting to a remote server,
 *  - downloading an object from the server,
 *  - disconnecting from the server,
 *  - receiving asynchronous event notifications on the download status.
 */

#if CONFIG_DOWNLOAD_CLIENT_DEPRECATED_API
#include <net/download_client_deprecated.h>
#else

#ifndef DOWNLOAD_CLIENT_H__
#define DOWNLOAD_CLIENT_H__

#include <zephyr/kernel.h>
#include <zephyr/types.h>
#include <zephyr/net/coap.h>

/* Predefinition of download client struct used in download client transport. */

#ifdef __cplusplus
extern "C" {
#endif

#define K_THREAD_STACK_MEMBER K_KERNEL_STACK_MEMBER

/**
 * @brief Download client event IDs.
 */
enum download_client_evt_id {
	/**
	 * Event contains a fragment.
	 * The application may return any non-zero value to stop the download.
	 */
	DOWNLOAD_CLIENT_EVT_FRAGMENT,
	/**
	 * An error has occurred during download and
	 * the connection to the server has been lost.
	 *
	 * Error reason may be one of the following:
	 * - ECONNRESET: socket error, peer closed connection
	 * - ECONNREFUSED: socket error, connection refused by server
	 * - ENETDOWN: socket error, network down
	 * - ETIMEDOUT: socket error, connection timed out
	 * - EHOSTDOWN: host went down during download
	 * - EBADMSG: HTTP response header not as expected
	 * - ERANGE: HTTP response does not support range requests
	 * - E2BIG: HTTP response header could not fit in buffer
	 * - EPROTONOSUPPORT: Protocol is not supported
	 * - EINVAL: Invalid configuration
	 * - EAFNOSUPPORT: Unsupported address family (IPv4/IPv6)
	 * - EHOSTUNREACH: Failed to resolve the target address
	 *
	 * In case of errors on the socket during send() or recv() (ECONNRESET),
	 * returning zero from the callback will let the library attempt
	 * to reconnect to the server and download the last fragment again.
	 * Otherwise, the application may return any non-zero value
	 * to stop the download. On any other error code than ECONNRESET, the client
	 * will not attempt to reconnect and ignores the return value.
	 *
	 * In case the download is stopped, and it was started using @ref download_client_get,
	 * the download client automatically closes the connection. The application should wait for
	 * DOWNLOAD_CLIENT_EVT_CLOSED before attempting another download.
	 * If download is stopped, and it was started using @ref download_client_start
	 * the application should manually disconnect (@ref download_client_stop)
	 * to clean up the network socket and wait for DOWNLOAD_CLIENT_EVT_CLOSED before attempting
	 * another download.
	 */
	DOWNLOAD_CLIENT_EVT_ERROR,
	/** Download complete. */
	DOWNLOAD_CLIENT_EVT_DONE,
	/** Connection have been closed. Client is now idle, ready for next download */
	DOWNLOAD_CLIENT_EVT_CLOSED,
	/** Client deinitialized. Memory can be freed. */
	DOWNLOAD_CLIENT_EVT_DEINITIALIZED,
};

struct download_fragment {
	const void *buf;
	size_t len;
};

/**
 * @brief Download client event.
 */
struct download_client_evt {
	/** Event ID. */
	enum download_client_evt_id id;

	union {
		/** Error cause. */
		int error;
		/** Fragment data. */
		struct download_fragment fragment;
	};
};

/**
 * @brief Download client asynchronous event handler.
 *
 * Through this callback, the application receives events, such as
 * download of a fragment, download completion, or errors.
 *
 * If the callback returns a non-zero value, the download stops.
 * To resume the download, use @ref download_client_start().
 *
 * @param[in] event	The event.
 *
 * @return Zero to continue the download, non-zero otherwise.
 */
typedef int (*download_client_callback_t)(
	const struct download_client_evt *event);

/**
 * @brief
 */
struct download_client_cfg {
	/** Event handler. */
	download_client_callback_t callback;
	/** Client buffer. */
	char *buf;
	/** Client buffer size. */
	size_t buf_size;
};

/**
 * @brief Download client configuration options.
 */
struct download_client_host_cfg {
	/** TLS security tag list.
	 *  Pass NULL to disable TLS.
	 * The list must be kept in scope while download is going on.
	 */
	const int *sec_tag_list;
	/** Number of TLS security tags in list.
	 *  Set to 0 to disable TLS.
	 */
	uint8_t sec_tag_count;
	/**
	 * PDN ID to be used for the download.
	 * Zero is the default PDN.
	 */
	uint8_t pdn_id;
	/** Maximum fragment size to download. 0 indicates that values
	 * configured using Kconfig shall be used.
	 */
	size_t range_override;
	/** Set socket to native TLS */
	bool set_native_tls;
	/** Keep connection to server when done */
	bool keep_connection;
};

/**
 * @brief Download client state.
 */
enum download_client_state {
	DOWNLOAD_CLIENT_DEINITIALIZED,
	DOWNLOAD_CLIENT_IDLE,
	DOWNLOAD_CLIENT_CONNECTING,
	DOWNLOAD_CLIENT_CONNECTED,
	DOWNLOAD_CLIENT_DOWNLOADING,
	DOWNLOAD_CLIENT_DEINITIALIZING,
};

/**
 * @brief Download client instance.
 *
 * Members are set internally by the download client.
 */
struct download_client {
	/** Client configuration options. */
	struct download_client_cfg config;
	/** Host configuration options. */
	struct download_client_host_cfg host_config;
	/** Host name, null-terminated.
	 */
	char hostname[CONFIG_DOWNLOAD_CLIENT_MAX_HOSTNAME_SIZE];
	/** File name, null-terminated.
	 */
	char file[CONFIG_DOWNLOAD_CLIENT_MAX_FILENAME_SIZE];
	/** Size of the file being downloaded, in bytes. */
	size_t file_size;
	/** Download progress, number of bytes downloaded. */
	size_t progress;
	/** Buffer offset. */
	size_t buf_offset;

	/** Download client transport, http, CoAP, MQTT, ...
	 *  Store a pointer to the selected transport per DLC instance to avoid looking it up each call.
	 */
	void *transport;
	/** Transport parameters. */
	uint8_t transport_internal[CONFIG_DOWNLOAD_CLIENT_TRANSPORT_PARAMS_SIZE];

	/** Ensure that thread is ready for download */
	struct k_sem event_sem;
	/** Protect shared variables. */
	struct k_mutex mutex;
	/** Download client state. */
	enum download_client_state state;
	/** Internal download thread. */
	struct k_thread thread;
	/** Internal thread ID. */
	k_tid_t tid;

	/* Internal thread stack. */
	K_THREAD_STACK_MEMBER(thread_stack, CONFIG_DOWNLOAD_CLIENT_STACK_SIZE);
};

/**
 * @brief Initialize the download client.
 *
 * This function can only be called once in each client instance as
 * it starts the background thread.
 *
 * @param[in] client	Client instance.
 * @param[in] callback	Callback function.
 *
 * @retval int Zero on success, otherwise a negative error code.
 */
int download_client_init(struct download_client *const dlc,
			 struct download_client_cfg *config);

/**
 * @brief Deinitialize the download client.
 *
 * This function can only be called once in each client instance as
 * it removes the background thread.
 *
 * @param[in] client	Client instance.
 *
 * @retval int Zero on success.
 */
int download_client_deinit(struct download_client *client);

/**
 * @brief Download a file.
 *
 * The download is carried out in fragments of up to
 * @kconfig{CONFIG_DOWNLOAD_CLIENT_HTTP_FRAG_SIZE} bytes for HTTP, or
 * @kconfig{CONFIG_DOWNLOAD_CLIENT_COAP_BLOCK_SIZE} bytes for CoAP,
 * which are delivered to the application
 * via @ref DOWNLOAD_CLIENT_EVT_FRAGMENT events.
 *
 * @param[in] client	Client instance.
 * @param[in] file	File to download, null-terminated.
 * @param[in] from	Offset from where to resume the download,
 *			or zero to download from the beginning.
 *
 * @retval int Zero on success, a negative error code otherwise.
 */
int download_client_start(struct download_client *client,
			  const struct download_client_host_cfg *host_config,
			  const char *url, size_t from);

/**
 * @brief Stop file download and disconnect from server.
 *
 * Request client to disconnect from the server. This does not block.
 * When client have been disconnected, it send @ref DOWNLOAD_CLIENT_EVT_CLOSED event.
 *
 * @param[in] client	Client instance.
 *
 * @return Zero on success, a negative error code otherwise.
 */
int download_client_stop(struct download_client *client);

/**
 * @brief Retrieve the size of the file being downloaded, in bytes.
 *
 * The file size is only available after the download has begun.
 *
 * @param[in]  client	Client instance.
 * @param[out] size	File size.
 *
 * @retval int Zero on success, a negative error code otherwise.
 */
int download_client_file_size_get(struct download_client *client, size_t *size);

/**
 * @brief Retrieve the number of bytes downloaded so far.
 *
 * The progress is only available after the download has begun.
 *
 * @param[in]  client	Client instance.
 * @param[out] size	Number of bytes downloaded so far.
 *
 * @retval int Zero on success, a negative error code otherwise.
 */
int download_client_downloaded_size_get(struct download_client *client, size_t *size);

/**
 * @brief Download a file asynchronously.
 *
 * This initiates an asynchronous connect-download-disconnect sequence to the target
 * host. When only one file is required from a target server, it can be used instead of
 * separate calls to download_client_start() and download_client_stop().
 *
 * Downloads are handled one at a time. If previous download is not finished
 * this returns -EALREADY.
 *
 * The download is carried out in fragments of up to
 * @kconfig{CONFIG_DOWNLOAD_CLIENT_HTTP_FRAG_SIZE} bytes for HTTP, or
 * @kconfig{CONFIG_DOWNLOAD_CLIENT_COAP_BLOCK_SIZE} bytes for CoAP,
 * which are delivered to the application
 * through @ref DOWNLOAD_CLIENT_EVT_FRAGMENT events.
 *
 * @param[in] client	Client instance.
 * @param[in] host	URI of the host to connect to.
 *			Can include scheme, port number and full file path, defaults to
 *			HTTP or HTTPS if no scheme is provided.
 * @param[in] config	Configuration options.
 * @param[in] file	File to download or NULL if path is already provided in host parameter.
 * @param[in] from	Offset from where to resume the download,
 *			or zero to download from the beginning.
 *
 * @retval int Zero on success, a negative error code otherwise.
 */
int download_client_get(struct download_client *client,
			const struct download_client_host_cfg *config,
			const char *url, size_t from);

#ifdef __cplusplus
}
#endif

#endif /* DOWNLOAD_CLIENT_H__ */

#endif /* CONFIG_DOWNLOAD_CLIENT_DEPRECATED_API */

/**@} */
