#include <esp_log.h>
#include "esp_tls.h"

#include "TO.h"
#include "TO_helper.h"

static const char *TAG = "esp-tls-libto";

/**
 * @brief callback used by libTO to send data over socket */
static TO_lib_ret_t sock_send(void *esp_tls, const uint8_t *data, uint32_t len)
{
	esp_tls_t *tls = esp_tls;
	ssize_t ret;
	ESP_LOGD(TAG, "sending %u bytes on socket", len);
	ret = send(tls->sockfd, data, len, 0);
	if (ret < 0) {
		return TO_ERROR;
	}
	return TO_OK;
}

/**
 * @brief callback used by libTO to receive data over socket */
static TO_lib_ret_t sock_recv(void *esp_tls, uint8_t *data, uint32_t len,
					uint32_t *read_len, int32_t timeout)
{
	ssize_t ret;
	esp_tls_t *tls = esp_tls;
	ESP_LOGD(TAG, "receiving %u bytes on socket", len);
	ret = recv(tls->sockfd, data, len, 0);
	if (ret < 0) {
		*read_len = 0;
		return TO_ERROR;
	}
	*read_len = ret;
	return TO_OK;
}

/**
 * @brief called at initialization,
 * @param[out] tls context allocated by the caller
 *
 * @note this function may be called twice during initialization
 * the first time all the context is memset-ed to 0 */
void esp_libto_tls_net_init(esp_tls_t *tls)
{
	tls->libto_ctx = DEFAULT_CTX;
}

/**
 * @brief called when connection is established before handshake */
esp_err_t esp_create_libto_tls_handle(const char *hostname, size_t hostlen,
		const void *cfg, esp_tls_t *tls)
{
	TO_lib_ret_t ret;
	TOSE_ctx_t *libto_ctx = tls->libto_ctx;
	TOSE_helper_tls_ctx_t *tls_ctx = NULL;
	const esp_tls_cfg_t *esp_cfg = cfg;


	char sni[hostlen+1];
	if (hostlen > 256) {
		/* bad parameter */
		return ESP_FAIL;
	}
	memcpy(sni, hostname, hostlen); /* in case hostname is not null-terminated */
	sni[hostlen] = '\0';

	ret = TOSE_helper_tls_init_session(libto_ctx, &tls_ctx, 0,
			tls, sock_send, sock_recv);
	if(ret != TO_OK) {
		ESP_LOGE(TAG, "TO_helper_tls_init_session: %d", (int) ret);
		goto exit_fail;
	}

	uint8_t cert_slot = 0;
	long n = -1;
	if (esp_cfg->clientcert_buf) {
		n = strtol((const char *)esp_cfg->clientcert_buf, NULL, 10);
	}
	if ((n >= 0) && (n < UINT8_MAX)) {
		cert_slot = n;
	}
	ret = TOSE_helper_tls_set_config_certificate_slot(tls_ctx, cert_slot);
	if(ret != TO_OK) {
		ESP_LOGE(TAG, "TOSE_helper_tls_set_config(CERTIFICATE_SLOT): %d", (int) ret);
		goto exit_fail;
	}

	ESP_LOGI(TAG, "Setting hostname for TLS session...");
	ret = TOSE_helper_tls_set_server_name(tls_ctx, sni);
	if(ret != TO_OK) {
		ESP_LOGE(TAG, "TOSE_helper_tls_set_server_name(): %d", (int) ret);
		goto exit_fail;
	}

	ret = TOSE_helper_tls_set_config_mode(tls_ctx, TO_TLS_MODE_TLS_1_2);
	if(ret != TO_OK) {
		ESP_LOGE(TAG, "TOSE_tls_set_mode(): %d", (int) ret);
		goto exit_fail;
	}
	tls->libto_tls = tls_ctx;
	return ESP_OK;

exit_fail:
	if (tls_ctx) {
		TOSE_helper_tls_fini(tls_ctx);
	}
	return ESP_FAIL;
}

/**
 * @brief do a handshake step
 * @retval 1 OK
 * @retval 0 in progress
 * @retval -1 ERROR
 * */
int esp_libto_tls_handshake(esp_tls_t *tls, const esp_tls_cfg_t *cfg)
{
	(void) cfg;
	TO_lib_ret_t ret = TO_ERROR;
	TOSE_helper_tls_ctx_t *tls_ctx = tls->libto_tls;

	if (tls_ctx) {
		ret = TOSE_helper_tls_do_handshake_step(tls_ctx);
	}
	if (ret == TO_AGAIN) {
		return 0;
	} else if (ret == TO_OK) {
		ESP_LOGI(TAG, "Handshake Done !");
		tls->conn_state = ESP_TLS_DONE;
		return 1;
	}
	tls->conn_state = ESP_TLS_FAIL;
	return -1;
}

/**
 * @brief called to terminate the connection (may be called while the connection
 * is not established, so when esp_create_libto_tls_handle() has not been called */
void esp_libto_tls_conn_delete(esp_tls_t *tls)
{
	TOSE_helper_tls_ctx_t *tls_ctx = tls->libto_tls;
	if (tls_ctx) {
		TOSE_helper_tls_cleanup(tls_ctx);
	}
}

ssize_t esp_libto_tls_read(struct esp_tls  *tls, char *data, size_t datalen)
{
	TO_lib_ret_t ret = TO_ERROR;
	TOSE_helper_tls_ctx_t *tls_ctx = tls->libto_tls;
	uint32_t recvlen;
	if (tls_ctx) {
		ESP_LOGI(TAG, "TLS read!");
		ret = TOSE_helper_tls_receive(tls_ctx, (uint8_t*) data, datalen, &recvlen, -1);
	}
	if (ret == TO_OK) {
		return recvlen;
	}
	ESP_LOGE(TAG, "read: %04x", ret);
	return ESP_FAIL;
}

ssize_t esp_libto_tls_write(struct esp_tls *tls, const char *data, size_t datalen)
{
	TO_lib_ret_t ret = TO_ERROR;
	TOSE_helper_tls_ctx_t *tls_ctx = tls->libto_tls;
	if (tls_ctx) {
		ESP_LOGI(TAG, "TLS send %zu bytes", datalen);
		ret = TOSE_helper_tls_send(tls_ctx, (const uint8_t*) data, datalen);
	}
	if (ret == TO_OK) {
		return datalen;
	}
	ESP_LOGE(TAG, "write: %04x", ret);
	return ESP_FAIL;
}

ssize_t esp_libto_tls_get_bytes_avail(esp_tls_t *tls)
{
	ESP_LOGE(TAG, "Not available");
	return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t esp_libto_tls_init_global_ca_store(void)
{
	return ESP_OK;
}

esp_err_t esp_libto_tls_set_global_ca_store(const unsigned char *cacert_pem_buf,
		const unsigned int cacert_pem_bytes)
{
	(void) cacert_pem_buf;
	(void) cacert_pem_bytes;
	ESP_LOGE(TAG, "Not supported");
	return ESP_ERR_NOT_SUPPORTED;
}

void esp_libto_tls_free_global_ca_store(void)
{
	return;
}

