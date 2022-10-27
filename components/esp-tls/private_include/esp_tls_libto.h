esp_err_t esp_create_libto_tls_handle(const char *hostname, size_t hostlen,
		const void *cfg, esp_tls_t *tls);
int esp_libto_tls_handshake(esp_tls_t *tls, const esp_tls_cfg_t *cfg);
void esp_libto_tls_conn_delete(esp_tls_t *tls);
void esp_libto_tls_net_init(esp_tls_t *tls);
ssize_t esp_libto_tls_read(struct esp_tls  *tls, char *data, size_t datalen);
ssize_t esp_libto_tls_write(struct esp_tls *tls, const char *data, size_t datalen);
ssize_t esp_libto_tls_get_bytes_avail(esp_tls_t *tls);
esp_err_t esp_libto_tls_init_global_ca_store(void);
esp_err_t esp_libto_tls_set_global_ca_store(const unsigned char *cacert_pem_buf,
		const unsigned int cacert_pem_bytes);
void esp_libto_tls_free_global_ca_store(void);
