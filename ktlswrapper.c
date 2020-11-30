/**************************
 * Originally from https://github.com/zliuva/ktlswrapper
 *
 * Modified by matt to add the tls_connect() function so kernel tls offload
 * can be used from a client-only perspective instead of as server platform.
 *
 * (also added linux TLS header here directly in case systems are misconfigured)
 * */

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>

#include "tls.h"
#include <arpa/inet.h>
#include <netinet/tcp.h>

#include <dlfcn.h>

#include <mbedtls/aes.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/gcm.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_internal.h>

static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;
static mbedtls_ssl_config conf;
static mbedtls_x509_crt srvcert;
static mbedtls_pk_context srvkey;

static const int AES_128_CIPHERS[] = {
    MBEDTLS_TLS_RSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_PSK_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_DHE_PSK_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_RSA_PSK_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
    0x0};

#define PRINT_MBEDTLS_ERROR(errno)                                             \
    {                                                                          \
        char buf[256];                                                         \
        mbedtls_strerror((errno), buf, sizeof(buf));                           \
        fprintf(stderr, "[%s:%d] mbedtls error: %s\n", __FILE__, __LINE__,     \
                buf);                                                          \
    }

#define ENSURE(x)                                                              \
    {                                                                          \
        int ret = (x);                                                         \
        if (ret != 0) {                                                        \
            PRINT_MBEDTLS_ERROR(ret);                                          \
            assert(false);                                                     \
        }                                                                      \
    }

static void init_ssl_conf(void) {
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&srvcert);
    mbedtls_pk_init(&srvkey);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    ENSURE(mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                 NULL, 0));
    ENSURE(mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                       MBEDTLS_SSL_TRANSPORT_STREAM,
                                       MBEDTLS_SSL_PRESET_DEFAULT));

    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
}

bool set_crypto_info(int client, mbedtls_ssl_context *ssl, bool read) {
    struct tls12_crypto_info_aes_gcm_128 crypto_info = {
        .info = {.version = TLS_1_2_VERSION,
                 .cipher_type = TLS_CIPHER_AES_GCM_128}};

    unsigned char *salt =
        read ? ssl->transform->iv_dec : ssl->transform->iv_enc;
    unsigned char *iv = salt + 4;
    unsigned char *rec_seq = read ? ssl->in_ctr : ssl->cur_out_ctr;

    mbedtls_gcm_context *gcm_context =
        read ? ssl->transform->cipher_ctx_dec.cipher_ctx
             : ssl->transform->cipher_ctx_enc.cipher_ctx;
    mbedtls_aes_context *aes_context = gcm_context->cipher_ctx.cipher_ctx;

    memcpy(crypto_info.iv, iv, TLS_CIPHER_AES_GCM_128_IV_SIZE);
    memcpy(crypto_info.rec_seq, rec_seq, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);
    memcpy(crypto_info.key, aes_context->rk, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
    memcpy(crypto_info.salt, salt, TLS_CIPHER_AES_GCM_128_SALT_SIZE);

#if 0
    /* We have a modern kernel, but our headers aren't in the right place
     * to discover TLS_TX, so just define both locally. The values will never
     * change since they are userspace APIs. */
#define LOCAL_TLS_RX 2
#define LOCAL_TLS_TX 1
#endif

    if (setsockopt(client, SOL_TLS, read ? TLS_RX : TLS_TX, &crypto_info,
                   sizeof(crypto_info)) < 0) {
        perror("setsockopt");
        return false;
    }

    return true;
}

bool setup_ktls(int client) {
    bool success = false;

    mbedtls_ctr_drbg_reseed(&ctr_drbg, NULL, 0);

    mbedtls_ssl_context ssl;
    mbedtls_ssl_init(&ssl);

    mbedtls_ssl_conf_ciphersuites(&conf, AES_128_CIPHERS);
    ENSURE(mbedtls_ssl_setup(&ssl, &conf));

    mbedtls_ssl_set_bio(&ssl, &client, mbedtls_net_send, mbedtls_net_recv,
                        NULL);

    int ret;
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            PRINT_MBEDTLS_ERROR(ret);
            goto cleanup;
        }
    }

    if (setsockopt(client, SOL_TCP, TCP_ULP, "tls", sizeof("tls")) < 0) {
        perror("setsockopt");
        goto cleanup;
    }

    success = set_crypto_info(client, &ssl, true) &&
              set_crypto_info(client, &ssl, false);

cleanup:
    mbedtls_ssl_free(&ssl);
    return success;
}

__attribute__((constructor)) static void init(void) {
    init_ssl_conf();
}

int tls_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    printf("Running wrapped connect...\n");
    if (connect(sockfd, addr, addrlen) == -1) {
        perror("Connect failed?");
        close(sockfd);
    }

    if (!setup_ktls((sockfd))) {
        close((sockfd));
        return -ECONNABORTED;
    }

    return 0;
}
