#include <netdb.h>
#include "common.h"

/* サーバのホスト名 */
static const char* server_host = "booktls-server";

/* サーバのポート番号(commom.c) */
extern const int server_port;

/* CA証明書のパス */
#define CA_CERT "./certs/ca.pem"

/* エコーバックするメッセージ一覧 */
static const char* txmsg_full = "full handshake test\n";
static const char* txmsg_resum = "session resumption test\n";
static const char* txmsg_hrr1 = "HRR test\n";
static const char* txmsg_early = "early data test\n";

static SSL_SESSION *session = NULL;
static SSL_SESSION *psksess = NULL;

/* クライアントコンテキストの設定関数 */
void configure_client_context(SSL_CTX *ctx)
{
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    if (!SSL_CTX_load_verify_locations(ctx, CA_CERT, NULL)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

/* フルハンドシェイクのサンプル */
void full_handshake(void)
{
    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;

    int result;
    int err;

    int client_skt = -1;
    char server_port_str[16];

    /* 送信バッファ */
    char txbuf[64];
    size_t txcap = sizeof(txbuf);
    int txlen;

    /* 受信バッファ */
    char rxbuf[128];
    size_t rxcap = sizeof(rxbuf);
    int rxlen;

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));

    ssl_ctx = create_context(false);

    printf("full handshake start\n\n");

    configure_client_context(ssl_ctx);

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    do {
        client_skt = create_socket(false, hints.ai_family, hints.ai_socktype);

        sprintf(server_port_str, "%d", server_port);
        if ((err = getaddrinfo(server_host, server_port_str, &hints, &res)) != 0) {
            perror("getaddrinfo failed");
            break;
        }

        if (connect(client_skt, res->ai_addr,  res->ai_addrlen) != 0) {
            perror("Unable to TCP connect to server");
            break;
        } else {
            printf("TCP connection to server successful\n");
        }
        freeaddrinfo(res);

        ssl = SSL_new(ssl_ctx);
        SSL_set_fd(ssl, client_skt);

        SSL_set_tlsext_host_name(ssl, server_host);

        SSL_set1_host(ssl, server_host);

        if (SSL_connect(ssl) == 1) {

            printf("SSL connection to server successful\n\n");

            txlen = strlen(txmsg_full);
            memset(txbuf, 0x00, txcap);
            memcpy(txbuf, txmsg_full, txlen);

            if ((result = SSL_write(ssl, txbuf, txlen)) <= 0) {
                printf("Server closed connection\n");
                ERR_print_errors_fp(stderr);
                break;
            }

            rxlen = SSL_read(ssl, rxbuf, rxcap);
            if (rxlen <= 0) {
                printf("Server closed connection\n");
                ERR_print_errors_fp(stderr);
                break;
            } else {
                rxbuf[rxlen] = 0;
                printf("Received: %s", rxbuf);
            }

            printf("Client exiting...\n");
        } else {

            printf("SSL connection to server failed\n\n");

            ERR_print_errors_fp(stderr);
        }
    } while(false);

    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }

    SSL_CTX_free(ssl_ctx);

    if (client_skt != -1) {
        close(client_skt);
    }
}

/* 新規セッションのコールバック */
static int new_session_cb(SSL *s, SSL_SESSION *sess)
{
    if (session == NULL) {
        SSL_SESSION_up_ref(sess);
        session = sess;
        psksess = sess;
    }

    if (SSL_version(s) == TLS1_3_VERSION) {
        printf("Session Ticket arrived\n");
    }

    return 0;
}

/* セッション再開のサンプル */
void session_resumption(void)
{
    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;

    int result;
    int err;
    int count = 0;

    int client_skt = -1;
    char server_port_str[16];

    char txbuf[64];
    size_t txcap = sizeof(txbuf);
    int txlen;

    char rxbuf[128];
    size_t rxcap = sizeof(rxbuf);
    int rxlen;

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));

    ssl_ctx = create_context(false);

    printf("session resumption start\n\n");

    configure_client_context(ssl_ctx);

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    do {
        client_skt = create_socket(false, hints.ai_family, hints.ai_socktype);

        sprintf(server_port_str, "%d", server_port);
        if ((err = getaddrinfo(server_host, server_port_str, &hints, &res)) != 0) {
            perror("getaddrinfo failed");
            break;
        }

        if (connect(client_skt, res->ai_addr,  res->ai_addrlen) != 0) {
            perror("Unable to TCP connect to server");
            break;
        } else {
            printf("TCP connection to server successful\n");
        }
        freeaddrinfo(res);

        SSL_CTX_set_session_cache_mode(ssl_ctx, SSL_SESS_CACHE_CLIENT
                                        | SSL_SESS_CACHE_NO_INTERNAL_STORE);

        SSL_CTX_sess_set_new_cb(ssl_ctx, new_session_cb);

        ssl = SSL_new(ssl_ctx);

        if (session != NULL){
            SSL_set_session(ssl, session);
            printf("set session ticket\n");
        }

        SSL_set_fd(ssl, client_skt);
        SSL_set_tlsext_host_name(ssl, server_host);
        SSL_set1_host(ssl, server_host);

        if (SSL_connect(ssl) == 1) {

            printf("SSL connection to server successful count=%d\n\n", count);

            txlen = strlen(txmsg_resum);
            memset(txbuf, 0x00, txcap);
            memcpy(txbuf, txmsg_resum, txlen);

            if ((result = SSL_write(ssl, txbuf, txlen)) <= 0) {
                printf("Server closed connection\n");
                ERR_print_errors_fp(stderr);
                break;
            }

            rxlen = SSL_read(ssl, rxbuf, rxcap);
            if (rxlen <= 0) {
                printf("Server closed connection\n");
                ERR_print_errors_fp(stderr);
                break;
            } else {
                rxbuf[rxlen] = 0;
                printf("Received: %s", rxbuf);
            }

            printf("Client exiting...\n");
        } else {

            printf("SSL connection to server failed\n\n");

            ERR_print_errors_fp(stderr);
        }

        if (ssl != NULL) {
            SSL_shutdown(ssl);
        }

        if (client_skt != -1) {
            close(client_skt);
        }
        count++;
    } while(count <= 1);

    if (ssl != NULL) {
        SSL_free(ssl);
    }

    SSL_SESSION_free(session);
    session = NULL;

    SSL_CTX_free(ssl_ctx);
}

/* Hello Retry Requestのサンプル */
void hello_retry_request(void)
{
    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;

    int result;
    int err;

    int client_skt = -1;
    char server_port_str[16];

    /* 送信バッファ */
    char txbuf[64];
    size_t txcap = sizeof(txbuf);
    int txlen;

    /* 受信バッファ */
    char rxbuf[128];
    size_t rxcap = sizeof(rxbuf);
    int rxlen;

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));

    ssl_ctx = create_context(false);

    printf("Hello Retry Request start\n\n");

    configure_client_context(ssl_ctx);

    /* supported_groupsをP-256とP-521に限定する */
    SSL_CTX_set1_groups_list(ssl_ctx, " P-256:P-521");

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    do {
        client_skt = create_socket(false, hints.ai_family, hints.ai_socktype);

        sprintf(server_port_str, "%d", server_port);
        if ((err = getaddrinfo(server_host, server_port_str, &hints, &res)) != 0) {
            perror("getaddrinfo failed");
            break;
        }

        if (connect(client_skt, res->ai_addr,  res->ai_addrlen) != 0) {
            perror("Unable to TCP connect to server");
            break;
        } else {
            printf("TCP connection to server successful\n");
        }
        freeaddrinfo(res);

        ssl = SSL_new(ssl_ctx);
        SSL_set_fd(ssl, client_skt);

        SSL_set_tlsext_host_name(ssl, server_host);

        SSL_set1_host(ssl, server_host);

        if (SSL_connect(ssl) == 1) {

            printf("SSL connection to server successful\n\n");

            txlen = strlen(txmsg_hrr1);
            memset(txbuf, 0x00, txcap);
            memcpy(txbuf, txmsg_hrr1, txlen);

            if ((result = SSL_write(ssl, txbuf, txlen)) <= 0) {
                printf("Server closed connection\n");
                ERR_print_errors_fp(stderr);
                break;
            }

            rxlen = SSL_read(ssl, rxbuf, rxcap);
            if (rxlen <= 0) {
                printf("Server closed connection\n");
                ERR_print_errors_fp(stderr);
                break;
            } else {
                rxbuf[rxlen] = 0;
                printf("Received: %s", rxbuf);
            }

            printf("Client exiting...\n");
        } else {

            printf("SSL connection to server failed\n\n");

            ERR_print_errors_fp(stderr);
        }
    } while(false);

    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }

    SSL_CTX_free(ssl_ctx);

    if (client_skt != -1) {
        close(client_skt);
    }
}

/* early data(0-RTT)のサンプル */
void early_data(void)
{
    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;

    int result;
    int err;
    int count = 0;

    int client_skt = -1;
    char server_port_str[16];

    char txbuf[64];
    size_t txcap = sizeof(txbuf);
    int txlen;

    char rxbuf[128];
    size_t rxcap = sizeof(rxbuf);
    int rxlen;

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));

    ssl_ctx = create_context(false);

    printf("early data start\n\n");

    configure_client_context(ssl_ctx);

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    do {
        client_skt = create_socket(false, hints.ai_family, hints.ai_socktype);

        sprintf(server_port_str, "%d", server_port);
        if ((err = getaddrinfo(server_host, server_port_str, &hints, &res)) != 0) {
            perror("getaddrinfo failed");
            break;
        }

        if (connect(client_skt, res->ai_addr,  res->ai_addrlen) != 0) {
            perror("Unable to TCP connect to server");
            break;
        } else {
            printf("TCP connection to server successful\n");
        }
        freeaddrinfo(res);

        SSL_CTX_set_session_cache_mode(ssl_ctx, SSL_SESS_CACHE_CLIENT
                                        | SSL_SESS_CACHE_NO_INTERNAL_STORE);

        SSL_CTX_sess_set_new_cb(ssl_ctx, new_session_cb);

        ssl = SSL_new(ssl_ctx);

        if (session != NULL){
            SSL_set_session(ssl, session);
            printf("set session\n");
        }

        SSL_set_fd(ssl, client_skt);

        SSL_set_tlsext_host_name(ssl, server_host);

        SSL_set1_host(ssl, server_host);

        /* early_dataの送信 */
        if ((psksess != NULL) && SSL_SESSION_get_max_early_data(psksess) > 0) {
            size_t writtenbytes;
            char *cbuf = "this_is_early_data";
            while (!SSL_write_early_data(ssl, cbuf, 18, &writtenbytes)) {
                switch (SSL_get_error(ssl, 0)) {
                case SSL_ERROR_WANT_WRITE:
                case SSL_ERROR_WANT_ASYNC:
                case SSL_ERROR_WANT_READ:
                    /* Just keep trying - busy waiting */
                    continue;
                default:
                    printf("Error writing early data\n");
                    ERR_print_errors_fp(stderr);
                }
                printf("send early data %ld bytes\n", writtenbytes);
            }
            
        }

        if (SSL_connect(ssl) == 1) {

            printf("SSL connection to server successful count=%d\n\n", count);

            txlen = strlen(txmsg_early);
            memset(txbuf, 0x00, txcap);
            memcpy(txbuf, txmsg_early, txlen);

            if ((result = SSL_write(ssl, txbuf, txlen)) <= 0) {
                printf("Server closed connection\n");
                ERR_print_errors_fp(stderr);
                break;
            }

            rxlen = SSL_read(ssl, rxbuf, rxcap);
            if (rxlen <= 0) {
                printf("Server closed connection\n");
                ERR_print_errors_fp(stderr);
                break;
            } else {
                rxbuf[rxlen] = 0;
                printf("Received: %s", rxbuf);
            }

            printf("Client exiting...\n");
        } else {

            printf("SSL connection to server failed\n\n");

            ERR_print_errors_fp(stderr);
        }

        if (ssl != NULL) {
            SSL_shutdown(ssl);
        }

        if (client_skt != -1) {
            close(client_skt);
        }
        count++;
    } while(count <= 1);

    if (ssl != NULL) {
        SSL_free(ssl);
    }

    SSL_SESSION_free(session);
    session = NULL;

    SSL_SESSION_free(psksess);
    psksess = NULL;

    SSL_CTX_free(ssl_ctx);
}

int main(void)
{
    char s[2] = {0};
    printf("===== TLS1.3 test menu =====\n");
    printf("1: full handshake\n");
    printf("2: session resumption\n");
    printf("3: Hello Retry Request\n");
    printf("4: early data(0-RTT)\n");
    printf("\n");
    printf("CTRL+C to exit\n\n");
    printf("> ");
    scanf("%1s%*[^\n]%*c", s);

    switch(s[0]){
        case '1':
            full_handshake();
            break;
        case '2':
            session_resumption();
            break;
        case '3':
            hello_retry_request();
            break;
        case '4':
            early_data();
            break;
        default:
            break;
    }
}
