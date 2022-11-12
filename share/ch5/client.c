#include <netdb.h>
#include "common.h"

/* サーバのホスト名 */
static const char* server_host = "booktls-server";

/* サーバのポート番号(commom.c) */
extern const int server_port;

/* CA証明書のパス */
#define CA_CERT "./certs/ca.pem"

static const char* txmsg_full = "full handshake\n";
static const char* txmsg_resum = "session resumption\n";
static const char* txmsg_hrr1 = "HRR 1st\n";
static const char* txmsg_hrr2 = "HRR 2nd\n";
static const char* txmsg_early = "early data\n";

static SSL_SESSION *session = NULL;

/* クライアントコンテキストの設定関数 */
void configure_client_context(SSL_CTX *ctx)
{
    /*
     * 証明書の検証に失敗した場合、ハンドシェイクを中断する設定
     */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    /*
     * サンプル向けに自己署名のCA証明書をロードする
     * 実際のアプリケーションではシステムの証明書ストアを以下の関数でロードする
     * SSL_CTX_set_default_verify_paths(ctx);
     */
    if (!SSL_CTX_load_verify_locations(ctx, CA_CERT, NULL)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

/* フルハンドシェイクのテスト */
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

    /* コンテキストの作成 */
    ssl_ctx = create_context(false);

    printf("full handshake start\n\n");

    /* クライアントコンテキストの設定 */
    configure_client_context(ssl_ctx);

    /* ソケットファミリー・タイプ */
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    do {
        /* クライアントソケットの生成 */
        client_skt = create_socket(false, hints.ai_family, hints.ai_socktype);

        sprintf(server_port_str, "%d", server_port);
        if ((err = getaddrinfo(server_host, server_port_str, &hints, &res)) != 0) {
            perror("getaddrinfo failed");
            break;
        }

        /* TCP接続の実行 */
        if (connect(client_skt, res->ai_addr,  res->ai_addrlen) != 0) {
            perror("Unable to TCP connect to server");
            break;
        } else {
            printf("TCP connection to server successful\n");
        }
        freeaddrinfo(res);

        /* クライアントSSL構造体の作成 */
        ssl = SSL_new(ssl_ctx);
        SSL_set_fd(ssl, client_skt);
        /* SNIを利用する */
        SSL_set_tlsext_host_name(ssl, server_host);
        /* サーバのホスト名をチェックする */
        SSL_set1_host(ssl, server_host);

        /* SSL接続の開始 */
        if (SSL_connect(ssl) == 1) {

            printf("SSL connection to server successful\n\n");

            txlen = strlen(txmsg_full);
            memset(txbuf, 0x00, txcap);
            memcpy(txbuf, txmsg_full, txlen);

            /* サーバへ送信 */
            if ((result = SSL_write(ssl, txbuf, txlen)) <= 0) {
                printf("Server closed connection\n");
                ERR_print_errors_fp(stderr);
                break;
            }

            /* サーバからのエコーバックを読み込み */
            rxlen = SSL_read(ssl, rxbuf, rxcap);
            if (rxlen <= 0) {
                printf("Server closed connection\n");
                ERR_print_errors_fp(stderr);
                break;
            } else {
                /* エコーバックの内容を表示 */
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

static int new_session_cb(SSL *s, SSL_SESSION *sess)
{
    if (session == NULL) {
        SSL_SESSION_up_ref(sess);
        session = sess;
    }

    if (SSL_version(s) == TLS1_3_VERSION) {
        printf("Session Ticket arrived\n");
    }

    return 0;
}

/* セッション再開 */
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

            // if (SSL_session_reused(ssl)) {
            //     printf("session reused\n");
            // } else {
            //     printf("new session\n");
            // }

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
            // printf("____SSL\n");
            SSL_shutdown(ssl);
            // printf("___SSL\n");
        }

        if (client_skt != -1) {
            close(client_skt);
            // printf("___client_skt\n");
        }
        count++;
    } while(count <= 1);

    if (ssl != NULL) {
        // printf("SSL_free_s\n");
        SSL_free(ssl);
        // printf("SSL_free_e\n");
    }

    SSL_SESSION_free(session);
    session = NULL;
    // printf("session\n");

    SSL_CTX_free(ssl_ctx);
    // printf("ssl_ctx\n");
}

int main(void)
{
    char s[2] = {0};
    while(true) {
        printf("===== TLS1.3 test menu =====\n");
        printf("1: full handshake\n");
        printf("2: session resumption\n");
        printf("3: HRR\n");
        printf("4: early data\n");
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
            default:
                break;
        }
    }
}
