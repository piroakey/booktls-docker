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

void close_completely(SSL *ssl, SSL_SESSION *session, SSL_CTX *ssl_ctx, int client_skt)
{
    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if(session != NULL) {
        SSL_SESSION_free(session);
    }
    SSL_CTX_free(ssl_ctx);

    if (client_skt != -1)
        close(client_skt);
}

void close_resum(SSL *ssl, int client_skt)
{
    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }

    if (client_skt != -1)
        close(client_skt);
}

/* フルハンドシェイクのテスト */
int full_handshake()
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

    close_completely(ssl, NULL, ssl_ctx, client_skt);

    return 0;
}

int main()
{
    full_handshake();
}
