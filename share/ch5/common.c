#include "common.h"

/* ポート番号 */
const int server_port = 443;

/* ソケット作成関数 */
int create_socket(bool isServer, int family, int socktype)
{
    int skt;
    int optval = 1;
    struct sockaddr_in addr;

    /* ソケットの作成 */
    skt = socket(family, socktype, 0);
    if (skt < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    /* サーバソケットの場合 */
    if (isServer) {
        addr.sin_family = family;
        addr.sin_port = htons(server_port);
        addr.sin_addr.s_addr = INADDR_ANY;

        /* アドレスの再利用 再起動用 */
        if (setsockopt(skt, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval))
                < 0) {
            perror("setsockopt(SO_REUSEADDR) failed");
            exit(EXIT_FAILURE);
        }

        /* ソケットの登録 */
        if (bind(skt, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
            perror("Unable to bind");
            exit(EXIT_FAILURE);
        }

        /* ソケットの接続準備 */
        if (listen(skt, 1) < 0) {
            perror("Unable to listen");
            exit(EXIT_FAILURE);
        }
    }

    return skt;
}

/* SSLコンテキスト作成関数 */
SSL_CTX* create_context(bool isServer)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    if (isServer)
        /* サーバ */
        method = TLS_server_method();
    else
        /* クライアント */
        method = TLS_client_method();

    ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}
