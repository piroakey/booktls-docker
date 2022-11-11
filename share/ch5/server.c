#include "common.h"

/* サーバ証明書のパス */
#define SERVER_CERT "./certs/server.crt"

/* キーファイル */
#define SERVER_KEY  "./certs/server.key"

/* ポート番号(commom.c) */
extern const int server_port;

/* サーバ実行フラグ */
static volatile bool server_running = true;

/* サーバコンテキストの設定関数 */
void configure_server_context(SSL_CTX *ctx)
{
    /* サーバ証明書とキーファイルの設定 */
    if (SSL_CTX_use_certificate_chain_file(ctx, SERVER_CERT) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

int main(void)
{
    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;

    int server_socket = -1;
    int client_skt = -1;

    /* 受信バッファ */
    char rxbuf[128];
    size_t rxcap = sizeof(rxbuf);
    int rxlen;

    struct sockaddr_in addr;
    unsigned int addr_len = sizeof(addr);
    
    /* コンテキストの作成 */
    ssl_ctx = create_context(true);

    printf("We are the server on port: %d\n\n", server_port);

    /* サーバコンテキストの設定 */
    configure_server_context(ssl_ctx);

    /* サーバソケットの生成  */
    server_socket = create_socket(true);

    while (server_running) {
        /* クライアントからの接続を待ち受け */
        client_skt = accept(server_socket, (struct sockaddr*) &addr,
                &addr_len);
        if (client_skt < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        printf("Client TCP connection accepted\n");

        /* サーバSSL構造体の作成 */
        ssl = SSL_new(ssl_ctx);
        SSL_set_fd(ssl, client_skt);

        /* クライアントからのSSLコネクション待ち受け */
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            server_running = false;
        } else {

            printf("Client SSL connection accepted\n\n");

            /* サーバの出力ループ */
            while (true) {
                /* クライアントからメッセージを取得する */
                /* クライアントが接続を閉じた場合は失敗する */
                if ((rxlen = SSL_read(ssl, rxbuf, rxcap)) <= 0) {
                    if (rxlen == 0) {
                        printf("Client closed connection\n");
                    }
                    ERR_print_errors_fp(stderr);
                    break;
                }
                /* ヌル終端を設定 */
                rxbuf[rxlen] = 0;
                /* "kill"の判定 */
                if (strcmp(rxbuf, "kill\n") == 0) {
                    /* サーバの終了 */
                    printf("Server received 'kill' command\n");
                    server_running = false;
                    break;
                }
                /* 受信メッセージの表示 */
                printf("Received: %s", rxbuf);
                /* クライアントへエコーバック */
                if (SSL_write(ssl, rxbuf, rxlen) <= 0) {
                    ERR_print_errors_fp(stderr);
                }
            }
        }
        if (server_running) {
            /* 次のクライアントのためのクリーンアップ */
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client_skt);
        }
    }
    printf("Server exiting...\n");

}
