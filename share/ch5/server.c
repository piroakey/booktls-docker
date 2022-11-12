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

int main(int argc, char *argv[])
{
    bool isHrr = false;
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

    if (argc >= 2) {
        isHrr = (argv[1][0] == 'h') ? true : false;
    }
    
    /* コンテキストの作成 */
    ssl_ctx = create_context(true);

    printf("We are the server on port: %d\n\n", server_port);

    /* サーバコンテキストの設定 */
    configure_server_context(ssl_ctx);

    /* HRRを起こすためにグループを絞る */
    if (isHrr) {
        SSL_CTX_set1_groups_list(ssl_ctx, "P-521");
        printf("HRR mode\n");
    }

    SSL_CTX_set_max_early_data(ssl_ctx, 32);

    /* サーバソケットの生成  */
    server_socket = create_socket(true, AF_INET, SOCK_STREAM);

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

        /* early_dataの読み込み */
        int write_header = 1, edret = SSL_READ_EARLY_DATA_ERROR;
        size_t readbytes;

        char buf[32] = {0};
        size_t bufsize = 32;
        while (edret != SSL_READ_EARLY_DATA_FINISH) {
            for (;;) {
                edret = SSL_read_early_data(ssl, (void*)buf, bufsize, &readbytes);
                if (edret != SSL_READ_EARLY_DATA_ERROR)
                    break;

                switch (SSL_get_error(ssl, 0)) {
                case SSL_ERROR_WANT_WRITE:
                case SSL_ERROR_WANT_ASYNC:
                case SSL_ERROR_WANT_READ:
                    /* Just keep trying - busy waiting */
                    continue;
                default:
                    printf("Error reading early data\n");
                    ERR_print_errors_fp(stderr);
                }
            }

            if (readbytes > 0) {
                if (write_header) {
                    printf("Early data received:\n");
                    write_header = 0;
                }
                printf("%s\n", buf);
            }
        }

        /* クライアントからのSSLコネクション待ち受け */
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            server_running = false;
        } else {

            printf("Client SSL connection accepted\n\n");

            /* セッション再開がされたか */
            if (SSL_session_reused(ssl)) {
                printf("session reused\n");
            } else {
                printf("new session\n");
            }

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
