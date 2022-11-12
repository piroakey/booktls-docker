#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/* ソケット作成関数 */
int create_socket(bool isServer, int socktype, int family);

/* SSLコンテキスト作成関数 */
SSL_CTX* create_context(bool isServer);
