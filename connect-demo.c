#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* Demonstration of using tls_connect() from ktlswrapper.c for opening a
 * TLS connection then sending/receiving data as normal from the kernel using
 * transparent kernel TLS ULP. */

int tls_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

int main(void) {
    struct sockaddr_in sa = {0};
    int SocketFD;

    SocketFD = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (SocketFD == -1) {
        perror("cannot create socket");
        exit(EXIT_FAILURE);
    }

    sa.sin_family = AF_INET;
    sa.sin_port = htons(443);
    inet_pton(AF_INET, "51.81.17.217", &sa.sin_addr);

    if (tls_connect(SocketFD, (struct sockaddr *)&sa, sizeof sa) == -1) {
        perror("connect failed");
        close(SocketFD);
        exit(EXIT_FAILURE);
    }

    /* perform read write operations ... */
    const char *msg = "GET / HTTP/1.0\r\n\r\n";
    int wrote = write(SocketFD, msg, strlen(msg));
    printf("Wrote: %d\n", wrote);

    uint8_t buf[1 << 20];
    int got = read(SocketFD, buf, sizeof(buf));
    printf("Read: %d\n", got);

    printf("Got: %.*s\n", (int)sizeof(buf), buf);

    shutdown(SocketFD, SHUT_RDWR);

    close(SocketFD);
    return EXIT_SUCCESS;
}
