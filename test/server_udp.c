#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <stdlib.h>

int main(int argc, const char *argv[])
{
    int sock;
	int i;

    if (argc != 2) {
        fprintf(stderr, "USAGE: %s listening_port\n", argv[0]);
        return -1;
    }

    sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        perror("Failed to create socket");
        return -1;
    }

    struct sockaddr_in saddr;
    memset(&saddr, 0, sizeof(saddr));

	inet_pton(AF_INET, "192.168.130.129", &saddr.sin_addr.s_addr);
	saddr.sin_port = htons(atoi(argv[1]));
	saddr.sin_family = AF_INET;

    if (bind(sock, (struct sockaddr *) &saddr, sizeof(saddr)) < 0) {
        perror("Failed to bind socket");
        close(sock);
        return -1;
    }

    char buf[4096];
    struct iovec iov[1];
    struct msghdr msg;
    struct sockaddr_in from;

    memset(&msg, 0, sizeof(msg));
    memset(&iov, 0, sizeof(iov));
    memset(&from, 0, sizeof(from));

	iov[0].iov_base = buf;
	iov[0].iov_len = sizeof(buf);

    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_name = &from;
    msg.msg_namelen = sizeof(from);

    int ret, fromlen;

#define N 10000

	for (i = 0; i < N; i ++) {
		ret = recvmsg(sock, &msg, 0);
		if (ret < 0) {
			perror("Failed to recv on socket");
			return -1;
		}
		if (i % (N / 50) == 0)
			printf("%d\n", i);
	}

    printf("Received %d bytes on socket\n", ret);
	printf("buf=%s\n", buf);

    if (close(sock) < 0) {
        perror("Failed to close socket");
        return -1;
    }

    return 0;
}
