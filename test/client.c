#include "../src/kernel/mptp.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <time.h>

#define ADDR 0x8182A8C0
#define DADDR 0x8182A8C0

int gen_port()
{
	int ret;
	srand(time(NULL));
	ret = (rand() % 65536) + 1;
	if (ret == 100 || ret == 101)
		ret *= 2;
	printf("Generated source port %d\n", ret);
	return ret;
}

int main(int argc, const char *argv[])
{
    int sock;

    sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_MPTP);
    if (sock < 0) {
        perror("Failed to create socket");
        return -1;
    }

    int size = sizeof(struct sockaddr_mptp) + sizeof(struct mptp_dest);
    struct sockaddr_mptp *saddr = malloc(size);
    memset(saddr, 0, size);

    saddr->count = 1;
    inet_aton(ADDR, &(saddr->dests[0].addr));
    saddr->dests[0].port = htons(gen_port());

    if (bind(sock, (struct sockaddr *) saddr, size) < 0) {
        perror("Failed to bind socket");
        close(sock);
        return -1;
    }

    char buf[] = "Buffer1";
    char buf2[] = "Buffer2";
    struct iovec iov[2];
    struct msghdr msg;
    int size2 = sizeof(struct sockaddr_mptp) + 2 * sizeof(struct mptp_dest);
    struct sockaddr_mptp *to = malloc(size2);

    memset(&msg, 0, sizeof(msg));
    memset(&iov, 0, sizeof(iov));
    memset(to, 0, size2);

    iov[0].iov_base = buf;
    iov[0].iov_len = sizeof(buf);
    iov[1].iov_base = buf2;
    iov[1].iov_len = sizeof(buf2);

    to->count = 2;
    inet_aton(DADDR, &(to->dests[0].addr));
    to->dests[0].port = htons(100);
    inet_aton(DADDR, &(to->dests[1].addr));
    to->dests[1].port = htons(101);

    msg.msg_iov = iov;
    msg.msg_iovlen = 2;
    msg.msg_name = to;
    msg.msg_namelen = size2;

    int ret;

    ret = sendmsg(sock, &msg, sizeof(msg));
    if (ret < 0) {
        perror("Failed to send on socket");
        return -1;
    }

    printf("Sent %d bytes on socket\n", msg.msg_namelen);

    if (close(sock) < 0) {
        perror("Failed to close socket");
        return -1;
    }

    free(saddr);
    free(to);
    return 0;
}
