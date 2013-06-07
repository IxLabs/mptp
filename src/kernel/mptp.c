#include <linux/module.h>
#include <linux/version.h>
#include <net/sock.h>
#include <net/protocol.h>
#include <net/ip.h>
#include <net/route.h>

#include "mptp.h"
#include "debug.h"

MODULE_DESCRIPTION("Multi-Party Transport Protocol");
MODULE_AUTHOR("Adrian Bondrescu/Cornel Mercan");
MODULE_LICENSE("GPL");

struct mptp_sock {
	struct inet_sock sock;
	/* mptp socket speciffic data */
	uint16_t src;
	uint16_t dst;
};

static struct mptp_sock *sock_port_map[MAX_MPTP_PORT];

static inline struct mptp_sock *mptp_sk(struct sock *sock)
{
	return (struct mptp_sock *)(sock);
}

static inline struct mptphdr *mptp_hdr(const struct sk_buff *skb)
{
	return (struct mptphdr *)skb_transport_header(skb);
}

static inline uint16_t get_next_free_port(void)
{
	int i;
	for (i = MIN_MPTP_PORT; i < MAX_MPTP_PORT; i++)
		if (sock_port_map[i] == NULL)
			return i;
	return 0;
}

static inline void mptp_unhash(uint16_t port)
{
	sock_port_map[port] = NULL;
}

static inline void mptp_hash(uint16_t port, struct mptp_sock *ssh)
{
	sock_port_map[port] = ssh;
}

static inline struct mptp_sock *mptp_lookup(uint16_t port)
{
	return sock_port_map[port];
}

static int mptp_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct mptp_sock *ssk = mptp_sk(sk);

	if (unlikely(!sk))
		return 0;

	mptp_unhash(ssk->src);

	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, -1);

	synchronize_net();

	sock_orphan(sk);
	sock->sk = NULL;

	skb_queue_purge(&sk->sk_receive_queue);

	log_debug("mptp_release sock=%p\n", sk);
	sock_put(sk);

	return 0;
}

static int mptp_bind(struct socket *sock, struct sockaddr *addr, int addr_len)
{
	struct sockaddr_mptp *mptp_addr;
	struct mptp_sock *ssk;
	int err;
	uint16_t port;

	if (unlikely
	    (addr_len <
	     sizeof(struct sockaddr_mptp) + sizeof(struct mptp_dest))) {
		log_error("Invalid size for sockaddr (%d)\n", addr_len);
		err = -EINVAL;
		goto out;
	}

	mptp_addr = (struct sockaddr_mptp *)addr;

	log_debug("Bind received port=%u (network order)\n",
		  mptp_addr->dests[0].port);
	port = ntohs(mptp_addr->dests[0].port);
	if (port == 0)
		port = get_next_free_port();

	if (unlikely(port == 0 || port >= MAX_MPTP_PORT)) {
		log_error("Invalid value for sockaddr port (%u)\n", port);
		err = -EINVAL;
		goto out;
	}

	if (unlikely(mptp_lookup(port) != NULL)) {
		log_error("Port %u already in use\n", port);
		err = -EADDRINUSE;
		goto out;
	}

	ssk = mptp_sk(sock->sk);
	sock->sk->sk_rcvbuf = 10 * 1024 * 1024;
	ssk->src = port;

	mptp_hash(port, ssk);

	log_debug("Socket %p bound to port %u\n", ssk, port);

	return 0;

 out:
	return err;
}

static int
mptp_connect(struct socket *sock, struct sockaddr *addr,
	     int addr_len, int flags)
{
	int err;
	struct sock *sk;
	struct inet_sock *isk;
	struct mptp_sock *ssk;

	log_debug("mptp_connect\n");

	if (unlikely(sock == NULL)) {
		log_error("Sock is NULL\n");
		err = -EINVAL;
		goto out;
	}
	sk = sock->sk;

	if (unlikely(sk == NULL)) {
		log_error("Sock->sk is NULL\n");
		err = -EINVAL;
		goto out;
	}

	isk = inet_sk(sk);
	ssk = mptp_sk(sk);

	if (unlikely(ssk->src != 0)) {
		log_error("ssk->src is not NULL\n");
		err = -EINVAL;
		goto out;
	}

	if (likely(addr)) {
		struct sockaddr_mptp *mptp_addr = (struct sockaddr_mptp *)addr;

		if (unlikely(addr_len < sizeof(*mptp_addr) ||
			     addr_len <
			     mptp_addr->count * sizeof(struct mptp_dest)
			     || mptp_addr->count <= 0)) {
			log_error("Invalid size or address family\n");
			err = -EINVAL;
			goto out;
		}
		ssk->dst = ntohs(mptp_addr->dests[0].port);
		if (unlikely(ssk->dst == 0 || ssk->dst >= MAX_MPTP_PORT)) {
			log_error("Invalid value for destination port(%u)\n",
				  ssk->dst);
			err = -EINVAL;
			goto out;
		}

		isk->inet_daddr = mptp_addr->dests[0].addr;
		log_debug
		    ("Received from user space destination port=%u and address=%u\n",
		     ssk->dst, isk->inet_daddr);
	} else {
		log_error("Invalid mptp_addr (NULL)\n");
		err = -EINVAL;
		goto out;
	}

	ssk->src = get_next_free_port();
	if (unlikely(ssk->src == 0)) {
		log_error("No free ports\n");
		err = -ENOMEM;
		goto out;
	}

	mptp_hash(ssk->src, ssk);

	return 0;

 out:
	return err;
}

static int
mptp_sendmsg(struct kiocb *iocb, struct socket *sock,
	     struct msghdr *msg, size_t len)
{
	int err;
	uint16_t dport;
	__be32 daddr;
	__be32 saddr;
	uint16_t sport;
	struct sk_buff *skb;
	struct sock *sk;
	struct inet_sock *isk;
	struct mptp_sock *ssk;
	struct mptphdr *shdr;
	int connected = 0;
	int totlen;
	int dests = 0;
	int i;
	struct sockaddr_mptp *mptp_addr = NULL;
	int ret = 0;

	if (unlikely(sock == NULL)) {
		log_error("Sock is NULL\n");
		err = -EINVAL;
		goto out;
	}
	sk = sock->sk;

	if (unlikely(sk == NULL)) {
		log_error("Sock->sk is NULL\n");
		err = -EINVAL;
		goto out;
	}

	isk = inet_sk(sk);
	ssk = mptp_sk(sk);

	sport = ssk->src;
	saddr = isk->inet_saddr;

	if (sport == 0) {
		sport = get_next_free_port();
		if (unlikely(sport == 0)) {
			log_error("No free ports\n");
			err = -ENOMEM;
			goto out;
		}
	}

	if (msg->msg_name) {
		mptp_addr = (struct sockaddr_mptp *)msg->msg_name;

		if (unlikely
		    (msg->msg_namelen <
		     sizeof(*mptp_addr) +
		     mptp_addr->count * sizeof(struct mptp_dest)
		     || mptp_addr->count <= 0)) {
			log_error
			    ("Invalid size for msg_name (size=%u, addr_count=%u)\n",
			     msg->msg_namelen, mptp_addr->count);
			err = -EINVAL;
			goto out;
		}

		dests = mptp_addr->count;
	} else {
		BUG();
		if (unlikely(!ssk->dst || !isk->inet_daddr)) {
			log_error("No destination port/address\n");
			err = -EDESTADDRREQ;
			goto out;
		}
		dport = ssk->dst;
		daddr = isk->inet_daddr;

		log_debug
		    ("Got from socket destination port=%u and address=%u\n",
		     dport, daddr);
		connected = 1;
	}

	if (msg->msg_iovlen < dests)
		dests = msg->msg_iovlen;

	for (i = 0; i < dests; i++) {
		struct rtable *rt = NULL;
		struct mptp_dest *dest = &mptp_addr->dests[i];
		struct iovec *iov = &msg->msg_iov[i];
		char *payload;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
		struct flowi fl = { };
#endif

		dport = ntohs(dest->port);
		if (unlikely(dport == 0 || dport >= MAX_MPTP_PORT)) {
			log_error("Invalid value for destination port(%u)\n",
				  dport);
			err = -EINVAL;
			goto out;
		}

		daddr = dest->addr;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
		fl.u.ip4.saddr = saddr;
		fl.u.ip4.daddr = daddr;
		fl.flowi_proto = sk->sk_protocol;
		fl.flowi_flags = inet_sk_flowi_flags(sk);
#endif

		log_debug
		    ("Received from user space destination port=%u and address=%u\n",
		     dport, daddr);

		len = iov->iov_len;
		totlen = len + sizeof(struct mptphdr) + sizeof(struct iphdr);
		skb =
		    sock_alloc_send_skb(sk, totlen,
					msg->msg_flags & MSG_DONTWAIT, &err);
		if (unlikely(!skb)) {
			log_error("sock_alloc_send_skb failed\n");
			goto out;
		}
		log_debug("Allocated %u bytes for skb (payload size=%u)\n",
			  totlen, len);

		skb_reset_network_header(skb);
		skb_reserve(skb, sizeof(struct iphdr));
		log_debug("Reseted network header\n");
		skb_reset_transport_header(skb);
		skb_put(skb, sizeof(struct mptphdr));
		log_debug("Reseted transport header\n");

		shdr = (struct mptphdr *)skb_transport_header(skb);
		shdr->dst = htons(dport);
		shdr->src = htons(sport);
		shdr->len = htons(len + sizeof(struct mptphdr));

		payload = skb_put(skb, len);
		log_debug("payload=%p\n", payload);

		err =
		    skb_copy_datagram_from_iovec(skb, sizeof(struct mptphdr),
						 iov, 0, len);
		if (unlikely(err)) {
			log_error("skb_copy_datagram_from_iovec failed\n");
			goto out_free;
		}
		log_debug("Copied %u bytes into the skb\n", len);

		if (connected)
			rt = (struct rtable *)__sk_dst_check(sk, 0);

		if (rt == NULL) {
			log_debug("rt == NULL\n");
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 39)
			struct flowi fl = {.fl4_dst = daddr,
				.proto = sk->sk_protocol,
				.flags = inet_sk_flowi_flags(sk),
			};
			err =
			    ip_route_output_flow(sock_net(sk), &rt, &fl, sk, 0);
			if (unlikely(err)) {
				log_error("Route lookup failed\n");
				goto out_free;
			}
#else
			rt = ip_route_output_flow(sock_net(sk), &fl.u.ip4, sk);
			log_debug("rt = %p\n", rt);
			if (IS_ERR(rt)) {
				log_error("Route lookup failed\n");
				goto out_free;
			}
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
			sk_dst_set(sk, dst_clone(&rt->u.dst));
#else
			sk_dst_set(sk, dst_clone(&rt->dst));
#endif
		}
		log_debug("rt != NULL\n");

		skb->local_df = 1;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 39)
		err = ip_queue_xmit(skb);
#else
		err = ip_queue_xmit(skb, &fl);
#endif
		if (likely(!err)) {
			log_debug("Sent %u bytes on wire\n", len);
			ret += len;
			dest->bytes = len;
		} else {
			log_error("ip_queue_xmit failed\n");
			dest->bytes = -1;
		}
	}

	return ret;

 out_free:
	kfree(skb);

 out:
	return err;
}

static int
mptp_recvmsg(struct kiocb *iocb, struct socket *sock,
	     struct msghdr *msg, size_t len, int flags)
{
	struct sk_buff *skb;
	struct sockaddr_mptp *mptp_addr;
	struct sock *sk = sock->sk;
	int err, copied;
	int i;
	struct sockaddr_mptp *ret_addr = (struct sockaddr_mptp *)msg->msg_name;
	ret_addr->count = 0;

	log_debug("Trying to receive sock=%p sk=%p flags=%d\n", sock, sk,
		  flags);

	skb = skb_recv_datagram(sk, flags, flags & MSG_DONTWAIT, &err);
	if (unlikely(!skb)) {
		log_error("skb_recv_datagram failed with %d\n", err);
		goto out;
	}

	for (i = 0; i < msg->msg_iovlen; i++) {
		log_debug("Received skb %p\n", skb);

		mptp_addr = (struct sockaddr_mptp *)skb->cb;

		copied = skb->len;
		if (copied > msg->msg_iov[i].iov_len) {
			copied = msg->msg_iov[i].iov_len;
			msg->msg_flags |= MSG_TRUNC;
		}

		err = skb_copy_datagram_iovec(skb, 0, &msg->msg_iov[i], copied);
		if (unlikely(err)) {
			log_error("skb_copy_datagram_iovec\n");
			goto out_free;
		}
		log_debug("Received %d bytes\n", copied);

		sock_recv_ts_and_drops(msg, sk, skb);

		if (ret_addr) {
			memcpy(&ret_addr->dests[i], &mptp_addr->dests[0],
			       sizeof(ret_addr->dests[i]));
			ret_addr->dests[i].bytes = copied;
		}

		err = copied;

 out_free:
		skb_free_datagram(sk, skb);

		if (i == msg->msg_iovlen - 1)
			break;

		skb = skb_recv_datagram(sk, flags, 1, &err);
		if (likely(err == -EAGAIN)) {
			log_debug("No more skbs in the queue, returning...\n");
			err = copied;
			break;
		}
	}

	ret_addr->count = i + 1;
	msg->msg_namelen =
	    sizeof(struct sockaddr_mptp) + (i + 1) * sizeof(struct mptp_dest);

 out:
	return err;
}

static int mptp_rcv(struct sk_buff *skb)
{
	struct mptphdr *shdr;
	struct mptp_sock *ssk;
	__be16 len;
	uint16_t src, dst;
	struct sockaddr_mptp *mptp_addr;
	int err;
	int addr_size = sizeof(struct sockaddr_mptp) + sizeof(struct mptp_dest);

	if (unlikely(!pskb_may_pull(skb, sizeof(struct mptphdr)))) {
		log_error("Insufficient space for header\n");
		goto drop;
	}

	shdr = (struct mptphdr *)skb->data;
	len = ntohs(shdr->len);

	if (unlikely(skb->len < len)) {
		log_error("Malformed packet (packet_len=%u, skb_len=%u)\n", len,
			  skb->len);
		goto drop;
	}

	if (unlikely(len < sizeof(struct mptphdr))) {
		log_error
		    ("Malformed packet (packet_len=%u sizeof(mptphdr)=%u\n",
		     len, sizeof(struct mptphdr));
		goto drop;
	}

	src = ntohs(shdr->src);
	dst = ntohs(shdr->dst);
	if (unlikely
	    (src == 0 || dst == 0 || src >= MAX_MPTP_PORT
	     || dst >= MAX_MPTP_PORT)) {
		log_error("Malformed packet (src=%u, dst=%u)\n", shdr->src,
			  shdr->dst);
		goto drop;
	}

	skb_pull(skb, sizeof(struct mptphdr));
	len -= sizeof(struct mptphdr);

	pskb_trim(skb, len);

	log_debug("Received %u bytes from from port=%u to port=%u\n",
		  len - sizeof(struct mptphdr), src, dst);

	ssk = mptp_lookup(dst);
	if (ssk == NULL) {
		log_error("MPTP lookup failed for port %u\n", dst);
		goto drop;
	}

	BUG_ON(addr_size > sizeof(skb->cb));

	mptp_addr = (struct sockaddr_mptp *)skb->cb;
	mptp_addr->dests[0].port = shdr->src;
	mptp_addr->dests[0].addr = ip_hdr(skb)->saddr;

	log_debug("Setting sin_port=%u, sin_addr=%u\n", ntohs(shdr->src),
		  mptp_addr->dests[0].addr);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
	err = ip_queue_rcv_skb((struct sock *)&ssk->sock, skb);
#else
	err = sock_queue_rcv_skb((struct sock *)&ssk->sock, skb);
#endif

	if (unlikely(err)) {
		log_error("ip_queue_rcv_skb failed with %d\n", err);
		consume_skb(skb);
	}
	return NET_RX_SUCCESS;

 drop:
	kfree(skb);
	return NET_RX_DROP;
}

static struct proto mptp_prot = {
	.obj_size = sizeof(struct mptp_sock),
	.owner = THIS_MODULE,
	.name = "MPTP",
};

static const struct proto_ops mptp_ops = {
	.family = PF_INET,
	.owner = THIS_MODULE,
	.release = mptp_release,
	.bind = mptp_bind,
	.connect = mptp_connect,
	.socketpair = sock_no_socketpair,
	.accept = sock_no_accept,
	.getname = sock_no_getname,
	.poll = datagram_poll,
	.ioctl = sock_no_ioctl,
	.listen = sock_no_listen,
	.shutdown = sock_no_shutdown,
	.setsockopt = sock_no_setsockopt,
	.getsockopt = sock_no_getsockopt,
	.sendmsg = mptp_sendmsg,
	.recvmsg = mptp_recvmsg,
	.mmap = sock_no_mmap,
	.sendpage = sock_no_sendpage,
};

static const struct net_protocol mptp_protocol = {
	.handler = mptp_rcv,
	.no_policy = 1,
	.netns_ok = 1,
};

static struct inet_protosw mptp_protosw = {
	.type = SOCK_DGRAM,
	.protocol = IPPROTO_MPTP,
	.prot = &mptp_prot,
	.ops = &mptp_ops,
	.no_check = 0,
};

static int __init mptp_init(void)
{
	int rc;

	rc = proto_register(&mptp_prot, 1);
	if (unlikely(rc)) {
		log_error("Error registering mptp protocol\n");
		goto out;
	}

	rc = inet_add_protocol(&mptp_protocol, IPPROTO_MPTP);
	if (unlikely(rc)) {
		log_error("Error adding mptp protocol\n");
		goto out_unregister;
	}

	inet_register_protosw(&mptp_protosw);
	log_debug("MPTP entered\n");

	return 0;

 out_unregister:
	proto_unregister(&mptp_prot);

 out:
	return rc;
}

static void __exit mptp_exit(void)
{
	inet_unregister_protosw(&mptp_protosw);

	inet_del_protocol(&mptp_protocol, IPPROTO_MPTP);

	proto_unregister(&mptp_prot);

	log_debug("MPTP exited\n");
}

module_init(mptp_init);
module_exit(mptp_exit);
