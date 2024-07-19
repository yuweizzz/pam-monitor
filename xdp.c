//go:build ignore

#include "bpf_endian.h"
#include "common.h"
#include "linux/tcp.h"
#include "linux/in.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_MAP_ENTRIES 32

struct src_pair {
    __u32 ip_src;
    __u16 port_src;
};

struct dest_pair {
    __u32 ip_dest;
    __u16 port_dest;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_MAP_ENTRIES);
    __type(key, struct src_pair);
    __type(value, struct dest_pair);
} xdp_rule_map SEC(".maps");

/*
Attempt to parse the IPv4 source address from the packet.
Returns 0 if there is no IPv4 header field; otherwise returns non-zero.
*/
static __always_inline int parse_ip_and_port(struct xdp_md *ctx,
											 struct src_pair *src,
											 struct dest_pair *dest)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

	// First, parse the ethernet header.
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return 0;
	}

	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		// The protocol is not IPv4, so we can't parse an IPv4 source address.
		return 0;
	}

	// Then parse the IP header.
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end) {
		return 0;
	}

	src->ip_src = (__u32)(ip->saddr);
	dest->ip_dest = (__u32)(ip->daddr);

	if (ip->protocol == IPPROTO_TCP) {
		struct tcphdr *tcp = (void *)(ip + 1);
		if ((void *)(tcp + 1) > data_end) {
			return 0;
		}
		src->port_src = (__u16)bpf_ntohs(tcp->source);
		dest->port_dest = (__u16)bpf_ntohs(tcp->dest);
	}

	return 1;
}

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx) {
	struct src_pair src = {0,0};
	struct dest_pair dest = {0,0};
	if (!parse_ip_and_port(ctx, &src, &dest)) {
		// Not an IPv4 packet, so don't count it.
		goto done;
	}

	bpf_map_update_elem(&xdp_rule_map, &src, &dest, BPF_ANY);

done:
	// Try changing this to XDP_DROP and see what happens!
	return XDP_PASS;
}
