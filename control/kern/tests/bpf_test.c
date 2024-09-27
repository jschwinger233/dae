// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>

//go:build exclude

#define __DEBUG

#include "../tproxy.c"

#define IP4_HLEN sizeof(struct iphdr)
#define TCP_HLEN sizeof(struct tcphdr)

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} entry_call_map SEC(".maps") = {
	.values = {
		[0] = &tproxy_wan_egress,
	},
};

SEC("tc/pktgen/hijack_by_port_80")
int testpktgen_hijack_by_port_80(struct __sk_buff *skb)
{
	bpf_skb_change_tail(skb, ETH_HLEN + IP4_HLEN + TCP_HLEN, 0);

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		bpf_printk("data + sizeof(*eth) > data_end\n");
		return TC_ACT_SHOT;
	}
	eth->h_proto = bpf_htons(ETH_P_IP);

	struct iphdr *ip = data + ETH_HLEN;
	if ((void *)(ip + 1) > data_end) {
		bpf_printk("data + sizeof(*ip) > data_end\n");
		return TC_ACT_SHOT;
	}
	ip->ihl = 5;
	ip->version = 4;
	ip->protocol = IPPROTO_TCP;
	ip->saddr = bpf_htonl(0xc0a80001); // 192.168.0.1
	ip->daddr = bpf_htonl(0x01010101); // 1.1.1.1

	struct tcphdr *tcp = data + ETH_HLEN + IP4_HLEN;
	if ((void *)(tcp + 1) > data_end) {
		bpf_printk("data + sizeof(*tcp) > data_end\n");
		return TC_ACT_SHOT;
	}
	tcp->source = bpf_htons(19233);
	tcp->dest = bpf_htons(80);
	tcp->syn = 1;

	return TC_ACT_OK;
}

SEC("tc/setup/hijack_by_port_80")
int testsetup_hijack_by_port_80(struct __sk_buff *skb)
{
	__u32 linklen = ETH_HLEN;
	bpf_map_update_elem(&linklen_map, &one_key, &linklen, BPF_ANY);

	struct match_set ms = {};
	struct port_range pr = {80, 80};
	ms.port_range = pr;
	ms.not = false;
	ms.type = MatchType_Port;
	ms.outbound = 2;
	ms.must = false;
	ms.mark = 0;

	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/hijack_by_port_80")
int testcheck_hijack_by_port_80(struct __sk_buff *skb)
{
	__u32 *status_code;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	if (data + sizeof(*status_code) > data_end) {
		bpf_printk("data + sizeof(*status_code) > data_end\n");
		return TC_ACT_SHOT;
	}

	status_code = data;
	if (*status_code != TC_ACT_REDIRECT) {
		bpf_printk("status_code(%d) != TC_ACT_REDIRECT\n", *status_code);
		return TC_ACT_SHOT;
	}

	struct ethhdr *eth = data + sizeof(*status_code);
	if ((void *)(eth + 1) > data_end) {
		bpf_printk("data + sizeof(*eth) > data_end\n");
		return TC_ACT_SHOT;
	}
	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		bpf_printk("eth->h_proto != 0x0800\n");
		return TC_ACT_SHOT;
	}

	struct iphdr *ip = (void *)eth + ETH_HLEN;
	if ((void *)(ip + 1) > data_end) {
		bpf_printk("data + sizeof(*ip) > data_end\n");
		return TC_ACT_SHOT;
	}
	if (ip->protocol != IPPROTO_TCP) {
		bpf_printk("ip->protocol != IPPROTO_TCP\n");
		return TC_ACT_SHOT;
	}
	if (ip->daddr != bpf_htonl(0x01010101)) {
		bpf_printk("ip->daddr != 1.1.1.1\n");
	}

	struct tcphdr *tcp = (void *)ip + IP4_HLEN;
	if ((void *)(tcp + 1) > data_end) {
		bpf_printk("data + sizeof(*tcp) > data_end\n");
		return TC_ACT_SHOT;
	}
	if (tcp->dest != bpf_htons(80)) {
		bpf_printk("tcp->dest != 80\n");
		return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
}
