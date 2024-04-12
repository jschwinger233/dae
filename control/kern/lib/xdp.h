struct xdp_meta {
	__u32 mark;
	__u8 l4proto;
	__u8 _pad[3];
};

const struct xdp_meta *_ __attribute__((unused));

static __always_inline struct xdp_meta *
xdp_get_meta(struct xdp_md *ctx)
{
	struct xdp_meta *meta = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	if ((void *)(meta + 1) > data_end) {
		bpf_printk("xdp_get_meta failed: data_end not enough");
		return NULL;
	}

	__builtin_memset(meta, 0, sizeof(struct xdp_meta));
	return meta;
}

static __always_inline void
xdp_reset_meta(struct xdp_md *ctx)
{
	bpf_xdp_adjust_head(ctx, (int)sizeof(struct xdp_meta));
}

static __always_inline int
xdp_handle_ipv6_extensions(struct xdp_md *ctx, __u32 offset, __u32 hdr,
			   struct icmp6hdr *icmp6h, struct tcphdr *tcph,
			   struct udphdr *udph, __u8 *ihl, __u8 *l4proto)
{
	__u8 hdr_length = 0;
	__u8 nexthdr = 0;
	*ihl = sizeof(struct ipv6hdr) / 4;
	int ret;
	// We only process TCP and UDP traffic.

	// Unroll can give less instructions but more memory consumption when loading.
	// We disable it here to support more poor memory devices.
	// #pragma unroll
	for (int i = 0; i < IPV6_MAX_EXTENSIONS;
	     i++, offset += hdr_length, hdr = nexthdr, *ihl += hdr_length / 4) {
		if (hdr_length % 4) {
			bpf_printk(
				"IPv6 extension length is not multiples of 4");
			return 1;
		}
		// See control/control_plane.go.

		switch (hdr) {
		case IPPROTO_ICMPV6:
			*l4proto = hdr;
			hdr_length = sizeof(struct icmp6hdr);
			// Assume ICMPV6 as a level 4 protocol.
			ret = bpf_xdp_load_bytes(ctx, offset, icmp6h,
						 hdr_length);
			if (ret) {
				bpf_printk("not a valid IPv6 packet");
				return -EFAULT;
			}
			return 0;

		case IPPROTO_HOPOPTS:
		case IPPROTO_ROUTING:
			ret = bpf_xdp_load_bytes(ctx, offset + 1, &hdr_length,
						 sizeof(hdr_length));
			if (ret) {
				bpf_printk("not a valid IPv6 packet");
				return -EFAULT;
			}

special_n1:
			ret = bpf_xdp_load_bytes(ctx, offset, &nexthdr,
						 sizeof(nexthdr));
			if (ret) {
				bpf_printk("not a valid IPv6 packet");
				return -EFAULT;
			}
			break;
		case IPPROTO_FRAGMENT:
			hdr_length = 4;
			goto special_n1;
		case IPPROTO_TCP:
		case IPPROTO_UDP:
			*l4proto = hdr;
			if (hdr == IPPROTO_TCP) {
				// Upper layer;
				ret = bpf_xdp_load_bytes(ctx, offset, tcph,
							 sizeof(struct tcphdr));
				if (ret) {
					bpf_printk("not a valid IPv6 packet");
					return -EFAULT;
				}
			} else if (hdr == IPPROTO_UDP) {
				// Upper layer;
				ret = bpf_xdp_load_bytes(ctx, offset, udph,
							 sizeof(struct udphdr));
				if (ret) {
					bpf_printk("not a valid IPv6 packet");
					return -EFAULT;
				}
			} else {
				// Unknown hdr.
				bpf_printk("Unexpected hdr.");
				return 1;
			}
			return 0;
		default:
			/// EXPECTED: Maybe ICMP, etc.
			// bpf_printk("IPv6 but unrecognized extension protocol: %u", hdr);
			return 1;
		}
	}
	bpf_printk("exceeds IPV6_MAX_EXTENSIONS limit");
	return 1;
}

static __always_inline int
xdp_parse_transport(struct xdp_md *ctx,
		    struct ethhdr *ethh, struct iphdr *iph, struct ipv6hdr *ipv6h,
		    struct icmp6hdr *icmp6h, struct tcphdr *tcph,
		    struct udphdr *udph, __u8 *ihl, __u16 *l3proto, __u8 *l4proto)
{
	__u32 offset = 0;
	int ret;

	__builtin_memset(ethh, 0, sizeof(struct ethhdr));
	ret = bpf_xdp_load_bytes(ctx, offset, ethh,
				 sizeof(struct ethhdr));
	if (ret) {
		bpf_printk("not ethernet packet");
		return 1;
	}
	// Skip ethhdr for next hdr.
	offset += sizeof(struct ethhdr);
	*l3proto = ethh->h_proto;

	*ihl = 0;
	*l4proto = 0;
	__builtin_memset(iph, 0, sizeof(struct iphdr));
	__builtin_memset(ipv6h, 0, sizeof(struct ipv6hdr));
	__builtin_memset(icmp6h, 0, sizeof(struct icmp6hdr));
	__builtin_memset(tcph, 0, sizeof(struct tcphdr));
	__builtin_memset(udph, 0, sizeof(struct udphdr));

	// bpf_printk("parse_transport: h_proto: %u ? %u %u", ethh->h_proto,
	//						bpf_htons(ETH_P_IP),
	// bpf_htons(ETH_P_IPV6));
	if (ethh->h_proto == bpf_htons(ETH_P_IP)) {
		ret = bpf_xdp_load_bytes(ctx, offset, iph,
					 sizeof(struct iphdr));
		if (ret)
			return -EFAULT;
		// Skip ipv4hdr and options for next hdr.
		offset += iph->ihl * 4;

		// We only process TCP and UDP traffic.
		*l4proto = iph->protocol;
		switch (iph->protocol) {
		case IPPROTO_TCP: {
			ret = bpf_xdp_load_bytes(ctx, offset, tcph,
						 sizeof(struct tcphdr));
			if (ret) {
				// Not a complete tcphdr.
				return -EFAULT;
			}
		} break;
		case IPPROTO_UDP: {
			ret = bpf_xdp_load_bytes(ctx, offset, udph,
						 sizeof(struct udphdr));
			if (ret) {
				// Not a complete udphdr.
				return -EFAULT;
			}
		} break;
		default:
			return 1;
		}
		*ihl = iph->ihl;
		return 0;
	} else if (ethh->h_proto == bpf_htons(ETH_P_IPV6)) {
		ret = bpf_xdp_load_bytes(ctx, offset, ipv6h,
					 sizeof(struct ipv6hdr));
		if (ret) {
			bpf_printk("not a valid IPv6 packet");
			return -EFAULT;
		}

		offset += sizeof(struct ipv6hdr);

		return xdp_handle_ipv6_extensions(ctx, offset, ipv6h->nexthdr,
						  icmp6h, tcph, udph, ihl, l4proto);
	} else {
		/// EXPECTED: Maybe ICMP, MPLS, etc.
		// bpf_printk("IP but not supported packet: protocol is %u",
		// iph->protocol);
		// bpf_printk("unknown link proto: %u", bpf_ntohl(skb->protocol));
		return 1;
	}
}

static __always_inline int
xdp_redirect_to_control_plane(struct xdp_md *ctx,
			      struct tuples *tuples,
			      struct ethhdr *ethh, struct tcphdr *tcph,
			      __u8 from_wan, __u16 l3proto, __u8 l4proto)
{
	struct redirect_tuple redirect_tuple = {};

	if (l3proto == bpf_htons(ETH_P_IP)) {
		redirect_tuple.sip.u6_addr32[3] = tuples->five.sip.u6_addr32[3];
		redirect_tuple.dip.u6_addr32[3] = tuples->five.dip.u6_addr32[3];
	} else {
		__builtin_memcpy(&redirect_tuple.sip, &tuples->five.sip,
				 IPV6_BYTE_LENGTH);
		__builtin_memcpy(&redirect_tuple.dip, &tuples->five.dip,
				 IPV6_BYTE_LENGTH);
	}
	redirect_tuple.l4proto = l4proto;
	struct redirect_entry redirect_entry = {};

	redirect_entry.ifindex = ctx->ingress_ifindex;
	redirect_entry.from_wan = from_wan;
	__builtin_memcpy(redirect_entry.smac, ethh->h_source,
			 sizeof(ethh->h_source));
	__builtin_memcpy(redirect_entry.dmac, ethh->h_dest,
			 sizeof(ethh->h_dest));
	bpf_map_update_elem(&redirect_track, &redirect_tuple, &redirect_entry,
			    BPF_ANY);

	struct xdp_meta *meta = xdp_get_meta(ctx);

	if (!meta) {
		bpf_printk("xdp_get_meta failed");
		return XDP_DROP; // TODO@gray: XDP_DROP
	}

	bpf_printk("meta=%llx\n", (void *)meta);
	meta->mark = TPROXY_MARK;
	if ((l4proto == IPPROTO_TCP && tcph->syn) || l4proto == IPPROTO_UDP)
		meta->l4proto = l4proto;

	return bpf_redirect(PARAM.dae0_ifindex, 0);
}
