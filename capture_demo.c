/*
 *  Description : 内核抓包模块demo
 *  Date        : 20180701
 *  Author      : fuyuande
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_arp.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/skbuff.h>
#include <linux/inet.h>

#include "capture_demo.h"

#if (LINUX_VERSION_CODE <= KERNEL_VERSION(5, 3, 0))
/* Dump skb information and contents.
 *
 * Must only be called from net_ratelimit()-ed paths.
 *
 * Dumps up to can_dump_full whole packets if full_pkt, headers otherwise.
 */
void skb_dump(const char *level, const struct sk_buff *skb, bool full_pkt)
{
	static atomic_t can_dump_full = ATOMIC_INIT(5);
	struct skb_shared_info *sh = skb_shinfo(skb);
	struct net_device *dev = skb->dev;
	struct sock *sk = skb->sk;
	struct sk_buff *list_skb;
	bool has_mac, has_trans;
	int headroom, tailroom;
	int i, len, seg_len;

	if (full_pkt)
		full_pkt = atomic_dec_if_positive(&can_dump_full) >= 0;

	if (full_pkt)
		len = skb->len;
	else
		len = min_t(int, skb->len, MAX_HEADER + 128);

	headroom = skb_headroom(skb);
	tailroom = skb_tailroom(skb);

	has_mac = skb_mac_header_was_set(skb);
	has_trans = skb_transport_header_was_set(skb);

	printk("%sskb len=%u headroom=%u headlen=%u tailroom=%u\n"
	       "mac=(%d,%d) net=(%d,%d) trans=%d\n"
	       "shinfo(txflags=%u nr_frags=%u gso(size=%hu type=%u segs=%hu))\n"
	       "csum(0x%x ip_summed=%u complete_sw=%u valid=%u level=%u)\n"
	       "hash(0x%x sw=%u l4=%u) proto=0x%04x pkttype=%u iif=%d\n",
	       level, skb->len, headroom, skb_headlen(skb), tailroom,
	       has_mac ? skb->mac_header : -1,
	       has_mac ? skb_mac_header_len(skb) : -1,
	       skb->network_header,
	       has_trans ? skb_network_header_len(skb) : -1,
	       has_trans ? skb->transport_header : -1,
	       sh->tx_flags, sh->nr_frags,
	       sh->gso_size, sh->gso_type, sh->gso_segs,
	       skb->csum, skb->ip_summed, skb->csum_complete_sw,
	       skb->csum_valid, skb->csum_level,
	       skb->hash, skb->sw_hash, skb->l4_hash,
	       ntohs(skb->protocol), skb->pkt_type, skb->skb_iif);

	if (dev)
		printk("%sdev name=%s feat=0x%pNF\n",
		       level, dev->name, &dev->features);
	if (sk)
		printk("%ssk family=%hu type=%hu proto=%hu\n",
		       level, sk->sk_family, sk->sk_type, sk->sk_protocol);

	if (full_pkt && headroom)
		print_hex_dump(level, "skb headroom: ", DUMP_PREFIX_OFFSET,
			       16, 1, skb->head, headroom, false);

	seg_len = min_t(int, skb_headlen(skb), len);
	if (seg_len)
		print_hex_dump(level, "skb linear:   ", DUMP_PREFIX_OFFSET,
			       16, 1, skb->data, seg_len, false);
	len -= seg_len;

	if (full_pkt && tailroom)
		print_hex_dump(level, "skb tailroom: ", DUMP_PREFIX_OFFSET,
			       16, 1, skb_tail_pointer(skb), tailroom, false);

	for (i = 0; len && i < skb_shinfo(skb)->nr_frags; i++) {
		skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		u32 p_off, p_len, copied;
		struct page *p;
		u8 *vaddr;

		skb_frag_foreach_page(frag, frag->page_offset,
				      skb_frag_size(frag), p, p_off, p_len,
				      copied) {
			seg_len = min_t(int, p_len, len);
			vaddr = kmap_atomic(p);
			print_hex_dump(level, "skb frag:     ",
				       DUMP_PREFIX_OFFSET,
				       16, 1, vaddr + p_off, seg_len, false);
			kunmap_atomic(vaddr);
			len -= seg_len;
			if (!len)
				break;
		}
	}

	if (full_pkt && skb_has_frag_list(skb)) {
		printk("skb fraglist:\n");
		skb_walk_frags(skb, list_skb)
		    skb_dump(level, list_skb, true);
	}
}
#endif

struct dst_entry *output_dst = NULL;
//查询报文源端口或者目的端口
unsigned short capture_get_port(const struct sk_buff *skb, int dir)
{
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	unsigned short port = 0;

	iph = ip_hdr(skb);
	if (!iph) {
		log_warn("ip header null \r\n");
		return 0;
	}

	if (iph->protocol == IPPROTO_TCP) {
		tcph = tcp_hdr(skb);
		if (!tcph) {
			log_warn("tcp header null \r\n");
			return 0;
		}

		if (dir == DST_PORT) {
			port = ntohs(tcph->dest);
			tcph = NULL;
			return port;
		} else {
			port = ntohs(tcph->source);
			tcph = NULL;
			return port;
		}
	} else if (iph->protocol == IPPROTO_UDP) {
		udph = udp_hdr(skb);
		if (!udph) {
			log_warn("udp header null \r\n");
			return 0;
		}
		if (dir == DST_PORT) {
			port = ntohs(udph->dest);
			udph = NULL;
			return port;
		} else {
			port = ntohs(udph->source);
			udph = NULL;
			return port;
		}
	} else
		return 0;
}

//查询传输层协议 TCP/UDP/ICMP
unsigned int capture_get_transport_protocol(const struct sk_buff *skb)
{
	struct iphdr *iph = NULL;
	iph = ip_hdr(skb);
	if (!iph)
		return 0;

	if (iph->protocol == IPPROTO_TCP)
		return (CAPTURE_TCP);

	if (iph->protocol == IPPROTO_UDP)
		return (CAPTURE_UDP);

	return 0;
}

void parse_skb(const struct sk_buff *skb)
{
	struct iphdr *iph = NULL;
	struct udphdr *udph = NULL;

	iph = ip_hdr(skb);
	if (!iph)
		return;

	udph = udp_hdr(skb);
	if (!udph)
		return;

	print_hex_dump(KERN_INFO, "dns transaction id: ", DUMP_PREFIX_OFFSET,
		       16, 1, (char *)udph + 8, 2, false);
}

//复制报文并添加新的头域发送到指定的接收地址
int capture_send(const struct sk_buff *skb, int output)
{
	struct ethhdr *oldethh = NULL;
	struct iphdr *oldiph = NULL;
	struct iphdr *newiph = NULL;
	struct udphdr *oldudph = NULL;
	struct udphdr *newudph = NULL;
	struct sk_buff *skb_cp = NULL;
	unsigned int headlen = 0;

	// mac + ip + udp = 14 + 20 + 8 = 42, 这里分配大一点
	headlen = 60;

	//如果报文头部不够大，在复制的时候顺便扩展一下头部空间，够大的话直接复制
	if (skb_headroom(skb) < headlen) {
		skb_cp = skb_copy_expand(skb, headlen, 0, GFP_ATOMIC);
		if (!skb_cp) {
			log_warn(" realloc skb fail \r\n");
			return -ENOMEM;
		}
	} else {
		skb_cp = skb_copy(skb, GFP_ATOMIC);
		if (!skb_cp) {
			log_warn(" copy skb fail \r\n");
			return -ENOMEM;
		}
	}

	oldiph = ip_hdr(skb);
	if (!oldiph) {
		log_warn("ip header null \r\n");
		kfree_skb(skb_cp);
		return -1;
	}

	/*
	 * 抓包报文格式
	 ---------------------------------------------------------------------
	 | new mac | new ip | new udp | old mac | old ip| old tcp/udp | data |
	 ---------------------------------------------------------------------
	 |        new header          |            new data                  |            
	 ---------------------------------------------------------------------    

	 */

	//如果是出去的报文，因为是在IP层捕获，MAC层尚未填充，这里将MAC端置零，并填写协议字段
	if (output == OUTPUT_SEND) {
		skb_push(skb_cp, sizeof(struct ethhdr));
		skb_reset_mac_header(skb_cp);
		oldethh = eth_hdr(skb_cp);
		oldethh->h_proto = htons(ETH_P_IP);
		memset(oldethh->h_source, 0, ETH_ALEN);
		memset(oldethh->h_dest, 0, ETH_ALEN);
		if (skb_cp->dev != NULL)
			memcpy(oldethh->h_source, skb_cp->dev->dev_addr,
			       ETH_ALEN);
	} else {
		//如果是进来的报文，MAC层已经存在，不做任何处理，直接封装
		skb_push(skb_cp, sizeof(struct ethhdr));
		skb_reset_mac_header(skb_cp);
		oldethh = eth_hdr(skb_cp);
		oldethh->h_proto = htons(ETH_P_IP);
	}

	//添加IP, UDP头部
	skb_push(skb_cp, sizeof(struct iphdr) + sizeof(struct udphdr));
	skb_reset_network_header(skb_cp);
	skb_set_transport_header(skb_cp, sizeof(struct iphdr));
	newiph = ip_hdr(skb_cp);
	newudph = udp_hdr(skb_cp);

	if ((newiph == NULL) || (newudph == NULL)) {
		log_warn("new ip udp header null \r\n");
		kfree_skb(skb_cp);
		return -EINVAL;
	}

	/* 抓包的报文发送的时候是调用协议栈函数发送的，所以output钩子函数会捕获
	 * 到抓包报文，
	 * 这里我们要把抓包报文和正常报文区分开，区分方式就是判断源端口，我们抓
	 * 到的报文在送出去的时候填写的是保留端口0，如果钩子函数遇到这样的报文
	 * 就会直接let go 防止重复抓包，这一点在测试的时候很重要，一旦重复抓包，
	 * 系统就直接挂了...
	 */
	memcpy((unsigned char *)newiph, (unsigned char *)oldiph,
	       sizeof(struct iphdr));
	memcpy((unsigned char *)newudph, (unsigned char *)oldudph,
	       sizeof(struct iphdr));
	newudph->source = htons(0);
	newiph->saddr = in_aton("1.1.1.1");
	newudph->dest = htons(58000);	//抓包服务器端口
	newiph->daddr = in_aton("10.20.53.43");	//抓包服务器地址

	newiph->ihl = 5;
	newiph->protocol = IPPROTO_UDP;
	newudph->len =
	    htons(ntohs(oldiph->tot_len) + sizeof(struct udphdr) +
		  sizeof(struct ethhdr));
	newiph->tot_len = htons(ntohs(newudph->len) + sizeof(struct iphdr));

	/* disable gso_segment */
	skb_shinfo(skb_cp)->gso_size = htons(0);

	//计算校验和
	newudph->check = 0;
	newiph->check = 0;
	skb_cp->csum =
	    csum_partial(skb_transport_header(skb_cp), htons(newudph->len), 0);
	newudph->check =
	    csum_tcpudp_magic(newiph->saddr, newiph->daddr, htons(newudph->len),
			      IPPROTO_UDP, skb_cp->csum);

	skb_cp->ip_summed = CHECKSUM_NONE;
	if (0 == newudph->check) {
		newudph->check = CSUM_MANGLED_0;
	}
	newiph->check = ip_fast_csum((unsigned char *)newiph, newiph->ihl);

	//设置出口设备
	if (skb_dst(skb_cp) == NULL) {
		if (output_dst == NULL) {
			kfree_skb(skb_cp);
			return -1;
		} else {
			dst_hold(output_dst);
			skb_dst_set(skb_cp, output_dst);
		}
	}
	//路由查找
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0))
	if (ip_route_me_harder(&init_net, skb_cp->sk, skb_cp, RTN_UNSPEC)) {
#else
	if (ip_route_me_harder(&init_net, skb_cp, RTN_UNSPEC)) {
#endif
		kfree_skb(skb_cp);
		log_info("ip route failed \r\n");
		return -EINVAL;
	}
	//发送
	ip_local_out(&init_net, skb_cp->sk, skb_cp);

	return 0;
}

//输入钩子函数
static unsigned int capture_input_hook(void *priv,
				       struct sk_buff *skb,
				       const struct nf_hook_state *state)
{
	struct iphdr *iph = NULL;
	unsigned short sport = 0;

	iph = ip_hdr(skb);
	if (unlikely(!iph))
		return NF_ACCEPT;

	//只处理TCP和UDP
	if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
		return NF_ACCEPT;

	//源地址和目的地址相同，只抓一次，在output钩子上处理一遍就够了
	if (iph->saddr == iph->daddr)
		return NF_ACCEPT;

	//设置传输层首部指针
	skb_set_transport_header(skb, (iph->ihl * 4));

	//检查端口，端口为0的let go
	sport = capture_get_port(skb, SRC_PORT);
	if (sport == 0 || sport != 53)
		return NF_ACCEPT;

	printk(KERN_INFO "NF_INET_PRE_ROUTING!\n");
	printk(KERN_INFO "This is a DNS response!\n");

	parse_skb(skb);
#if 0
	//复制一份报文并发送出去
	capture_send(skb, INPUT_SEND);
#else
	/* skb_dump 在5.3内核之后才支持. git describe --contains */
	skb_dump(KERN_INFO, skb, false);
#endif

	//返回accept，让系统正常处理
	return NF_ACCEPT;
}

//输入钩子函数
static unsigned int capture_input_hook1(void *priv,
					struct sk_buff *skb,
					const struct nf_hook_state *state)
{
	struct iphdr *iph = NULL;
	unsigned short sport = 0;

	iph = ip_hdr(skb);
	if (unlikely(!iph))
		return NF_ACCEPT;

	//只处理TCP和UDP
	if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
		return NF_ACCEPT;

	//源地址和目的地址相同，只抓一次，在output钩子上处理一遍就够了
	if (iph->saddr == iph->daddr)
		return NF_ACCEPT;

	//设置传输层首部指针    
	skb_set_transport_header(skb, (iph->ihl * 4));

	//检查端口，端口为0的let go
	sport = capture_get_port(skb, SRC_PORT);
	if (sport == 0 || sport != 53)
		return NF_ACCEPT;

	printk(KERN_INFO "NF_INET_LOCAL_IN!\n");
	printk(KERN_INFO "This is a DNS response!\n");

	parse_skb(skb);
#if 0
	//复制一份报文并发送出去
	capture_send(skb, INPUT_SEND);
#else
	/* skb_dump 在5.3内核之后才支持. git describe --contains */
	skb_dump(KERN_INFO, skb, false);
#endif

	//返回accept，让系统正常处理
	return NF_ACCEPT;
}

//输出钩子函数
static unsigned int capture_output_hook(void *priv,
					struct sk_buff *skb,
					const struct nf_hook_state *state)
{
	struct iphdr *iph;
	unsigned short sport = 0;
	iph = ip_hdr(skb);

	if (unlikely(!iph))
		return NF_ACCEPT;

	//只处理TCP或UDP        
	if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
		return NF_ACCEPT;

	//如果源端口为0，是抓包报文，直接let it go, 否则进行抓包
	sport = capture_get_port(skb, SRC_PORT);

	if (output_dst == NULL) {
		if (skb_dst(skb) != NULL) {

			output_dst = skb_dst(skb);
			dst_hold(output_dst);
			log_info("dst get success \r\n");
		}
	}

	if (sport != 0)
		capture_send(skb, OUTPUT_SEND);

	return NF_ACCEPT;
}

static struct nf_hook_ops capture_hook_ops[] = {
	{
	 .hook = capture_input_hook,	//输入钩子处理函数
	 /*协议簇为ipv4 */
	 .pf = NFPROTO_INET,
	 /*hook的类型为在完整性校验之后，选路确定之前 */
	 .hooknum = NF_INET_PRE_ROUTING,
	 /*优先级最高 */
	 .priority = NF_IP_PRI_FIRST },
	{.hook = capture_input_hook1,
	 .hooknum = NF_INET_LOCAL_IN,
	 .pf = PF_INET,
	 .priority = NF_IP_PRI_FIRST },
#if 0
	{
	 .hook = capture_output_hook,	//输出钩子处理函数
	 /*协议簇为ipv4 */
	 .pf = PF_INET,
	 /*hook的类型为在完数据包离开本地主机“上线”之前 */
	 .hooknum = NF_INET_POST_ROUTING,
	 .priority = NF_IP_PRI_FIRST },
#endif
};

static int __init capture_init(void)
{
	//注册钩子函数, 注册实际上就是在一个nf_hook_ops链表中再插入一个nf_hook_ops结构*/
	if (nf_register_net_hooks
	    (&init_net, capture_hook_ops, ARRAY_SIZE(capture_hook_ops)) != 0) {
		log_warn("netfilter register fail");
		return -1;
	}
	log_info("capture module init \r\n");
	return 0;
}

static void __exit capture_exit(void)
{
	//注销钩子函数
	nf_unregister_net_hooks(&init_net, capture_hook_ops,
				ARRAY_SIZE(capture_hook_ops));
	if (output_dst != NULL) {
		dst_release(output_dst);
		log_info("dst release success \r\n");
	}
	log_info("capture module exit \r\n");
	return;
}

module_init(capture_init);
module_exit(capture_exit);
MODULE_ALIAS("capture");
MODULE_AUTHOR("fuyuande");
MODULE_DESCRIPTION("capture module");
MODULE_LICENSE("GPL v2");
