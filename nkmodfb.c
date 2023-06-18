#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
 
static struct nf_hook_ops hk; 
struct sk_buff *sock_buff;
struct udphdr *udp_header;          //udp header struct 
struct tcphdr *tcp_header;          //tcp header struct 
struct iphdr *ip_header; 			//ip header struct    

unsigned int nf_hook_ex(const struct nf_hook_ops *ops, 
						struct sk_buff *skb, 
						const struct net_device *in, 
						const struct net_device *out, 
						int (*okfn)(struct sk_buff *)){
		
    sock_buff = (struct sk_buff *) skb;

	// Trích xuất ip header
    ip_header = (struct iphdr *)skb_network_header(sock_buff);
    if(!sock_buff) { return NF_ACCEPT;}
 
	
	/* Câu 3c Drop packets facebook.com*/
	char ip[16];
	char target[16]="157.240.199.35";
	snprintf(ip, 16, "%pI4", &ip_header->daddr);
	if (strcmp(ip, target) == 0) {
        return NF_ACCEPT;
		
	}
    printk(KERN_INFO "DROP facebook.com \n");    
	return NF_DROP;
	

}
 
/* Tự động được gọi khi người dùng gọi lệnh 'insmod' */
int kmod_init(void){
        /* khởi tạo và gán thông tin cho biến `hk` */
        hk = (struct nf_hook_ops){
				// đây là hàm callback `nf_hook_ex` kiểu nf_hookfn - định nghĩa trong include/linux/netfilter.h
                .hook = nf_hook_ex, 
				/* Sự kiện mà hook này đăng ký  */
                .hooknum = NF_INET_PRE_ROUTING, 
				/* Chỉ xử lý các Internet (IPv4) packet  */
                .pf = PF_INET, 
				/* Cài đặt độ ưu tiên của hook này ở mức độ cao nhất*/
                .priority = NF_IP_PRI_FIRST
        };
        nf_register_hook(&hk); 
 
  return 0;
}
 
/* Tự động được gọi khi người dùng gọi lệnh 'rmmod' */
void kmod_exit(void){
        nf_unregister_hook(&hk);
}
 
/* Some standard macros to pass the kernel compile script some information */
module_init(kmod_init);
module_exit(kmod_exit);
MODULE_LICENSE("GPL");
