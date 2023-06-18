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
struct iphdr *ip_header;    

unsigned int nf_hook_ex(const struct nf_hook_ops *ops, 
						struct sk_buff *skb, 
						const struct net_device *in, 
						const struct net_device *out, 
						int (*okfn)(struct sk_buff *)) {
 
        struct sk_buff *sock_buff = (struct sk_buff *) skb;
 
        struct tcphdr *tcp_header;   // thêm biến để lưu trữ tiêu đề TCP
 
        if(!sock_buff) { 
            return NF_ACCEPT;
        }
 
        tcp_header = tcp_hdr(sock_buff);  // trích xuất tiêu đề TCP
 
        if (tcp_header) {   // kiểm tra xem gói tin có phải là TCP hay không
            printk(KERN_INFO "Drop TCP packet \n");   
            return NF_DROP;
        }
 
        return NF_ACCEPT;
}

 
/* Được gọi khi sử dụng lệnh 'insmod' */
int kmod_init(void){
        /* gán thông tin cho biến `hk` */
        hk = (struct nf_hook_ops){
                .hook = nf_hook_ex, 
				/* đây là hàm callback `nf_hook_ex` kiểu nf_hookfn - định nghĩa trong include/linux/netfilter.h, line 47
				- các tham số của hook mà người dùng định nghĩa phải khớp với kiểu nf_hookfn */
                .hooknum = NF_INET_PRE_ROUTING, 
				/* Sự kiện mà hook này đăng ký  */
                .pf = PF_INET, 
				/* Chỉ xử lý các Internet (IPv4) packet  */
                .priority = NF_IP_PRI_FIRST
				/* Cài đặt độ ưu tiên của hook này ở mức độ cao nhất*/
        };
        nf_register_hook(&hk); 
 
  return 0;
}
 
/* Được gọi khi sử dụng lệnh 'rmmod' */
void kmod_exit(void){
        nf_unregister_hook(&hk);
}
 
/* Some standard macros to pass the kernel compile script some information */
module_init(kmod_init);
module_exit(kmod_exit);
MODULE_LICENSE("GPL");
