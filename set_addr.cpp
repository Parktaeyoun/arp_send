#include "header.h"

void set_addr(addr_t *table, char *victim_ip){

    libnet_t *libnet = NULL;
    char error[LIBNET_ERRBUF_SIZE];

    if (getuid() && geteuid()) {
      fprintf(stderr, "must be run as root");
      exit(1);
    }

    // open libnet
    libnet = libnet_init(LIBNET_LINK, "ens33", error); //ens33 is device name

    //set my ip address
    table->ip_me = libnet_get_ipaddr4(libnet);

    // set victim's ip address
    table->ip_victim = libnet_name2addr4(libnet, (char *)victim_ip, LIBNET_RESOLVE);

    // Get gateway's ip address
    FILE *fp;
    char Gate[MAXLINE];

    fp = popen("ip route | grep 'default via' | cut -d' ' -f3", "r");
    if (fp == NULL)
    {
        perror("error!");
    }
    fgets(Gate, MAXLINE, fp);
    printf("My Gateway: %s", Gate);



    // set gateway's ip address
    table->ip_gateway = libnet_name2addr4(libnet, Gate, LIBNET_RESOLVE);

    // set my mac address
    struct libnet_ether_addr *mymac;
    mymac = libnet_get_hwaddr(libnet);
    memcpy(table->mac_me, mymac, ETH_ALEN);

    // Make ARP Request query
    char buff[MAXLINE] = "arping ";
    strcat(buff, (char *)victim_ip);
    strcat(buff, " -c1 | grep 'Unicast' | cut -c 35-51");

    // Get victim's mac address
    char victim_MAC[MAXLINE];
    fp = popen(buff, "r");
    if (fp == NULL)
    {
        perror("error!");
    }
    fgets(victim_MAC, MAXLINE, fp);
    printf("victim mac :%s", victim_MAC);

    // set victim's mac address
    char *ptr;
    table->mac_victim[0]=strtol(ptr=strtok(victim_MAC, ":"), &ptr, 16);
    table->mac_victim[1]=strtol(ptr=strtok(NULL, ":"), &ptr, 16);
    table->mac_victim[2]=strtol(ptr=strtok(NULL, ":"), &ptr, 16);
    table->mac_victim[3]=strtol(ptr=strtok(NULL, ":"), &ptr, 16);
    table->mac_victim[4]=strtol(ptr=strtok(NULL, ":"), &ptr, 16);
    table->mac_victim[5]=strtol(ptr=strtok(NULL, ":"), &ptr, 16);

    // Make ARP Request query
    char buff1[MAXLINE] = "arping ";
    strncat(buff1, (char *)Gate, 11);
    strcat(buff1, " -c1 | grep 'Unicast' | cut -c 33-49");

    // Get gateway's mac address
    char gateway_MAC[MAXLINE];
    int state;
    fp = popen(buff1, "r");
    if (fp == NULL)
    {
        perror("error!");
    }
    fgets(gateway_MAC, MAXLINE, fp);
    state = pclose(fp);

    printf("gateway ip :%s", Gate);
    printf("gateway mac :%s ", gateway_MAC);

    // set gateway's mac address
    char *ptr1;
    table->mac_gateway[0]=strtol(ptr1=strtok(gateway_MAC, ":"), &ptr1, 16);
    table->mac_gateway[1]=strtol(ptr1=strtok(NULL, ":"), &ptr1, 16);
    table->mac_gateway[2]=strtol(ptr1=strtok(NULL, ":"), &ptr1, 16);
    table->mac_gateway[3]=strtol(ptr1=strtok(NULL, ":"), &ptr1, 16);
    table->mac_gateway[4]=strtol(ptr1=strtok(NULL, ":"), &ptr1, 16);
    table->mac_gateway[5]=strtol(ptr1=strtok(NULL, ":"), &ptr1, 16);

    libnet_destroy(libnet);
}
