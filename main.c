#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

void processPacket(unsigned char* buffer, int size)
{
    struct iphdr *iph=(struct iphdr*) buffer;
    switch(iph->protocol)
    {
        case 1:
            printf("ICMP Packet received\n");
            break;
        case 2:
            printf("IGMP Packet received\n");
            break;
        case 6:
            printf("TCP Packet received\n");
            break;
        case 17:
            printf("UDP Packet received\n");
            break;
        default:
            printf("Currently Unknown Packet received\n");
            break;
    }
}

int main()
{
    int saddr_size, data_size;
    struct sockaddr saddr;
    struct in_addr in;

    unsigned char* buffer=(unsigned char*) malloc (50000);

    FILE * logfile=fopen("log.txt","w");

    printf("Traffic sniffer starting\n");

    int sock_raw =socket(AF_INET,SOCK_RAW,IPPROTO_TCP);

    if(sock_raw<0)
    {
        printf("Socket error\n");
        return 1;
    }
    while(1)
    {
        saddr_size=sizeof(saddr);
        data_size=recvfrom(sock_raw,buffer,50000,0,&saddr,&saddr_size);
        if(data_size<0)
        {
            printf("Error when receiving packets");
            return 1;
        }
        processPacket(buffer,data_size);

    }


    return 0;
}