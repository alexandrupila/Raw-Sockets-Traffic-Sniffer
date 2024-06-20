#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

typedef struct 
{
    uint32_t address;
    int count;

}ip_replies;

void processPacket(unsigned char* buffer, int size,FILE* logfile)
{   
    struct ethhdr* eth=(struct ethhdr*)(buffer);

    if(htons(eth->h_proto)!=0x800) return;

    struct iphdr *iph=(struct iphdr*) (buffer+sizeof(struct ethhdr));
    switch(iph->protocol)
    {
        case 1:
            printf("ICMP Packet received\n");
            printICMP(buffer,size,logfile);
            break;
        case 2:
            printf("IGMP Packet received\n");
            break;
        case 6:
            printf("TCP Packet received\n");
            printTCP(buffer,size,logfile);
            break;
        case 17:
            printf("UDP Packet received\n");
            printUDP(buffer,size,logfile);
            break;
        default:
            printf("Currently Unknown Packet received\n");
            break;
    }
}

void printHTTP(unsigned char* buffer, int size,FILE* logfile)
{
    unsigned short iphdrlen;
    struct iphdr* iph=(struct iphdr*) buffer;
    iphdrlen=iph->ihl*4;

    struct tcphdr* tcph=(struct tcphdr*)(buffer+iphdrlen+sizeof(struct ethhdr));
    unsigned short tcphdrlen;
    tcphdrlen=tcph->doff*4;

    int payload_offset=buffer+sizeof(struct ethhdr)+iphdrlen+tcphdrlen;

    unsigned char* http_payload=buffer+payload_offset;
    int http_payload_size=size-payload_offset;

    fprintf(logfile,"HTTP RECEIVED\n");

    fprintf(logfile,"%s",http_payload);

}

void printTCP(unsigned char* buffer, int size,FILE* logfile)
{       

    unsigned short iphdrlen;
    struct iphdr* iph=(struct iphdr*) buffer;
    iphdrlen=iph->ihl*4;

    struct tcphdr* tcph=(struct tcphdr*)(buffer+iphdrlen+sizeof(struct ethhdr));

    if(tcph->dest==80 || tcph->source==80) //aici trebuie sa modific, nu prea am dat de http pe portul ala va fi nevoie sa verific daca e GET/POST si altele in buffer
    {   
        printf("TCP CONTAINS HTTP\n");
        printHTTP(buffer,size,logfile);
        return;
    }

    fprintf(logfile,"TCP RECEIVED\n");

    fprintf(logfile,"Source port:%u Destination port:%u Seq. number:%u Ack seq:%u\n",tcph->source,tcph->dest,tcph->seq,tcph->ack_seq);
    fprintf(logfile,"FLAGS: ");
    if((int)tcph->urg) fprintf(logfile,"URG ");
    if((int)tcph->ack) fprintf(logfile,"ACK ");
    if((int)tcph->psh) fprintf(logfile,"PSH ");
    if((int)tcph->rst) fprintf(logfile,"RST ");
    if((int)tcph->syn) fprintf(logfile,"SYN ");
    if((int)tcph->fin) fprintf(logfile,"FIN ");
    fprintf(logfile,"\n");
    fprintf(logfile,"Window: %d\n",tcph->window);
    fprintf(logfile,"Checksum: %d\n",tcph->check);
    fprintf(logfile,"Urgent Pointer: %d\n",tcph->urg_ptr);

}

void printUDP(unsigned char* buffer, int size, FILE* logfile)
{
    unsigned short iphdrlen;
    struct iphdr* iph=(struct iphdr*)buffer;
    iphdrlen=iph->ihl*4;

    struct udphdr* udph=(struct udphdr*)(buffer+iphdrlen+sizeof(struct ethhdr));

    fprintf(logfile,"UDP RECEIVED\n");

    fprintf(logfile,"Source port:%u Destination port:%u Length:%u Checksum:%u\n",udph->source,udph->dest,udph->len,udph->check);

}

void printICMP(unsigned char* buffer, int size, FILE* logfile)
{
    unsigned short iphdrlen;
    struct iphdr* iph=(struct iphdr*) buffer;
    iphdrlen=iph->ihl*4;

    struct icmphdr* icmph=(struct icmphdr*) buffer+iphdrlen+sizeof(struct ethhdr);
    
    fprintf(logfile,"ICMP RECEIVED\n");

    fprintf(logfile,"Type: %d ",(unsigned int)icmph->type);

    if((unsigned int)icmph->type==11) fprintf(logfile," TTL EXPIRED\n");
    else if ((unsigned int)icmph->type==ICMP_ECHOREPLY) fprintf(logfile," ICMP ECHO REPLY\n");
    else fprintf(logfile,"\n");

    fprintf(logfile,"Code: %d\n",(unsigned int)icmph->code);
    fprintf(logfile,"Checksum: %d\n",(unsigned int)icmph->checksum);

}

void monitorICMP(unsigned char* buffer, int size, FILE* logfile)
{   
    static ip_replies repls[50];
    static int nr_of_ips=0;

    struct ethhdr* eth=(struct ethhdr*)(buffer);
    if(htons(eth->h_proto)!=0x800) return;

    struct iphdr *iph=(struct iphdr*) (buffer+sizeof(struct ethhdr));
    unsigned short iphdrlen=iph->ihl*4;

    if(iph->protocol!=1) return;

    struct icmphdr* icmph=(struct icmphdr*) buffer+iphdrlen+sizeof(struct ethhdr);

    if(icmph->type==0)
    {   
        int exists=0;
        for(int i=0;i<nr_of_ips;i++)
        {
            if(repls[i].address==iph->saddr) 
            {
                exists=1;
                repls[i].count++;
                break;
            }
        }
        if(!exists)
        {
            repls[nr_of_ips].address=iph->saddr;
            repls[nr_of_ips++].count=0;
        }

    }

    for(int i=0;i<nr_of_ips;i++)
    {
        if(repls[i].count>4)
        {   
            struct in_addr ip_addr;
            ip_addr.s_addr=repls[i].address;
            printf("Suspicious ICMP Traffic from %s\n",inet_ntoa(ip_addr));
        }
    }

}

int main(int argc, char* argv[])
{
    int saddr_size, data_size;
    struct sockaddr saddr;
    struct in_addr in;

    unsigned char* buffer=(unsigned char*) malloc (50000);

    FILE * logfile=fopen("log.txt","w");

    if(strcmp(argv[1],"--monitor")==0)
    {
        printf("Monitoring ICMP Traffic\n");
    }
    else printf("Traffic sniffer starting\n");

    int sock_raw =socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));

    if(sock_raw<0)
    {
        printf("Socket error\n");
        return 1;
    }
    int packet_nr=0;
    while(1)
    {
        saddr_size=sizeof(saddr);
        data_size=recvfrom(sock_raw,buffer,50000,0,&saddr,&saddr_size);
        if(data_size<0)
        {
            printf("Error when receiving packets");
            return 1;
        }
        if(strcmp(argv[1],"--monitor")==0) monitorICMP(buffer,data_size,logfile);
        else processPacket(buffer,data_size,logfile);
        packet_nr++;
        if(packet_nr==5000) exit(0);

    }


    return 0;
}