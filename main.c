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
#include "utils.h"
typedef struct 
{
    uint32_t address;
    int count;

}ip_replies;

void DumpHex(const void* data, size_t size, FILE* logfile) {

    fprintf(logfile,"DATA DUMP\n");

	char ascii[17]; 
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		fprintf(logfile,"%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			fprintf(logfile," ");
			if ((i+1) % 16 == 0) {
				fprintf(logfile,"|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					fprintf(logfile," ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					fprintf(logfile,"   ");
				}
				fprintf(logfile,"|  %s \n", ascii);
			}
		}
	}
}

void printIPs(unsigned char* buffer, int size,FILE* logfile)
{   
    struct ethhdr* eth=(struct ethhdr*)(buffer);

    struct iphdr* iph=(struct iphdr*) (buffer+sizeof(struct ethhdr));

    char ipSource[INET_ADDRSTRLEN];
    inet_ntop(AF_INET,&(iph->saddr),ipSource,INET_ADDRSTRLEN);

    char ipDestination[INET_ADDRSTRLEN];
    inet_ntop(AF_INET,&(iph->daddr),ipDestination,INET_ADDRSTRLEN);

    fprintf(logfile,"Source IP Address: %s Destination IP Address: %s\r\n",ipSource,ipDestination);
}

int isDNS(unsigned char* buffer, int size,int type)
{
    unsigned short iphdrlen;
    struct iphdr* iph=(struct iphdr*) buffer+sizeof(struct ethhdr);
    iphdrlen=iph->ihl*4;

    struct dnshdr* dnsh;

    if(type==1)
    {
        struct tcphdr* tcph=(struct tcphdr*)(buffer+iphdrlen+sizeof(struct ethhdr));
        unsigned short tcphdrlen;
        tcphdrlen=tcph->doff*4;
        dnsh=(struct dnshdr*)(buffer+sizeof(struct ethhdr)+iphdrlen+tcphdrlen);
    }
    else
    {
        struct udphdr* udph=(struct udphdr*)(buffer+iphdrlen+sizeof(struct ethhdr));
        unsigned short udphdrlen=udph->len;
        dnsh=(struct dnshdr*)(buffer+sizeof(struct ethhdr)+iphdrlen+8);
    }

    
    if(ntohs(dnsh->queryOrResponse)==0 && ntohs(dnsh->numberOfAnswers)==0 && ntohs(dnsh->numberOfAuthority)==0)
    {
        printf("DNS QUERY IDENTIFIED\n");
        return 1;
    }



    return 0;


}

void processPacket(unsigned char* buffer, int size,FILE* logfile)
{   
    struct ethhdr* eth=(struct ethhdr*)(buffer);

    if(htons(eth->h_proto)==0x806)
    {
        printARP(buffer,size,logfile);
        return;
    }

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
            printIGMP(buffer,size,logfile);
            break;
        case 6:
            printf("TCP Packet received\n");
            printTCP(buffer,size,logfile,-1);
            break;
        case 17:
            printf("UDP Packet received\n");
            printUDP(buffer,size,logfile,-1);
            break;
        default:
            printf("Currently Unknown Packet received\n");
            break;
    }
}

void processFilteredPacketIP(unsigned char* buffer,int size, FILE* logfile,struct in_addr address) 
{   
    struct ethhdr* eth=(struct ethhdr*)(buffer);

    if(htons(eth->h_proto)==0x806)
    {   
         struct iphdr *iph=(struct iphdr*) (buffer+sizeof(struct ethhdr));

        if(iph->saddr==address.s_addr || iph->daddr==address.s_addr )
        {
            printARP(buffer,size,logfile);
        }
        return;
    }


    if(htons(eth->h_proto)!=0x800) return;

    struct iphdr *iph=(struct iphdr*) (buffer+sizeof(struct ethhdr));

    if(iph->saddr==address.s_addr || iph->daddr==address.s_addr )
    {
        switch(iph->protocol)
        {
        case 1:
            printf("ICMP Packet received\n");
            printICMP(buffer,size,logfile);
            break;
        case 2:
            printf("IGMP Packet received\n");
            printIGMP(buffer,size,logfile);
            break;
        case 6:
            printf("TCP Packet received\n");
            printTCP(buffer,size,logfile,-1);
            break;
        case 17:
            printf("UDP Packet received\n");
            printUDP(buffer,size,logfile,-1);
            break;
        default:
            printf("Currently Unknown Packet received\n");
            break;
        }
    }
}

void processFilteredPacketPort(unsigned char* buffer, int size, FILE* logfile, int filteredPort)
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
            printIGMP(buffer,size,logfile);
            break;
        case 6:
            printf("TCP Packet received\n");
            printTCP(buffer,size,logfile,filteredPort);
            break;
        case 17:
            printf("UDP Packet received\n");
            printUDP(buffer,size,logfile,filteredPort);
            break;
        default:
            printf("Currently Unknown Packet received\n");
            break;
        }
}

void printTCP(unsigned char* buffer, int size,FILE* logfile,int filteredPort)
{       

    unsigned short iphdrlen;
    struct iphdr* iph=(struct iphdr*) buffer+sizeof(struct ethhdr);
    iphdrlen=iph->ihl*4;

    struct tcphdr* tcph=(struct tcphdr*)(buffer+iphdrlen+sizeof(struct ethhdr));


    if(filteredPort!=-1)
    {
        if(tcph->dest!=filteredPort && tcph->source!=filteredPort) 
        {
            return;
        }
    }

    if(isDNS(buffer,size,1))
    {
        printDNS(buffer,size,1,logfile);
        return 1;
    }

    fprintf(logfile,"TCP RECEIVED\n");

    printIPs(buffer,size,logfile);

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

    DumpHex(buffer,size,logfile);

    fprintf(logfile,"--------------------------------------------------------------------------------------------\n");
}

void printUDP(unsigned char* buffer, int size, FILE* logfile,int filteredPort)
{
    unsigned short iphdrlen;
    struct iphdr* iph=(struct iphdr*)buffer+sizeof(struct ethhdr);
    iphdrlen=iph->ihl*4;

    struct udphdr* udph=(struct udphdr*)(buffer+iphdrlen+sizeof(struct ethhdr));

    if(filteredPort!=-1)
    {
        if(udph->dest!=filteredPort && udph->source!=filteredPort) 
        {
            return;
        }
    }

    if(isDNS(buffer,size,0))
    {
        printDNS(buffer,size,0,logfile);
        return 1;
    }

    fprintf(logfile,"UDP RECEIVED\n");

    printIPs(buffer,size,logfile);

    fprintf(logfile,"Source port:%u Destination port:%u Length:%u Checksum:%u\n",udph->source,udph->dest,udph->len,udph->check);

    DumpHex(buffer,size,logfile);

    fprintf(logfile,"--------------------------------------------------------------------------------------------\n");

}

void printICMP(unsigned char* buffer, int size, FILE* logfile)
{
    unsigned short iphdrlen;
    struct iphdr* iph=(struct iphdr*) buffer+sizeof(struct ethhdr);
    iphdrlen=iph->ihl*4;

    struct icmphdr* icmph=(struct icmphdr*) buffer+iphdrlen+sizeof(struct ethhdr);
    
    fprintf(logfile,"ICMP RECEIVED\n");

    printIPs(buffer,size,logfile);


    fprintf(logfile,"Type: %d ",(unsigned int)icmph->type);

    if((unsigned int)icmph->type==11) fprintf(logfile," TTL EXPIRED\n");
    else if ((unsigned int)icmph->type==ICMP_ECHOREPLY) fprintf(logfile," ICMP ECHO REPLY\n");
    else fprintf(logfile,"\n");

    fprintf(logfile,"Code: %d\n",(unsigned int)icmph->code);
    fprintf(logfile,"Checksum: %d\n",(unsigned int)icmph->checksum);

    DumpHex(buffer,size,logfile);

    fprintf(logfile,"--------------------------------------------------------------------------------------------\n");

}

void printIGMP(unsigned char* buffer, int size, FILE* logfile)
{
    unsigned short iphdrlen;
    struct iphdr* iph=(struct iphdr*) buffer+sizeof(struct ethhdr);
    iphdrlen=iph->ihl*4;

    struct igmp_header* igmph=(struct igmp_header*) buffer+iphdrlen+sizeof(struct ethhdr);
    
    fprintf(logfile,"IGMP RECEIVED\n");

    printIPs(buffer,size,logfile);

    if(igmph->type==IgmpType_MembershipQuery) 
    {
        fprintf(logfile,"IGMP Type: Membership Query\n");
    }
    else if(igmph->type==IgmpType_MembershipReportV1)
    {
        fprintf(logfile,"IGMP Type: Membership Report V1\n");
    }
    else if(igmph->type==IgmpType_MembershipReportV2)
    {
        fprintf(logfile,"IGMP Type: Membership Report V2\n");
    }
    else if(igmph->type==IgmpType_MembershipReportV3)
    {
        fprintf(logfile,"IGMP Type: Membership Report V3\n");
    }
    else if(igmph->type==IgmpType_LeaveGroup)
    {
        fprintf(logfile,"IGMP Type: Leave Group\n");
    }

    char groupIp[INET_ADDRSTRLEN];
    inet_ntop(AF_INET,&(igmph->groupAddress),groupIp,INET_ADDRSTRLEN);

    fprintf(logfile,"Group Address: %s\n",groupIp);

    DumpHex(buffer,size,logfile);

    fprintf(logfile,"--------------------------------------------------------------------------------------------\n");
}

void printARP(unsigned char* buffer, int size, FILE* logfile)
{
    struct ethhdr* eth=(struct ethhdr*)(buffer);

    printf("ARP Identified\n");

    struct arphdr* arp=(struct arphdr*)(buffer+sizeof(struct ethhdr));

    char ipSource[INET_ADDRSTRLEN];
    inet_ntop(AF_INET,&(arp->senderIpAddr),ipSource,INET_ADDRSTRLEN);

    char ipDestination[INET_ADDRSTRLEN];
    inet_ntop(AF_INET,&(arp->targetIpAddr),ipDestination,INET_ADDRSTRLEN);

    if(htons(arp->opcode)==1) 
    {   
        printf("ARP REQUEST\n");

        fprintf(logfile,"ARP RECEIVED\n");
        fprintf(logfile,"Operation type: Request\n");

        fprintf(logfile,"Sender MAC: %x, Sender IP: %s\n",arp->senderMacAddr,ipSource);

        fprintf(logfile,"Target IP Address: %s\n",ipDestination);
    }
    else if(htons(arp->opcode)==2)
    {   
        printf("ARP REPLY\n");

        fprintf(logfile,"ARP RECEIVED\n");
        fprintf(logfile,"Operation type: Reply\n");

        fprintf(logfile,"Sender MAC: %x, Sender IP: %s\n",arp->senderMacAddr,ipSource);

        fprintf(logfile,"Target MAC: %x, Target IP: %s\n",arp->targetMacAddr,ipDestination);

    }

    DumpHex(buffer,size,logfile);

    fprintf(logfile,"--------------------------------------------------------------------------------------------\n");

}

void printDNS(unsigned char* buffer, int size,int type, FILE* logfile)
{
    unsigned short iphdrlen;
    struct iphdr* iph=(struct iphdr*) buffer+sizeof(struct ethhdr);
    iphdrlen=iph->ihl*4;

    struct dnshdr* dnsh;

    if(type==1)
    {
        struct tcphdr* tcph=(struct tcphdr*)(buffer+iphdrlen+sizeof(struct ethhdr));
        unsigned short tcphdrlen;
        tcphdrlen=tcph->doff*4;
        dnsh=(struct dnshdr*)(buffer+sizeof(struct ethhdr)+iphdrlen+tcphdrlen);
    }
    else
    {
        struct udphdr* udph=(struct udphdr*)(buffer+iphdrlen+sizeof(struct ethhdr));
        unsigned short udphdrlen=udph->len;
        dnsh=(struct dnshdr*)(buffer+sizeof(struct ethhdr)+iphdrlen+8);
    }

    printf("DNS Identifiend\n");
    fprintf(logfile,"DNS RECEIVED\n");
    printIPs(buffer,size,logfile);

    if(dnsh->queryOrResponse==0) fprintf(logfile,"DNS Message Type: Query\n");
    else fprintf(logfile,"DNS Message Type: Reply\n");

    fprintf(logfile,"DNS FLAGS: ");

    if(dnsh->authoritativeAnswer) fprintf(logfile,"AA ");
    if(dnsh->truncation) fprintf(logfile,"TC ");
    if(dnsh->recursionDesired) fprintf(logfile,"RD ");
    if(dnsh->recursionAvailable) fprintf(logfile,"RA ");
    fprintf(logfile,"\n");

    fprintf(logfile,"Question Count: %d\n",htons(dnsh->numberOfQuestions));
    fprintf(logfile,"Answer Count: %d\n",htons(dnsh->numberOfAnswers));
    fprintf(logfile,"Additional Records Count: %d\n",htons(dnsh->numberOfAdditional));

    if(dnsh->queryOrResponse==0)
    {
        char* dnsQuery;
        int len;

        if(type==1)
        {
            struct tcphdr* tcph=(struct tcphdr*)(buffer+iphdrlen+sizeof(struct ethhdr));
            unsigned short tcphdrlen;
            tcphdrlen=tcph->doff*4;
            
            dnsQuery=(char*)(buffer+sizeof(struct ethhdr)+iphdrlen+tcphdrlen+12);
            len=size-(sizeof(struct ethhdr)+iphdrlen+tcphdrlen+12);
        }
        else
        {
            struct udphdr* udph=(struct udphdr*)(buffer+iphdrlen+sizeof(struct ethhdr));
            unsigned short udphdrlen=udph->len;

            dnsQuery=(char*)(buffer+sizeof(struct ethhdr)+iphdrlen+8+12);
            len=size-(sizeof(struct ethhdr)+iphdrlen+8+12);
        }

        if(len<=0)
        {
            printf("lungime mai mica de 0 %d\n",len);
        }
        else
        {
             fprintf(logfile,"Potential DNS Queries Dump:\n");

            DumpHex(dnsQuery,len,logfile);
        }

    }

    DumpHex(buffer,size,logfile);
    fprintf(logfile,"--------------------------------------------------------------------------------------------\n");
 
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
    struct in_addr ip_filter;
    int port_filter;

    unsigned char* buffer=(unsigned char*) malloc (50000);

    FILE * logfile=fopen("log.txt","w");

    if(argc>1)
    {
        if(strcmp(argv[1],"--monitor")==0)
        {
            printf("Monitoring ICMP Traffic\n");
        }
        else if (strcmp(argv[1],"--filter")==0)
        {
            if(strcmp(argv[2],"ip")==0)
            {   
            printf("Filtering traffic by ip\n");
            char str[INET_ADDRSTRLEN];
            inet_aton(argv[3],&(ip_filter.s_addr));
            }
            else if (strcmp(argv[2],"port")==0)
            {
                printf("Filtering traffic by port ");
                port_filter=atoi(argv[3]);
                printf(" %d\n",port_filter);
            }
            else 
            {
                printf("Invalid argument. Use --help to view arguments \n");
                exit(0);
            }
        }
        else if (strcmp(argv[1],"--help")==0)
        {
            printf("1. Pentru a monitoriza traficul de icmp foloseste \"sudo ./main --monitor\" \n");
            printf("2. Pentru a filtra in functie de ip foloseste \"sudo ./main --filter ip [ip] \" \n");
            printf("2. Pentru a filtra in functie de ip foloseste \"sudo ./main --filter port [port] \" \n");
            exit(0);
        }
        else 
        {
            printf("Invalid argument. Use --help to view arguments \n");
            exit(0);
        }
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
        if(argc>1)
        {
            if(strcmp(argv[1],"--monitor")==0) monitorICMP(buffer,data_size,logfile);
            else if (strcmp(argv[1],"--filter")==0) 
            {   
                if(strcmp(argv[2],"ip")==0)
                {
                processFilteredPacketIP(buffer,data_size,logfile,ip_filter);
                }
                else if (strcmp(argv[2],"port")==0)
                {
                processFilteredPacketPort(buffer,data_size,logfile,port_filter);
                }
            }
        }
        else processPacket(buffer,data_size,logfile);
        packet_nr++;
        //if(packet_nr==10) exit(0);

    }


    return 0;
}