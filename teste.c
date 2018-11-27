/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * This work was partially supported by National Funds through FCT/MCTES (Portuguese Foundation
 * for Science and Technology), within the CISTER Research Unit (CEC/04234) and also by
 * Grant nr. 737459 Call H2020-ECSEL-2016-2-IA-two-stage 
 * ISEP/CISTER, Polytechnic Institute of Porto.
 * Luis Lino Ferreira (llf@isep.ipp.pt), Flávio Relvas (flaviofrelvas@gmail.com),
 * Michele Albano (mialb@isep.ipp.pt), Rafael Teles Da Rocha (rtdrh@isep.ipp.pt)
*/

// Author : Martin Casado & Flavio
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h> 
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <netinet/ether.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>

#define MAX 6

         struct my_ip
{
    u_int8_t ip_vhl; 
#define IP_V(ip) (((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip) ((ip)->ip_vhl & 0x0f)
    u_int8_t ip_tos;             
    u_int16_t ip_len;              
    u_int16_t ip_id;              
    u_int16_t ip_off;             
#define IP_DF 0x4000            
#define IP_MF 0x2000              
#define IP_OFFMASK 0x1fff         
    u_int8_t ip_ttl;              
    u_int8_t ip_p;                
    u_int16_t ip_sum;              
    struct in_addr ip_src, ip_dst; 
};

struct pkt_data
{
    struct tm *time;
    struct in_addr src;
    struct in_addr dst;
    u_int len;
};

char *dev;
char errbuf[PCAP_ERRBUF_SIZE];
pcap_t *descr;
char filter[150];
struct pkt_data **dt;
int cnt = 0;
char **data;

typedef struct
{
    int capacity;
    int size;
    int front;
    int rear;
    char **elements;
} Queue;

Queue *createQueue(int maxElements)
{
   
    Queue *Q;
    Q = (Queue *)malloc(sizeof(Queue));
    
    Q->elements = (char **)malloc(sizeof(char *) * maxElements);
    Q->size = 0;
    Q->capacity = maxElements;
    Q->front = 0;
    Q->rear = -1;
    
    return Q;
}

void Dequeue(Queue *Q)
{
    if (Q->size != 0)
    {
        Q->size--;
        Q->front++;
       
        if (Q->front == Q->capacity)
        {
            Q->front = 0;
        }
    }
    return;
}

char *front(Queue *Q)
{
    if (Q->size != 0)
    {
        
        return Q->elements[Q->front];
    }
    return NULL;
}

void Enqueue(Queue *Q, char *element)
{
    char *p = (char *)malloc(strlen(element) + 1);

   
    if (Q->size == Q->capacity)
    {
        printf("Queue is Full\n");
    }
    else
    {
        Q->size++;
        Q->rear = Q->rear + 1;
       
        if (Q->rear == Q->capacity)
        {
            Q->rear = 0;
        }

        Q->elements[Q->rear] = p; 

        
        strcpy(Q->elements[Q->rear], element);
       
    }
    return;
}

int Queue_size(Queue *Q)
{
    return Q->size;
}

const void handle_IP(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{

  
    Queue *q = (Queue *)args;
    
    time_t now = time(0);
    struct tm *mytime = localtime(&now);
    const struct my_ip *ip;
    u_int length = pkthdr->len;
    u_int hlen, off, version;
    int i;
   

    int len;
    if (packet != NULL)
    {
       
        
        ip = (struct my_ip *)(packet + sizeof(struct ether_header));
        length -= sizeof(struct ether_header);

      
        if (length < sizeof(struct my_ip))
        {
            printf("truncated ip %d", length);
            return;
        }

        len = ntohs(ip->ip_len);
        hlen = IP_HL(ip);   
        version = IP_V(ip); 

    
        if (hlen < 5)
        {
            printf("bad-hlen %d \n", hlen);
        }

   
        if (length < len)
        {
            printf("\ntruncated IP - %d bytes missing\n", len - length);
        }

        off = ntohs(ip->ip_off);
        if ((off & 0x1fff) == 0)
        { 
            char src[150];
            strcpy(src, inet_ntoa(ip->ip_src));
          
            sprintf((src + strlen(src)), ", %s, %d,%s\0", inet_ntoa(ip->ip_dst), len, asctime(mytime));
       
            Enqueue(q, src);
            cnt++;
           
            return;
        }
    }
    else
    {
        printf("What happend?\n");
    }
}

void capture1(Queue *q)
{
   
    struct ether_header *eptr; 
    u_char *ptr;               
    struct bpf_program fp;     
    bpf_u_int32 maskp;        
    bpf_u_int32 netp;      




    pcap_lookupnet(dev, &netp, &maskp, errbuf);

    if (pcap_compile(descr, &fp, filter, 0, netp) == -1)
    {
        fprintf(stderr, "Error calling pcap_compile\n");
        exit(1);
    }

    if (pcap_setfilter(descr, &fp) == -1)
    {
        fprintf(stderr, "Error setting filter\n");
        exit(1);
    }


    struct pcap_pkthdr hdr;
    u_char *packet;
    packet = pcap_next(descr, &hdr);
    if (packet != NULL)
    {
        //printf("n\n");
        printf("I Have a Packet!\n");
        handle_IP((u_char *)q, &hdr, packet);
    }

}

void capture(Queue *q)
{
    int i;
    cnt = 0;
    const u_char *packet;
    struct pcap_pkthdr hdr;   
    struct ether_header *eptr;
    u_char *ptr;             
    struct bpf_program fp;    
    bpf_u_int32 maskp;       
    bpf_u_int32 netp;         


    pcap_lookupnet(dev, &netp, &maskp, errbuf);

    if (pcap_compile(descr, &fp, filter, 0, netp) == -1)
    {
        fprintf(stderr, "Error calling pcap_compile\n");
        exit(1);
    }

    if (pcap_setfilter(descr, &fp) == -1)
    {
        fprintf(stderr, "Error setting filter\n");
        exit(1);
    }

    pcap_loop(descr, -1, handle_IP, (u_char *)q);

    fprintf(stdout, "\nDone processing packets... wheew!\n");
    return;
}

void stop(pcap_t *descr)
{
    printf("STOPPING\n");
    pcap_breakloop(descr);
}

void handleDev(char * netif)
{
    pcap_if_t **devs = malloc(sizeof(pcap_if_t));
    /* grab a device to peak into... */
    pcap_findalldevs(devs, errbuf);

    if (devs == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }
    int c = 0;
    while (devs != NULL)
    {
        printf("%s\n", devs[0]->name);
        if (strcmp(devs[0]->name, netif) == 0)
        {
            dev = devs[0]->name;
            break;
        }
        devs = devs[0]->next;
    }

    printf("DEV OK\n");
}

void handleDescr()
{
    descr = pcap_open_live(dev, BUFSIZ, 0, -1, errbuf);
    if (descr == NULL)
    {
        printf("pcap_open_live(): %s\n", errbuf);
        exit(1);
    }
    printf("DESCR OK\n");
}

int main(int argc, char **argv)
{
    
    char consumer[50];
    char producer[50];
    handleDev("enp4s0");
    handleDescr();

    strcpy(consumer,"192.168.60.157");
    strcpy(producer,"172.16.3.70");

    strcpy(filter,"host ");
    strcat(filter,consumer);
    strcat(filter," or ");
    strcat(filter, producer);
    printf("%s\n",filter);

    Queue *q = createQueue(100);
    pthread_t thread_id;
    pthread_create(&thread_id, NULL, capture, q);
    while (1)
    {
        sleep(1);
        while (q->size != 0)
        {
            char *s = front(q);
            //printf("%s", s);
            Dequeue(q);
            char * token;
            int i =0;
            token =strtok(s, ",");
            while( token !=NULL){
                if(i==0 && strcmp(token,consumer)){
                    
                }
                printf("%s\n", token);

                token = strtok(NULL,",");
            }
        }
    }
    return 0;
}