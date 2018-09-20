/*************************************************** 
* file:     testpcap1.c 
* Date:     Thu Mar 08 17:14:36 MST 2001  
* Author:   Martin Casado 
* Location: LAX Airport (hehe) 
* 
* Simple single packet capture program 
*****************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h> /* if this gives you an error try pcap/pcap.h */
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <netinet/ether.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>

#define MAX 6

/*
 * Structure of an internet header, naked of options.
 *
 * Stolen from tcpdump source (thanks tcpdump people)
 *
 * We declare ip_len and ip_off to be short, rather than u_short
 * pragmatically since otherwise unsigned comparisons can result
 * against negative integers quite easily, and fail in subtle ways.
 */
struct my_ip
{
    u_int8_t ip_vhl; /* header length, version */
#define IP_V(ip) (((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip) ((ip)->ip_vhl & 0x0f)
    u_int8_t ip_tos;               /* type of service */
    u_int16_t ip_len;              /* total length */
    u_int16_t ip_id;               /* identification */
    u_int16_t ip_off;              /* fragment offset field */
#define IP_DF 0x4000               /* dont fragment flag */
#define IP_MF 0x2000               /* more fragments flag */
#define IP_OFFMASK 0x1fff          /* mask for fragmenting bits */
    u_int8_t ip_ttl;               /* time to live */
    u_int8_t ip_p;                 /* protocol */
    u_int16_t ip_sum;              /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
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
char *filter;
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

/* crateQueue function takes argument the maximum number of elements the Queue can hold, creates
   a Queue according to it and returns a pointer to the Queue. */
Queue *createQueue(int maxElements)
{
    /* Create a Queue */
    Queue *Q;
    Q = (Queue *)malloc(sizeof(Queue));
    /* Initialise its properties */
    Q->elements = (char **)malloc(sizeof(char *) * maxElements);
    Q->size = 0;
    Q->capacity = maxElements;
    Q->front = 0;
    Q->rear = -1;
    /* Return the pointer */
    return Q;
}

void Dequeue(Queue *Q)
{
    if (Q->size != 0)
    {
        Q->size--;
        Q->front++;
        /* As we fill elements in circular fashion */
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
        /* Return the element which is at the front*/
        return Q->elements[Q->front];
    }
    return NULL;
}

void Enqueue(Queue *Q, char *element)
{
    char *p = (char *)malloc(strlen(element) + 1);

    /* If the Queue is full, we cannot push an element into it as there is no space for it.*/
    if (Q->size == Q->capacity)
    {
        printf("Queue is Full\n");
    }
    else
    {
        Q->size++;
        Q->rear = Q->rear + 1;
        /* As we fill the queue in circular fashion */
        if (Q->rear == Q->capacity)
        {
            Q->rear = 0;
        }

        Q->elements[Q->rear] = p; //(char *) malloc((sizeof element + 1)* sizeof(char));

        /* Insert the element in its rear side */
        strcpy(Q->elements[Q->rear], element);
        //printf("%d\n",Q->size);
    }
    return;
}

int Queue_size(Queue *Q)
{
    return Q->size;
}

const void handle_IP(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{

    //printf("Is it a good packet?\n");
    Queue *q = (Queue *)args;
    //char * r;
    time_t now = time(0);
    struct tm *mytime = localtime(&now);
    const struct my_ip *ip;
    u_int length = pkthdr->len;
    u_int hlen, off, version;
    int i;
    //sprintf(r,"\0");

    int len;
    if (packet != NULL)
    {
        //printf("Packet NULL\n");
        //ret = "";
        //return ;

        /* jump pass the ethernet header */
        ip = (struct my_ip *)(packet + sizeof(struct ether_header));
        length -= sizeof(struct ether_header);

        /* check to see we have a packet of valid length */
        if (length < sizeof(struct my_ip))
        {
            printf("truncated ip %d", length);
            return;
        }

        len = ntohs(ip->ip_len);
        hlen = IP_HL(ip);   /* header length */
        version = IP_V(ip); /* ip version */

        /* check header length */
        if (hlen < 5)
        {
            printf("bad-hlen %d \n", hlen);
        }

        /* see if we have as much packet as we should */
        if (length < len)
        {
            printf("\ntruncated IP - %d bytes missing\n", len - length);
        }
        /* Check to see if we have the first fragment */
        off = ntohs(ip->ip_off);
        if ((off & 0x1fff) == 0)
        { /* aka no 1's in first 13 bits */
            /* print SOURCE DESTINATION hlen version len offset */
            //printf("Yes, very good packet.\n");
            char src[150];
            strcpy(src, inet_ntoa(ip->ip_src));
            //sprintf(r,"%s",src);
            sprintf((src + strlen(src)), ", %s, %d,%s\0", inet_ntoa(ip->ip_dst), len, asctime(mytime));
            //printf("%s\n", src);
            Enqueue(q, src);
            cnt++;
            //insert(r);
            //dt[cnt]->src=ip->ip_src;
            //dt[cnt]->dst=ip->ip_dst;
            //dt[cnt]->time=mytime;
            //fprintf(stdout,"Time: %s ,IP: ",asctime(mytime));
            //fprintf(stdout,"P-%s ",
            //        inet_ntoa(ip->ip_src));
            //fprintf(stdout,"%s %d %d %d %d %d %d\n",
            //        inet_ntoa(ip->ip_dst),
            //        hlen,version,len,off,
            //        ip->ip_p,ip->ip_tos);
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
    //char * ret = malloc(sizeof(char)*150);
    //*ret ='\0';
    struct ether_header *eptr; /* net/ethernet.h */
    u_char *ptr;               /* printing out hardware header info */
    struct bpf_program fp;     /* hold compiled program     */
    bpf_u_int32 maskp;         /* subnet mask               */
    bpf_u_int32 netp;          /* ip                        */

    /* open the device for sniffing. 
       pcap_t *pcap_open_live(char *device,int snaplen, int prmisc,int to_ms, 
       char *ebuf) 
       snaplen - maximum size of packets to capture in bytes 
       promisc - set card in promiscuous mode? 
       to_ms   - time to wait for packets in miliseconds before read 
       times out 
       errbuf  - if something happens, place error string here        Note if you change "prmisc" param to anything other than zero, you will 
       get all packets your device sees, whether they are intendeed for you or 
       not!! Be sure you know the rules of the network you are running on 
       before you set your card in promiscuous mode!!     */

    /* ask pcap for the network address and mask of the device */
    pcap_lookupnet(dev, &netp, &maskp, errbuf);

    /* Lets try and compile the program.. non-optimized */
    if (pcap_compile(descr, &fp, filter, 0, netp) == -1)
    {
        fprintf(stderr, "Error calling pcap_compile\n");
        exit(1);
    }

    /* set the compiled program as the filter */
    if (pcap_setfilter(descr, &fp) == -1)
    {
        fprintf(stderr, "Error setting filter\n");
        exit(1);
    }

    /* 
       grab a packet from descr (yay!)                     
       u_char *pcap_next(pcap_t *p,struct pcap_pkthdr *h)  
       so just pass in the descriptor we got from          
       our call to pcap_open_live and an allocated         
       struct pcap_pkthdr                                 */
    //  char* opt;
    struct pcap_pkthdr hdr;
    u_char *packet;
    packet = pcap_next(descr, &hdr);
    if (packet != NULL)
    {
        //printf("n\n");
        printf("I Have a Packet!\n");
        handle_IP((u_char *)q, &hdr, packet);
    }
    //return ret;
    //strcpy(s,ret);
}

void capture(Queue *q)
{
    int i;
    cnt = 0;
    const u_char *packet;
    struct pcap_pkthdr hdr;    /* pcap.h */
    struct ether_header *eptr; /* net/ethernet.h */
    u_char *ptr;               /* printing out hardware header info */
    struct bpf_program fp;     /* hold compiled program     */
    bpf_u_int32 maskp;         /* subnet mask               */
    bpf_u_int32 netp;          /* ip                        */

    /* ask pcap for the network address and mask of the device */
    pcap_lookupnet(dev, &netp, &maskp, errbuf);

    //printf("%d / %d\n", netp,maskp);
    /* Lets try and compile the program.. non-optimized */
    if (pcap_compile(descr, &fp, filter, 0, netp) == -1)
    {
        fprintf(stderr, "Error calling pcap_compile\n");
        exit(1);
    }

    /* set the compiled program as the filter */
    if (pcap_setfilter(descr, &fp) == -1)
    {
        fprintf(stderr, "Error setting filter\n");
        exit(1);
    }

    /* allright here we call pcap_loop(..) and pass in our callback function */
    /* int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user)*/
    /* If you are wondering what the user argument is all about, so am I!!   */
    pcap_loop(descr, -1, handle_IP, (u_char *)q);

    fprintf(stdout, "\nDone processing packets... wheew!\n");
    /**
       *  
       * do
       {
           packet = pcap_next(descr,&hdr); 
           if(packet != NULL){
                printf("Grabbed packet of length %d\n",hdr.len); 
                //printf("Recieved at ..... %s\n",ctime((const time_t*)&hdr.ts.tv_sec));  
                printf("Ethernet address length is %d\n",ETH_HLEN); 
                /* lets start with the ether header... 
                eptr = (struct ether_header *) packet; 
                /* Do a couple of checks to see what packet type we have..
                if (ntohs (eptr->ether_type) == ETHERTYPE_IP) 
                { 
                    printf("Ethernet type hex:%x dec:%d is an IP packet\n", 
                            ntohs(eptr->ether_type), 
                            ntohs(eptr->ether_type)); 
                }else  if (ntohs (eptr->ether_type) == ETHERTYPE_ARP) 
                { 
                    printf("Ethernet type hex:%x dec:%d is an ARP packet\n", 
                            ntohs(eptr->ether_type), 
                            ntohs(eptr->ether_type)); 
                }else { 
                    printf("Ethernet type %x not IP", ntohs(eptr->ether_type)); 
                    //exit(1); 
                } 

                handle_IP(NULL,&hdr,packet);

                

                /* THANK YOU RICHARD STEVENS!!! RIP
                ptr = eptr->ether_dhost; 
                i = ETHER_ADDR_LEN; 
                printf(" Destination Address:  "); 
                do{         printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++); 
                }while(--i>0); 
                printf("\n"); 
                ptr = eptr->ether_shost; 
                i = ETHER_ADDR_LEN; 
                printf(" Source Address:  "); 
                do{ 
                    printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++); 
                }while(--i>0); 
                printf("\n"); 
                    }
       }while(1);
       ** /
    
    /*  struct pcap_pkthdr { 
        struct timeval ts;   time stamp  
        bpf_u_int32 caplen;  length of portion present  
        bpf_u_int32;         lebgth this packet (off wire)  
        } 
     */
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

/**
 * 
    filter= argv[1];

    printf("DEV: %s\n",dev); 


    pthread_t thread_id;
    pthread_create(&thread_id, NULL, capture, NULL);
    //capture(argc,argv);
    sleep(10);
    stop(descr);
    pthread_join(thread_id, NULL);
 * */

int main(int argc, char **argv)
{
    cnt = 0;

    handleDev("enp4s0");
    handleDescr();
    filter = "(dst host 192.168.60.69 && port 8454) || (dst host 127.0.0.1 && (src host 192.168.60.69 && port 8454))";

    Queue *q = createQueue(100);
    pthread_t thread_id;
    pthread_create(&thread_id, NULL, capture, q);
    while (1)
    {
        while (q->size != 0)
        {
            char *s = front(q);
            printf("%s", s);
            Dequeue(q);
        }
    }
    return 0;
}