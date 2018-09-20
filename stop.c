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

void stop(){
    char *dev;  
    char errbuf[PCAP_ERRBUF_SIZE]; 
    pcap_t* descr; 
     dev = pcap_lookupdev(errbuf); 
    if(dev == NULL) 
    { 
        printf("%s\n",errbuf); 
        exit(1); 
    } 
    printf("DEV: %s\n",dev); 

     descr = pcap_open_live(dev,BUFSIZ,0,-1,errbuf); 
    if(descr == NULL) 
    { 
        printf("pcap_open_live(): %s\n",errbuf); 
        exit(1); 
    } 

    pcap_breakloop(descr);

}


int main(int argc, char **argv) 
{
    stop();
    return 0;
}