%module teste
%{
    #include <pcap.h>
    #include <errno.h> 
    #include <sys/socket.h> 
    #include <netinet/in.h> 
    #include <arpa/inet.h> 
    #include <netinet/if_ether.h> /* includes net/ethernet.h */ 
    #include <netinet/ether.h>
    #include <string.h>
    #include <time.h>
      typedef struct
  {
        int capacity;
        int size;
        int front;
        int rear;
        char **elements;
  } Queue;
    extern char *dev;  
    extern pcap_t* descr; 
    extern char *filter;


    extern Queue * createQueue(int maxElements);
    extern void Dequeue(Queue *Q);
    extern char* front(Queue *Q);
    extern void Enqueue(Queue *Q,char *element);


    extern void handleDev(char * netif);
    extern void handleDescr();
    extern void capture(Queue * q);
    extern void stop(pcap_t *descr);
    extern void capture1(Queue * q);

%}

    typedef struct
  {
        int capacity;
        int size;
        int front;
        int rear;
        char **elements;
  } Queue;
    extern char *dev;  
    extern pcap_t* descr; 
    extern char *filter;


    extern Queue * createQueue(int maxElements);
    extern void Dequeue(Queue *Q);
    extern char* front(Queue *Q);
    extern void Enqueue(Queue *Q,char *element);


    extern void handleDev(char * netif);
    extern void handleDescr();
    extern void capture(Queue * q);
    extern void stop(pcap_t *descr);
    extern void capture1(Queue * q);
