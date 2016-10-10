#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>  /* GIMME a libpcap plz! */
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <pthread.h>


pthread_mutex_t mutex1 = PTHREAD_MUTEX_INITIALIZER;
//pthread_mutex_t mutex2 = PTHREAD_MUTEX_INITIALIZER;


pcap_t* descr;
char * tp;
char *s_dev;

struct n_arg_struct {
  char *type;
  char *dev;
  int  count;
};

void my_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char*
  packet);

  /*function: for individual interface packet capturing*/
  int pktinit(char *type, char *dev, int  count) {

    openlog("slog", LOG_PID|LOG_CONS, LOG_USER);
    syslog(LOG_INFO, "Sniffing started! ");

    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;        /* to hold compiled program */
    bpf_u_int32 pMask;            /* subnet mask */
    bpf_u_int32 pNet;             /* ip address*/
    pcap_if_t *alldevs, *d;
    char dev_buff[64] = {0};

    const u_char *packet; //new
    struct pcap_pkthdr hdr;     /* pcap.h                    *///new

    pthread_mutex_lock( &mutex1 );
    s_dev=dev;
    pcap_lookupnet(dev, &pNet, &pMask, errbuf);
    descr = pcap_open_live(dev, BUFSIZ, 0, count, errbuf);
    if(descr == NULL){
      printf("pcap_open_live() failed due to [%s]\n", errbuf);
      return 1;
    }


    if(pcap_compile(descr,&fp,type,0,pNet) == -1){
      fprintf(stderr,"Error calling pcap_compile\n"); exit(1);
    }

    /* set the compiled program as the filter */
    if(pcap_setfilter(descr,&fp) == -1){
      fprintf(stderr,"Error setting filter\n"); exit(1);
    }

    /* ... and loop */
    pcap_loop(descr, count, my_callback,NULL);

    pthread_mutex_unlock( &mutex1 );
    syslog(LOG_INFO, "End of sniffing ");
    closelog();

    return 0;
  }

  void *convert(void *arguments){
    struct n_arg_struct *args = arguments;
    //  pthread_mutex_lock( &mutex2 );
    tp=args->type;
    pktinit(args->type, args->dev, args->count);
    //  pthread_mutex_unlock( &mutex2 );
    pthread_exit(NULL);
    return NULL;
  }

  int main(int argc, char **argv) {

    if(argc < 7) {
      fprintf(stderr,"Command needs more argument!\n");
      return 0;
    }

    int c;
    int digit_optind = 0;
    //  int aopt = 0, bopt = 0;
    char *copt = 0, *topt=0, *uopt=0;
    while ( (c = getopt(argc, argv, "t:u:c:")) != -1) {
      int this_option_optind = optind ? optind : 1;
      switch (c) {
        case 't':
        topt = optarg;
        break;
        case 'u':
        uopt = optarg;
        break;
        case 'c':
        copt = optarg;
        break;

        case '?':
        break;
        default:
        printf ("?? getopt returned character code 0%o ??\n", c);
      }
    }
    if (optind < argc) {
      printf ("non-option ARGV-elements: ");
      while (optind < argc)
      printf ("%s ", argv[optind++]);
      printf ("\n");
    }

    int pid,i;

    pthread_t thread1, thread2;
    int  iret1, iret2;
    struct n_arg_struct fi_th;
    struct n_arg_struct se_th;

    fi_th.type="tcp";
    fi_th.dev=topt;
    fi_th.count=strtol (copt, NULL, 10);

    se_th.type= "udp";
    se_th.dev=uopt;
    se_th.count=strtol (copt, NULL, 10);

    if (pthread_create( &thread1, NULL, convert, (void*) &fi_th) != 0) {
      printf("Problem in Creation of Thread!\n");
      return -1;
    }

    if (pthread_create( &thread2, NULL, convert, (void*) &se_th) != 0) {
      printf("Problem in Creation of Thread!\n");
      return -1;
    }
    return pthread_join(thread1, NULL); /* Wait until thread is finished */
    return pthread_join(thread2, NULL); /* Wait until thread is finished */

    return 0;
  }

  void my_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char*
    packet) {

      //+1 for the zero-terminator and another +1 for underscore
      char *result = malloc(strlen(s_dev)+strlen(tp)+strlen("snf.pcap")+1+1);
      //  printf("%s\n", s_dev);

      if(result == NULL) {
        printf("Memory allocation failed in file name creation");
        return ;
      }

      strcpy(result, s_dev);
      strcat(result, "_");
      strcat(result, tp);
      strcat(result, ".pcap");

      pcap_dumper_t *pd =pcap_dump_open(descr, result );
      pcap_dump((char *)pd, pkthdr, packet);
      pcap_dump_close(pd);
      free(result);

    }
