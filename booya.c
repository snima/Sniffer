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

pcap_t* descr;
char * tp;
char *s_dev;

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

    syslog(LOG_INFO, "End of sniffing ");
    closelog();

    return 0;
  }

  int main(int argc, char **argv) {
    int pid,i;
    if(argc < 7) {
      fprintf(stderr,"Command needs more argument!\n");
      return 0;
    }

    for (int i=0; i<3; i+=2) {

      if((pid=fork()) != -1) {

        char type[]="tcp";
        tp="tcp";
        if (strcmp(argv[i+1], "-u")==0) {
          strcpy (type, "udp");
          tp="udp";
        }

        pktinit(type, argv[i+2], strtol (argv[6], NULL, 10));
      }
      else
      {
        fprintf(stderr,"pacp failed for: %s\n", argv[i]);
        return 1;
      }
    }
    return 0;
  }

  void my_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char*
    packet) {

      //  static int cnt = 1;
      //  fprintf(stdout,"%d, ",cnt);
      //  fflush(stdout);
      //  cnt++;

      //+1 for the zero-terminator and another +1 for underscore
      char *result = malloc(strlen(s_dev)+strlen(tp)+strlen("snf.pcap")+1+1);
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
