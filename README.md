# Sniffer
A Simple Sniffer that captures packets on two different interfaces. Also its capturing is restricted to UDP and TCP.
The input argument should be similiar to bellow, which capture 3 TCP packet from wls3 and 3 UDP packet from enp0s10.

sudo ./booya.o -t wls3 -u enp0s10 -c 3

For compling by gcc use this command and also libpcap should be installed. 
gcc booya.c -o booya.o -lpcap
