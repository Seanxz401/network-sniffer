#ifndef GLOBLE_H
#define GLOBLE_H

#include <stdio.h>
#include <stdlib.h>//exit
#include <string.h>//memset
#include <stdint.h>//uint32_t->unsigned int
#include <pthread.h>
#include <pcap.h>
typedef struct host_info{
    char ip[16];
    int up;
}host_info;
extern char netmask_str[16];
extern char gateway_str[16];
extern char device[16];
extern const char sep[2];//sep of ip&mac for strtok
extern int net_size;//size of subnet
extern int count_up;//num of hosts up
extern uint32_t broad;
extern unsigned char broad_mac[6];
extern host_info *hosts;
extern pcap_t *handle;
extern pthread_t pcap_thread;
extern int pcap_flag;
extern int spoof_flag;
extern int pktsn_flag;
extern pthread_t spooft_thread;
extern pthread_t spoofg_thread;
extern pthread_t pktsn_thread;
extern char filter_str[50];
extern char target_str[16];
extern char pktinfo[50];
extern int id;

typedef struct {
    u_char DestMac[6];
    u_char SrcMac[6];
    u_char Etype[2];
}ETHHEADER;


typedef struct ip_hdr
{
    unsigned char h_verlen;
    unsigned char tos;
    unsigned short tatal_len;
    unsigned short ident;
    unsigned short frag_and_flags;
    unsigned char ttl;
    unsigned char proto;
    unsigned short checksum;
    unsigned int sourceIP;
    unsigned int destIP;
}IPHEADER;


typedef struct tcp_hdr
{
    unsigned short sport;
    unsigned short dport;
    unsigned int seq;
    unsigned int ack;
    unsigned char lenres;
    unsigned char flag;
    unsigned short win;
    unsigned short sum;
    unsigned short urp;
}TCPHEADER;

#define ETHER_HEADER_LEN 14
#define ARP_HEADER_LEN 8
#define ETHER_ARP_LEN 28
#define ETHER_ARP_PACKET_LEN 42

class Globle
{
public:
    Globle();
    void reset_all();
};

#endif // GLOBLE_H
