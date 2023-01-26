#include "globle.h"

char netmask_str[16]="255.255.255.0";
char gateway_str[16]="192.168.32.2";
char device[16]="ens32";
const char sep[2]=".";//sep of ip&mac for strtok
int net_size=0;//size of subnet
int count_up=0;//num of hosts up
uint32_t broad=0xffffffff;
unsigned char broad_mac[6]={0xff,0xff,0xff,0xff,0xff,0xff};
host_info *hosts;
pcap_t *handle;
pthread_t pcap_thread;
pthread_t spooft_thread;
pthread_t spoofg_thread;
pthread_t pktsn_thread;
char filter_str[50];
char target_str[16];
int pcap_flag=1;//0->stop next in arp scan
int spoof_flag=1;
int pktsn_flag=1;
char pktinfo[50];
int id=0;//pkt_id
Globle::Globle()
{

}
void Globle::reset_all(){
    memset(netmask_str,0,16);
    memset(gateway_str,0,16);
    memset(device,0,16);
    net_size=0;
    count_up=0;
    if(hosts!=NULL) free(hosts);
    hosts=NULL;
    printf("reset netmask,gateway,device,netsize,countup,hosts\n");
}
