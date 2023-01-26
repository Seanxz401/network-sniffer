#ifndef ARP_H
#define ARP_H

#include "globle.h"
#include "widget.h"

#include <sys/socket.h>//inet_addr
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/types.h>//socket
#include <unistd.h>//close

#include <netinet/ether.h>//eth
#include <netpacket/packet.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include <unistd.h>//sleep

#include <time.h>//wjw
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <ctype.h>

class ARP
{
public:
    ARP();
    static int socket_init(unsigned char* src_mac,struct sockaddr_ll *src);
    static void create_pkt(unsigned char* buf,struct in_addr src_ip,struct in_addr dst_ip,unsigned char* src_mac,unsigned char* dst_mac,int op);
    void init_hosts();
    static void* arp_sniff(void* argv);
    void send_subnet();
    void arpscan();
    static void* arpspoof(void* argv);
    static void* pkt_sniff(void* argv);
    void startsnsp();
    static int isHTTP(char *datatcp, int len);
    static void printHTTPhead(char *httphead, int len);
    static int findHTTPPasswd(char *data, int len);
    static int findFTPPasswd(char *data, int len);
    static int findSMTPPasswd(char *data, int len);
    static int findPOPPasswd(char *data, int len, char* info);
    static int findTelnetPasswd(char *data, int len);
    static void pkt_analyze(const struct pcap_pkthdr* header,const u_char* pkt_data);
    ~ARP();

private:
};

#endif // ARP_H
