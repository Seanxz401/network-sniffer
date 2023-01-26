#ifndef WIDGET_H
#define WIDGET_H

#include <QWidget>
#include <QProcess>
#include <QMessageBox>
#include <QScrollArea>
#include<QTime>
#include <QTreeWidget>
#include <QTreeWidgetItem>

QT_BEGIN_NAMESPACE
namespace Ui { class Widget; }
QT_END_NAMESPACE

class Widget : public QWidget
{
    Q_OBJECT

public:
    Widget(QWidget *parent = nullptr);
    void analyze_append();
    void pkt_analyze(const struct pcap_pkthdr* header,const u_char* pkt_data);
    void pkt_sniff();
    ~Widget();


private slots:
    void on_scanstart_clicked();

//signals:
    void host_button_clicked(char *ip);

    void on_clear_clicked();
    QString gettimestr();

    void on_start_clicked();

    void on_stop_clicked();

    void on_test_clicked();

private:
    Ui::Widget *ui;
};
#endif // WIDGET_H
