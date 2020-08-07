// Qt headers
#include "framehound.h"
#include "ui_framehound.h"


FrameHound::FrameHound(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::FrameHound)
{
    ui->setupUi(this);
    qRegisterMetaType<std::vector<uint8_t>>("std::vector<uint8_t>");

    // Populate dropdown with all interfaces
    struct ifaddrs* ifa;
    if (getifaddrs(&ifa) == -1) {
        perror("getifaddrs failed: ");
    }
    struct ifaddrs* curr;
    for (curr = ifa; curr != NULL && curr->ifa_addr->sa_family == AF_PACKET; curr = curr->ifa_next) {
        QString ifrName = QString(curr->ifa_name);
        QAction* act = ui->chooseInterfaceMenu->addAction(ifrName);
        connect(act, &QAction::triggered, this, [=]{ this->sni->setIfrName(ifrName); });
    }
    freeifaddrs(ifa);

    // start packet sniffer on separate thread
    this->sni = new Sniffer();
    this->sni->moveToThread(&this->sniffingThread);
    this->sniffingThread.start();

    // Start packet backlog manager on seperate thread
    this->mng = new PacketBacklogManager(this->sni);
    this->mng->moveToThread(&this->managingThread);
    this->managingThread.start();

    // connect various signals to functions
    connect(this->mng, &PacketBacklogManager::sendPacketToGUI, this, &FrameHound::receivePacketFromManager);
    connect(ui->startSniffing, &QPushButton::clicked, this->sni, &Sniffer::sniff);
    connect(ui->startSniffing, &QPushButton::clicked, this->mng, &PacketBacklogManager::startManaging);
    connect(ui->stopSniffing, &QPushButton::clicked, this, [=] {
        this->sni->setStopFlag(true);
        this->mng->setStopFlag(true);
    });
}


FrameHound::~FrameHound()
{
    delete ui;
}


void FrameHound::receivePacketFromManager(std::vector<uint8_t> packet) {
    QFrame* packetFrame = new QFrame();
    struct innerProtocolInfo L2 = {0, 0, packetFrame};
    struct innerProtocolInfo L3;
    struct innerProtocolInfo L4;

    L3 = interpretEthernetHeaders(packet, L2);
    switch(L3.innerProtocolID) {
    case 2048: //IPv4
        L4 = displayIPHeaders(packet, L3);
        break;
    default:
        break;
    }

    ui->packetDisplay->addWidget(packetFrame);
}


void FrameHound::closeEvent(QCloseEvent* event) {
    QMessageBox msgBox;
    msgBox.setText("Do you want to quit?");
    msgBox.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    msgBox.setDefaultButton(QMessageBox::No);
    int res = msgBox.exec();
    if (res == QMessageBox::Yes) {
        // tell sniffer, manager to stop
        this->sni->setStopFlag(true);
        this->mng->setStopFlag(true);
        // wait 2 seconds for them to finish processing backlog packets
        struct timespec ts = { 2, 0 }; nanosleep(&ts, NULL);
        // delete them
        delete this->sni;
        delete this->mng;
        // quit the threads
        this->sniffingThread.exit();
        this->managingThread.exit();
        // close the GUI
        event->accept();
    } else {
        event->ignore();
    }
}
