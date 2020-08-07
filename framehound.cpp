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
    QFrame* L2Frame = new QFrame();
    L2Frame->setFrameStyle(QFrame::Box | QFrame::Plain);
    QHBoxLayout* hl = new QHBoxLayout();
    QLabel* ethHdrExp = new QLabel();
    QFrame* L3Frame = new QFrame();
    L3Frame->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    hl->addWidget(ethHdrExp);
    hl->addWidget(L3Frame);
    L2Frame->setLayout(hl);

    struct innerProtocolInfo inf;
    std::stringstream ss;
    std::vector<std::pair<std::string, std::string>> ethHdr = interpretEthernetHeaders(packet, inf);
    for (auto const& x: ethHdr) {
        ss << x.first << x.second << "\n";
    }
    ethHdrExp->setText(QString::fromStdString(ss.str()));

    ui->packetDisplay->addWidget(L2Frame);
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
