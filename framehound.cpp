// Qt headers
#include "framehound.h"
#include "ui_framehound.h"


FrameHound::FrameHound(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::FrameHound)
{
    ui->setupUi(this);
    qRegisterMetaType<std::vector<std::pair<std::string, std::string>>>(
                "std::vector<std::pair<std::string, std::string>>");

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
    connect(this->mng, &PacketBacklogManager::sendProtocolsToGUI, this, &FrameHound::receiveProtocolsFromManager);
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


void FrameHound::receiveProtocolsFromManager(std::vector<std::pair<std::string, std::string>> L2) {
    // general purpose variables
    std::stringstream ss;
    QString explanation;


    // Make L2 protocol frame
    QFrame* L2Frame = new QFrame();
    for (auto const& x: L2) {
        ss << x.first << x.second << "\n";
    }
    explanation = QString::fromStdString(ss.str());
    QFrame* L3Frame = packetFrameMaker(L2Frame, explanation);

    // Make L3 protocol frame
//    QFrame* L3Frame = packetFrameMaker(L2Frame, explanation);
//    QString L3Explanation;
//    for (auto const& x: L3) {
//        ss << x.first << x.second << "\n";
//    }
//    explanation = QString::fromStdString(ss.str());

//    // Make L4 protocol frame
//    QFrame* L4Frame = packetFrameMaker(L3Frame, explanation);


    // Append completed frame to scrollArea
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


QFrame* packetFrameMaker(QFrame* outerFrame, QString explanation) {
    outerFrame->setFrameStyle(QFrame::Box | QFrame::Plain);
    QHBoxLayout* hl = new QHBoxLayout();
    QLabel* ethHdrExp = new QLabel(explanation);
    QFrame* innerFrame = new QFrame();
    innerFrame->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    hl->addWidget(ethHdrExp);
    hl->addWidget(innerFrame);
    outerFrame->setLayout(hl);

    return innerFrame;
}
