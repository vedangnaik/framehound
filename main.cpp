#include "framehound.h"

#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    FrameHound w;
    w.show();
    return a.exec();
}
