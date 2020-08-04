#include "framehound.h"
#include "ui_framehound.h"
#include <iostream>

FrameHound::FrameHound(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::FrameHound)
{
    ui->setupUi(this);
    std::cout << "Hello, World!" << std::endl;
}

FrameHound::~FrameHound()
{
    delete ui;
}

