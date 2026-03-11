QT += core gui widgets testlib

TARGET = PacketAnalyzer
TEMPLATE = app
CONFIG += c++11

# Link GTest/GMock (Paths may vary; these are standard for Linux)
unix: LIBS += -lgtest -lgmock -lpthread

SOURCES += \
    main.cpp \
    MainWindow.cpp \
    PacketTableModel.cpp \
    PacketCapture.cpp \
    PacketParser.cpp \
    tests.cpp

HEADERS += \
    MainWindow.h \
    PacketTableModel.h \
    PacketCapture.h \
    PacketParser.h \
    PacketInfo.h