QT += core gui widgets

TARGET = PacketAnalyzer
TEMPLATE = app

CONFIG += c++11

# Platform-specific configuration
win32 {
    LIBS += -lws2_32
    DEFINES += _WIN32_WINNT=0x0601
}

unix {
    # Linux/Unix specific settings
}

SOURCES += \
    main.cpp \
    MainWindow.cpp \
    PacketTableModel.cpp \
    PacketCapture.cpp

HEADERS += \
    MainWindow.h \
    PacketTableModel.h \
    PacketCapture.h \
    PacketInfo.h

# Default rules for deployment
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target