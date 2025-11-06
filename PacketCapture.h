#ifndef PACKETCAPTURE_H
#define PACKETCAPTURE_H

#include <QThread>
#include <QString>
#include <atomic>
#include <string>
#include "PacketInfo.h"

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
#else
    #include <sys/socket.h>
#endif

class PacketCapture : public QThread {
    Q_OBJECT

public:
    explicit PacketCapture(QObject *parent = nullptr);
    ~PacketCapture();

    void stopCapture();
    void setFilter(const std::string& filter);

    signals:
        void packetCaptured(const PacketInfo& packet);
    void captureError(const QString& error);
    void captureStarted();
    void captureStopped();

protected:
    void run() override;

private:
    bool initializeSocket();
    void closeSocket();
    PacketInfo parsePacket(unsigned char* buffer, int size);
    bool matchesFilter(const PacketInfo& packet);
    std::string getCurrentTime();
    std::string macToString(unsigned char* mac);
    std::string ipToString(uint32_t ip);

#ifdef _WIN32
    SOCKET sock;
    WSADATA wsa;
#else
    int sock;
#endif

    std::atomic<bool> running;
    std::string currentFilter;
    int packetNumber;
};

#endif // PACKETCAPTURE_H