#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QPushButton>
#include <QTableView>
#include <QTextEdit>
#include <QLabel>
#include <QComboBox>
#include <QLineEdit>
#include "PacketTableModel.h"
#include "PacketCapture.h"

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onStartCapture();
    void onStopCapture();
    void onClearPackets();
    void onPacketCaptured(const PacketInfo& packet);
    void onPacketSelected(const QModelIndex& index);
    void onCaptureError(const QString& error);
    void onCaptureStarted();
    void onCaptureStopped();
    void onApplyFilter();

private:
    void setupUI();
    void updateStatusBar();
    QString formatPacketDetails(const PacketInfo& packet);
    QString formatHexDump(const std::vector<uint8_t>& data);

    // UI Components
    QPushButton *startButton;
    QPushButton *stopButton;
    QPushButton *clearButton;
    QPushButton *applyFilterButton;
    QTableView *packetTable;
    QTextEdit *detailsView;
    QTextEdit *hexView;
    QLabel *statusLabel;
    QComboBox *filterTypeCombo;
    QLineEdit *filterValueEdit;

    // Data
    PacketTableModel *model;
    PacketCapture *capture;

    // Statistics
    int totalPackets;
    int tcpCount;
    int udpCount;
    int icmpCount;
};

#endif // MAINWINDOW_H