#include "MainWindow.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSplitter>
#include <QHeaderView>
#include <QMessageBox>
#include <QGroupBox>
#include <sstream>
#include <iomanip>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), totalPackets(0), tcpCount(0), udpCount(0), icmpCount(0) {
    
    model = new PacketTableModel(this);
    capture = new PacketCapture(this);
    
    setupUI();
    
  
    connect(capture, &PacketCapture::packetCaptured, this, &MainWindow::onPacketCaptured);
    connect(capture, &PacketCapture::captureError, this, &MainWindow::onCaptureError);
    connect(capture, &PacketCapture::captureStarted, this, &MainWindow::onCaptureStarted);
    connect(capture, &PacketCapture::captureStopped, this, &MainWindow::onCaptureStopped);
    
    connect(startButton, &QPushButton::clicked, this, &MainWindow::onStartCapture);
    connect(stopButton, &QPushButton::clicked, this, &MainWindow::onStopCapture);
    connect(clearButton, &QPushButton::clicked, this, &MainWindow::onClearPackets);
    connect(applyFilterButton, &QPushButton::clicked, this, &MainWindow::onApplyFilter);
    connect(packetTable, &QTableView::clicked, this, &MainWindow::onPacketSelected);
    
    stopButton->setEnabled(false);
}

MainWindow::~MainWindow() {
    if (capture->isRunning()) {
        capture->stopCapture();
        capture->wait();
    }
}

void MainWindow::setupUI() {
    setWindowTitle("Network Packet Analyzer");
    resize(1200, 800);
    
    QWidget *centralWidget = new QWidget(this);
    QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget);
    
   
    QHBoxLayout *controlLayout = new QHBoxLayout();
    
    startButton = new QPushButton("Start Capture", this);
    stopButton = new QPushButton("Stop Capture", this);
    clearButton = new QPushButton("Clear", this);
    
    startButton->setStyleSheet("QPushButton { background-color: #4CAF50; color: white; font-weight: bold; padding: 8px; }");
    stopButton->setStyleSheet("QPushButton { background-color: #f44336; color: white; font-weight: bold; padding: 8px; }");
    clearButton->setStyleSheet("QPushButton { padding: 8px; }");
    
    controlLayout->addWidget(startButton);
    controlLayout->addWidget(stopButton);
    controlLayout->addWidget(clearButton);
    controlLayout->addStretch();
    
    mainLayout->addLayout(controlLayout);
    
    // Filter panel
    QHBoxLayout *filterLayout = new QHBoxLayout();
    QLabel *filterLabel = new QLabel("Filter:", this);
    filterTypeCombo = new QComboBox(this);
    filterTypeCombo->addItem("None");
    filterTypeCombo->addItem("Protocol");
    filterTypeCombo->addItem("Source IP");
    filterTypeCombo->addItem("Dest IP");
    filterTypeCombo->addItem("Port");
    
    filterValueEdit = new QLineEdit(this);
    filterValueEdit->setPlaceholderText("Enter filter value (e.g., tcp, 192.168.1.1, 80)");
    
    applyFilterButton = new QPushButton("Apply Filter", this);
    
    filterLayout->addWidget(filterLabel);
    filterLayout->addWidget(filterTypeCombo);
    filterLayout->addWidget(filterValueEdit);
    filterLayout->addWidget(applyFilterButton);
    
    mainLayout->addLayout(filterLayout);
    
    // Main splitter
    QSplitter *splitter = new QSplitter(Qt::Vertical, this);
    
    // Packet table
    packetTable = new QTableView(this);
    packetTable->setModel(model);
    packetTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    packetTable->setSelectionMode(QAbstractItemView::SingleSelection);
    packetTable->setAlternatingRowColors(true);
    packetTable->horizontalHeader()->setStretchLastSection(true);
    packetTable->verticalHeader()->setVisible(false);
    
    // Set column widths
    packetTable->setColumnWidth(0, 60);   // Number
    packetTable->setColumnWidth(1, 100);  // Time
    packetTable->setColumnWidth(2, 150);  // Source
    packetTable->setColumnWidth(3, 150);  // Destination
    packetTable->setColumnWidth(4, 80);   // Protocol
    packetTable->setColumnWidth(5, 80);   // Length
    
    splitter->addWidget(packetTable);
    
    
    QWidget *bottomWidget = new QWidget(this);
    QHBoxLayout *bottomLayout = new QHBoxLayout(bottomWidget);
    
   
    QGroupBox *detailsGroup = new QGroupBox("Packet Details", this);
    QVBoxLayout *detailsLayout = new QVBoxLayout(detailsGroup);
    detailsView = new QTextEdit(this);
    detailsView->setReadOnly(true);
    detailsView->setFont(QFont("Courier", 9));
    detailsLayout->addWidget(detailsView);
    
   
    QGroupBox *hexGroup = new QGroupBox("Hex Dump", this);
    QVBoxLayout *hexLayout = new QVBoxLayout(hexGroup);
    hexView = new QTextEdit(this);
    hexView->setReadOnly(true);
    hexView->setFont(QFont("Courier", 9));
    hexLayout->addWidget(hexView);
    
    bottomLayout->addWidget(detailsGroup);
    bottomLayout->addWidget(hexGroup);
    
    splitter->addWidget(bottomWidget);
    splitter->setStretchFactor(0, 2);
    splitter->setStretchFactor(1, 1);
    
    mainLayout->addWidget(splitter);
    
    // Status bar
    statusLabel = new QLabel("Ready to capture", this);
    statusBar()->addWidget(statusLabel);
    
    setCentralWidget(centralWidget);
}

void MainWindow::onStartCapture() {
    startButton->setEnabled(false);
    stopButton->setEnabled(true);
    filterTypeCombo->setEnabled(false);
    filterValueEdit->setEnabled(false);
    applyFilterButton->setEnabled(false);
    
    capture->start();
}

void MainWindow::onStopCapture() {
    capture->stopCapture();
}

void MainWindow::onClearPackets() {
    model->clearPackets();
    detailsView->clear();
    hexView->clear();
    totalPackets = 0;
    tcpCount = 0;
    udpCount = 0;
    icmpCount = 0;
    updateStatusBar();
}

void MainWindow::onPacketCaptured(const PacketInfo& packet) {
    model->addPacket(packet);
    totalPackets++;
    
    if (packet.protocol == "TCP") tcpCount++;
    else if (packet.protocol == "UDP") udpCount++;
    else if (packet.protocol == "ICMP") icmpCount++;
    
    updateStatusBar();
    
    // Auto-scroll to bottom
    packetTable->scrollToBottom();
}

void MainWindow::onPacketSelected(const QModelIndex& index) {
    if (!index.isValid())
        return;
    
    const PacketInfo& packet = model->getPacket(index.row());
    
    // Update details view
    detailsView->setHtml(formatPacketDetails(packet));
    
    // Update hex view
    hexView->setPlainText(formatHexDump(packet.raw_data));
}

void MainWindow::onCaptureError(const QString& error) {
    QMessageBox::critical(this, "Capture Error", error);
    onCaptureStopped();
}

void MainWindow::onCaptureStarted() {
    statusLabel->setText("Capturing packets...");
}

void MainWindow::onCaptureStopped() {
    startButton->setEnabled(true);
    stopButton->setEnabled(false);
    filterTypeCombo->setEnabled(true);
    filterValueEdit->setEnabled(true);
    applyFilterButton->setEnabled(true);
    statusLabel->setText("Capture stopped");
}

void MainWindow::onApplyFilter() {
    QString filterType = filterTypeCombo->currentText();
    QString filterValue = filterValueEdit->text().trimmed();
    
    if (filterType == "None" || filterValue.isEmpty()) {
        capture->setFilter("");
        statusLabel->setText("Filter cleared");
        return;
    }
    
    std::string filter;
    if (filterType == "Protocol") {
        filter = "protocol=" + filterValue.toLower().toStdString();
    } else if (filterType == "Source IP") {
        filter = "src=" + filterValue.toStdString();
    } else if (filterType == "Dest IP") {
        filter = "dst=" + filterValue.toStdString();
    } else if (filterType == "Port") {
        filter = "port=" + filterValue.toStdString();
    }
    
    capture->setFilter(filter);
    statusLabel->setText("Filter applied: " + QString::fromStdString(filter));
}

void MainWindow::updateStatusBar() {
    QString status = QString("Total: %1 | TCP: %2 | UDP: %3 | ICMP: %4")
                        .arg(totalPackets)
                        .arg(tcpCount)
                        .arg(udpCount)
                        .arg(icmpCount);
    
    if (capture->isRunning()) {
        status = "Capturing... | " + status;
    }
    
    statusLabel->setText(status);
}

QString MainWindow::formatPacketDetails(const PacketInfo& packet) {
    QString html;
    html += "<html><body style='font-family: Courier; font-size: 10pt;'>";
    
    html += "<b style='color: #2196F3;'>═══ Packet #" + QString::number(packet.number) + " ═══</b><br>";
    html += "<b>Time:</b> " + QString::fromStdString(packet.timestamp) + "<br>";
    html += "<b>Length:</b> " + QString::number(packet.length) + " bytes<br><br>";
    
    if (!packet.source_mac.empty()) {
        html += "<b style='color: #4CAF50;'>═══ Ethernet Header ═══</b><br>";
        html += "<b>Source MAC:</b> " + QString::fromStdString(packet.source_mac) + "<br>";
        html += "<b>Dest MAC:</b> " + QString::fromStdString(packet.dest_mac) + "<br><br>";
    }
    
    html += "<b style='color: #FF9800;'>═══ IP Header ═══</b><br>";
    html += "<b>Source IP:</b> " + QString::fromStdString(packet.source_ip) + "<br>";
    html += "<b>Dest IP:</b> " + QString::fromStdString(packet.dest_ip) + "<br>";
    html += "<b>Protocol:</b> " + QString::fromStdString(packet.protocol) + "<br>";
    html += "<b>TTL:</b> " + QString::number(packet.ttl) + "<br><br>";
    
    if (packet.protocol == "TCP" || packet.protocol == "UDP") {
        html += "<b style='color: #9C27B0;'>═══ " + QString::fromStdString(packet.protocol) + " Header ═══</b><br>";
        html += "<b>Source Port:</b> " + QString::number(packet.source_port) + "<br>";
        html += "<b>Dest Port:</b> " + QString::number(packet.dest_port) + "<br>";
        
        if (packet.protocol == "TCP" && !packet.flags.empty()) {
            html += "<b>Flags:</b> " + QString::fromStdString(packet.flags) + "<br>";
        }
    }
    
    html += "</body></html>";
    return html;
}

QString MainWindow::formatHexDump(const std::vector<uint8_t>& data) {
    std::stringstream ss;
    
    for (size_t i = 0; i < data.size(); i += 16) {
       
        ss << std::setfill('0') << std::setw(4) << std::hex << i << "  ";
        
       
        for (size_t j = 0; j < 16; j++) {
            if (i + j < data.size()) {
                ss << std::setfill('0') << std::setw(2) << std::hex 
                   << static_cast<int>(data[i + j]) << " ";
            } else {
                ss << "   ";
            }
            
            if (j == 7) ss << " ";
        }
        
        ss << " ";
        
  
        for (size_t j = 0; j < 16 && i + j < data.size(); j++) {
            unsigned char c = data[i + j];
            ss << (c >= 32 && c <= 126 ? static_cast<char>(c) : '.');
        }
        
        ss << "\n";
    }
    
    return QString::fromStdString(ss.str());
}