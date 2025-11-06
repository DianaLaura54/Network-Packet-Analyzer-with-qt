#include "PacketTableModel.h"
#include <QBrush>
#include <QColor>

PacketTableModel::PacketTableModel(QObject *parent)
    : QAbstractTableModel(parent) {
}

int PacketTableModel::rowCount(const QModelIndex &parent) const {
    if (parent.isValid())
        return 0;
    return packets.size();
}

int PacketTableModel::columnCount(const QModelIndex &parent) const {
    if (parent.isValid())
        return 0;
    return 7; // Number, Time, Source, Destination, Protocol, Length, Info
}

QVariant PacketTableModel::data(const QModelIndex &index, int role) const {
    if (!index.isValid() || index.row() >= static_cast<int>(packets.size()))
        return QVariant();

    const PacketInfo& packet = packets[index.row()];

    if (role == Qt::DisplayRole) {
        switch (index.column()) {
            case 0: return packet.number;
            case 1: return QString::fromStdString(packet.timestamp);
            case 2: return QString::fromStdString(packet.source_ip);
            case 3: return QString::fromStdString(packet.dest_ip);
            case 4: return QString::fromStdString(packet.protocol);
            case 5: return packet.length;
            case 6: {
                if (packet.protocol == "TCP" || packet.protocol == "UDP") {
                    return QString("%1 → %2").arg(packet.source_port).arg(packet.dest_port);
                }
                return QString();
            }
        }
    } else if (role == Qt::ForegroundRole) {
        if (index.column() == 4) { // Protocol column
            if (packet.protocol == "TCP")
                return QBrush(QColor(33, 150, 243)); // Blue
            else if (packet.protocol == "UDP")
                return QBrush(QColor(76, 175, 80)); // Green
            else if (packet.protocol == "ICMP")
                return QBrush(QColor(255, 152, 0)); // Orange
        }
    }

    return QVariant();
}

QVariant PacketTableModel::headerData(int section, Qt::Orientation orientation, int role) const {
    if (role == Qt::DisplayRole && orientation == Qt::Horizontal) {
        switch (section) {
            case 0: return "No.";
            case 1: return "Time";
            case 2: return "Source";
            case 3: return "Destination";
            case 4: return "Protocol";
            case 5: return "Length";
            case 6: return "Info";
        }
    }
    return QVariant();
}

void PacketTableModel::addPacket(const PacketInfo& packet) {
    beginInsertRows(QModelIndex(), packets.size(), packets.size());
    packets.push_back(packet);
    endInsertRows();
}

void PacketTableModel::clearPackets() {
    beginResetModel();
    packets.clear();
    endResetModel();
}

const PacketInfo& PacketTableModel::getPacket(int row) const {
    return packets[row];
}