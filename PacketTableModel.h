#ifndef PACKETTABLEMODEL_H
#define PACKETTABLEMODEL_H

#include <QAbstractTableModel>
#include <vector>
#include "PacketInfo.h"

class PacketTableModel : public QAbstractTableModel {
    Q_OBJECT

public:
    explicit PacketTableModel(QObject *parent = nullptr);

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;

    void addPacket(const PacketInfo& packet);
    void clearPackets();
    const PacketInfo& getPacket(int row) const;

private:
    std::vector<PacketInfo> packets;
};

#endif // PACKETTABLEMODEL_H