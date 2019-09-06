// Copyright (c) 2011-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/messengerbookmodel.h>

#include <qt/guiutil.h>
#include <qt/walletmodel.h>

#include <interfaces/node.h>
#include <key_io.h>
#include <wallet/wallet.h>
#include <messages/message_utils.h>

#include <QFont>
#include <QDebug>

struct MsgAddressTableEntry
{
    QString label;
    QString address;

    MsgAddressTableEntry() {}
    MsgAddressTableEntry(const QString &_label, const QString &_address):
        label(_label), address(_address) {}
};

struct MsgAddressTableEntryLessThan
{
    bool operator()(const MsgAddressTableEntry &a, const MsgAddressTableEntry &b) const
    {
        return a.address < b.address;
    }
    bool operator()(const MsgAddressTableEntry &a, const QString &b) const
    {
        return a.address < b;
    }
    bool operator()(const QString &a, const MsgAddressTableEntry &b) const
    {
        return a < b.address;
    }
};

// Private implementation
class MsgAddressTablePriv
{
public:
    QList<MsgAddressTableEntry> cachedAddressTable;
    MessengerBookModel *parent;

    explicit MsgAddressTablePriv(MessengerBookModel *_parent):
        parent(_parent) {}

    void refreshAddressTable(interfaces::Wallet& wallet)
    {
        cachedAddressTable.clear();
        {
            for (const auto& address : wallet.getMsgAddresses())
            {
                cachedAddressTable.append(MsgAddressTableEntry(
                                  QString::fromStdString(address.name),
                                  QString::fromStdString(address.dest)));
            }
        }
        // qLowerBound() and qUpperBound() require our cachedAddressTable list to be sorted in asc order
        // Even though the map is already sorted this re-sorting step is needed because the originating map
        // is sorted by binary address, not by base58() address.
        qSort(cachedAddressTable.begin(), cachedAddressTable.end(), MsgAddressTableEntryLessThan());
    }

    void updateEntry(const QString &address, const QString &label, int status)
    {
        // Find address / label in model
        QList<MsgAddressTableEntry>::iterator lower = qLowerBound(
            cachedAddressTable.begin(), cachedAddressTable.end(), address, MsgAddressTableEntryLessThan());
        QList<MsgAddressTableEntry>::iterator upper = qUpperBound(
            cachedAddressTable.begin(), cachedAddressTable.end(), address, MsgAddressTableEntryLessThan());
        int lowerIndex = (lower - cachedAddressTable.begin());
        int upperIndex = (upper - cachedAddressTable.begin());
        bool inModel = (lower != upper);

        switch(status)
        {
        case CT_NEW:
            if(inModel)
            {
                qWarning() << "MsgAddressTablePriv::updateEntry: Warning: Got CT_NEW, but entry is already in model";
                break;
            }

            parent->beginInsertRows(QModelIndex(), lowerIndex, lowerIndex);
            cachedAddressTable.insert(lowerIndex, MsgAddressTableEntry(label, address));
            parent->endInsertRows();
            break;
        case CT_UPDATED:
            if(!inModel)
            {
                qWarning() << "MsgAddressTablePriv::updateEntry: Warning: Got CT_UPDATED, but entry is not in model";
                break;
            }
            lower->label = label;
            parent->emitDataChanged(lowerIndex);
            break;
        case CT_DELETED:
            if(!inModel)
            {
                qWarning() << "MsgAddressTablePriv::updateEntry: Warning: Got CT_DELETED, but entry is not in model";
                break;
            }
            parent->beginRemoveRows(QModelIndex(), lowerIndex, upperIndex-1);
            cachedAddressTable.erase(lower, upper);
            parent->endRemoveRows();
            break;
        }
    }

    int size()
    {
        return cachedAddressTable.size();
    }

    MsgAddressTableEntry *index(int idx)
    {
        if(idx >= 0 && idx < cachedAddressTable.size())
        {
            return &cachedAddressTable[idx];
        }
        else
        {
            return 0;
        }
    }
};

MessengerBookModel::MessengerBookModel(WalletModel *parent) :
    QAbstractTableModel(parent), walletModel(parent)
{
    addOwnAddressToBook();

    columns << tr("Label") << tr("Address");
    priv = new MsgAddressTablePriv(this);
    priv->refreshAddressTable(parent->wallet());
}

MessengerBookModel::~MessengerBookModel()
{
    delete priv;
}

int MessengerBookModel::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return priv->size();
}

int MessengerBookModel::columnCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return columns.length();
}

QVariant MessengerBookModel::data(const QModelIndex &index, int role) const
{
    if(!index.isValid())
        return QVariant();

    MsgAddressTableEntry *rec = static_cast<MsgAddressTableEntry*>(index.internalPointer());

    if(role == Qt::DisplayRole || role == Qt::EditRole)
    {
        switch(index.column())
        {
        case Label:
            if(rec->label.isEmpty() && role == Qt::DisplayRole)
            {
                return tr("(no label)");
            }
            else
            {
                return rec->label;
            }
        case Address:
            return rec->address;
        }
    }
    else if (role == Qt::FontRole)
    {
        QFont font;
        if(index.column() == Address)
        {
            font = GUIUtil::fixedPitchFont();
        }
        return font;
    }
    else if (role == Qt::TextAlignmentRole)
    {
        return Qt::AlignCenter;
    }
    return QVariant();
}

bool MessengerBookModel::setData(const QModelIndex &index, const QVariant &value, int role)
{
    if(!index.isValid())
        return false;
    MsgAddressTableEntry *rec = static_cast<MsgAddressTableEntry*>(index.internalPointer());
    editStatus = OK;

    if(role == Qt::EditRole)
    {
        const std::string& curAddress = rec->address.toStdString();
        const std::string& curLabel = rec->label.toStdString();

        if(index.column() == Label)
        {
            // Do nothing, if old label == new label
            if(rec->label == value.toString())
            {
                editStatus = NO_CHANGES;
                return false;
            }
            walletModel->wallet().setMsgAddressBook(curAddress, value.toString().toStdString());
        } else if(index.column() == Address) {
            const std::string& newAddress = value.toString().toStdString();

            // Refuse to set invalid address, set error status and return false
            if (!checkRSApublicKey(newAddress))
            {
                editStatus = INVALID_ADDRESS;
                return false;
            }

            if(newAddress == curAddress)
            {
                editStatus = NO_CHANGES;
                return false;
            }
            // Check for duplicate addresses to prevent accidental deletion of addresses, if you try
            // to paste an existing address over another address (with a different label)
            if (walletModel->wallet().getMsgAddress(newAddress, /* name= */ nullptr))
            {
                editStatus = DUPLICATE_ADDRESS;
                return false;
            }
            else
            {
                // Remove old entry
                walletModel->wallet().delMsgAddressBook(curAddress);
                // Add new entry with new address
                walletModel->wallet().setMsgAddressBook(newAddress, curLabel);
            }

        }
        return true;
    }
    return false;
}

QVariant MessengerBookModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(orientation == Qt::Horizontal)
    {
        if(role == Qt::DisplayRole && section < columns.size())
        {
            return columns[section];
        }
    }
    return QVariant();
}

Qt::ItemFlags MessengerBookModel::flags(const QModelIndex &index) const
{
    if(!index.isValid())
        return 0;
    Qt::ItemFlags retval = Qt::ItemIsSelectable | Qt::ItemIsEnabled | Qt::ItemIsEditable;
    return retval;
}

QModelIndex MessengerBookModel::index(int row, int column, const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    MsgAddressTableEntry *data = priv->index(row);
    if(data)
    {
        return createIndex(row, column, priv->index(row));
    }
    else
    {
        return QModelIndex();
    }
}

void MessengerBookModel::updateEntry(const QString &address, const QString &label, int status)
{
    // Update messenger address book model
    priv->updateEntry(address, label, status);
}

QString MessengerBookModel::addRow(const QString &label, const QString &address)
{
    std::string strLabel = label.toStdString();
    std::string strAddress = address.toStdString();

    editStatus = OK;
    if(!checkRSApublicKey(strAddress))
    {
        editStatus = INVALID_ADDRESS;
        return QString();
    }

    // Check for duplicate addresses
    if (walletModel->wallet().getMsgAddress(strAddress, /* name= */ nullptr))
    {
        editStatus = DUPLICATE_ADDRESS;
        return QString();
    }

    // Add entry
    walletModel->wallet().setMsgAddressBook(strAddress, strLabel);
    return QString::fromStdString(strAddress);
}

bool MessengerBookModel::removeRows(int row, int count, const QModelIndex &parent)
{
    Q_UNUSED(parent);
    MsgAddressTableEntry *rec = priv->index(row);
    if(count != 1 || !rec)
    {
        // Can only remove one row at a time, and cannot remove rows not in model.
        // Also refuse to remove receiving addresses.
        return false;
    }

    if (rec->address == MY_ADDRESS_LABEL)
    {
        return false;
    }

    walletModel->wallet().delMsgAddressBook(rec->address.toStdString());
    return true;
}

QString MessengerBookModel::labelForAddress(const QString &address) const
{
    std::string name;
    if (getAddressData(address, &name)) {
        return QString::fromStdString(name);
    }
    return QString();
}

bool MessengerBookModel::getAddressData(const QString &address,
        std::string* name) const {
    return walletModel->wallet().getMsgAddress(address.toStdString(), name);
}

void MessengerBookModel::emitDataChanged(int idx)
{
    Q_EMIT dataChanged(index(idx, 0, QModelIndex()), index(idx, columns.length()-1, QModelIndex()));
}

void MessengerBookModel::addOwnAddressToBook()
{
    WalletDatabase& dbh = GetWallets()[0]->GetMsgDBHandle();
    WalletBatch walletBatch(dbh);
    std::string publicRsaKey;
    walletBatch.ReadPublicKey(publicRsaKey);
    this->addRow(QString(MY_ADDRESS_LABEL), QString(publicRsaKey.c_str()));
}
