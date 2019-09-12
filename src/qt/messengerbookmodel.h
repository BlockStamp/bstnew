// Copyright (c) 2019 Michal Siek @ BioinfoBank institute
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_MESSENGERBOOKMODEL_H
#define BITCOIN_QT_MESSENGERBOOKMODEL_H

#include <QAbstractTableModel>
#include <QStringList>

class MsgAddressTablePriv;
class WalletModel;

namespace interfaces {
class Wallet;
}

const char* const MY_ADDRESS_LABEL = ".::my address::.";

/**
   Qt model of the messenger address book in the core. This allows views to access and modify the address book.
 */
class MessengerBookModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    explicit MessengerBookModel(WalletModel *parent = 0);
    ~MessengerBookModel();

    enum ColumnIndex {
        Label = 0,   /**< User specified label */
        Address = 1  /**< Bitcoin address */
    };

    /** Return status of edit/insert operation */
    enum EditStatus {
        OK,                     /**< Everything ok */
        NO_CHANGES,             /**< No changes were made during edit operation */
        INVALID_ADDRESS,        /**< Unparseable address */
        DUPLICATE_ADDRESS,      /**< Address already in address book */
        DUPLICATE_LABEL         /**< Label already exists in address book */
    };

    /** @name Methods overridden from QAbstractTableModel
        @{*/
    int rowCount(const QModelIndex &parent) const;
    int columnCount(const QModelIndex &parent) const;
    QVariant data(const QModelIndex &index, int role) const;
    bool setData(const QModelIndex &index, const QVariant &value, int role);
    QVariant headerData(int section, Qt::Orientation orientation, int role) const;
    QModelIndex index(int row, int column, const QModelIndex &parent) const;
    bool removeRows(int row, int count, const QModelIndex &parent = QModelIndex());
    Qt::ItemFlags flags(const QModelIndex &index) const;
    /*@}*/

    /* Add an address to the model.
       Returns the added address on success, and an empty string otherwise.
     */
    QString addRow(const QString &label, const QString &address);

    /* Edit an address. Used for set 'my address' after import the new one.
     * NOTE! data will replace label and/or address already existing
     */
    QString editRow(const QString &label, const QString &address);

    /** Look up label for address in address book, if not found return empty string. */
    QString labelForAddress(const QString &address) const;

    EditStatus getEditStatus() const { return editStatus; }
    void addOwnAddressToBook();

private:
    WalletModel* const walletModel;
    MsgAddressTablePriv *priv = nullptr;
    QStringList columns;
    EditStatus editStatus = OK;

    /** Look up address book data given an address string. */
    bool getAddressData(const QString &address, std::string* name) const;

    /** Notify listeners that data changed. */
    void emitDataChanged(int index);


public Q_SLOTS:
    /* Update address list from core.
     */
    void updateEntry(const QString &address, const QString &label, int status);

    friend class MsgAddressTablePriv;
};

#endif // BITCOIN_QT_MESSENGERBOOKMODEL_H
