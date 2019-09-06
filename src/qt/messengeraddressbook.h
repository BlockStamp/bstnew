// Copyright (c) 2011-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_MESSENGERADDRESSBOOK_H
#define BITCOIN_QT_MESSENGERADDRESSBOOK_H

#include <QDialog>

class MsgAddressBookSortFilterProxyModel;
class MessengerBookModel;
class PlatformStyle;

namespace Ui {
    class AddressBookPage;
}

QT_BEGIN_NAMESPACE
class QMenu;
class QModelIndex;
QT_END_NAMESPACE

/** Widget that shows a list of sending or receiving addresses.
  */
class MessengerAddressBook : public QDialog
{
    Q_OBJECT

public:

    explicit MessengerAddressBook(const PlatformStyle *platformStyle, QWidget *parent = 0);
    ~MessengerAddressBook();

    void setModel(MessengerBookModel *model);
    const QString &getReturnValue() const { return returnValue; }
    void initAddAddress(const std::string addressToAdd);

public Q_SLOTS:
    void done(int retval);

private:
    Ui::AddressBookPage *ui;
    MessengerBookModel *model;
    QString returnValue;
    MsgAddressBookSortFilterProxyModel *proxyModel;
    QMenu *contextMenu;
    QAction *deleteAction; // to be able to explicitly disable it
    QAction *editAction;
    QString newAddressToSelect;

private Q_SLOTS:
    /** Delete currently selected address entry */
    void on_deleteAddress_clicked();
    /** Create a new address for receiving coins and / or add a new address book entry */
    void on_newAddress_clicked();
    /** Copy address of currently selected address entry to clipboard */
    void on_copyAddress_clicked();
    /** Copy label of currently selected address entry to clipboard (no button) */
    void onCopyLabelAction();
    /** Edit currently selected address entry (no button) */
    void onEditAction();

    /** Set button states based on selected tab and selection */
    void selectionChanged();
    /** Spawn contextual menu (right mouse menu) for address book entry */
    void contextualMenu(const QPoint &point);
    /** New entry/entries were added to address table */
    void selectNewAddress(const QModelIndex &parent, int begin, int /*end*/);
};

#endif // BITCOIN_QT_MESSENGERADDRESSBOOK_H
