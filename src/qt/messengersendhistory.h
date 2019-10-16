// Copyright (c) 2019 Michal Siek
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_MESSENGERSENDHISTORY_H
#define BITCOIN_QT_MESSENGERSENDHISTORY_H

#include <QDialog>

#include <string>
#include <univalue.h>

#include <wallet/wallet.h>

class WalletModel;
class ClientModel;
class PlatformStyle;
class QTableWidgetItem;

namespace Ui {
    class MessengerSendHistory;
}

QT_BEGIN_NAMESPACE
class QModelIndex;
QT_END_NAMESPACE

class MessengerSendHistory : public QDialog
{
    Q_OBJECT

public:
    explicit MessengerSendHistory(const PlatformStyle *platformStyle,
                                  WalletModel* _walletModel,
                                  ClientModel* _clientModel,
                                  QWidget *parent = 0);
    ~MessengerSendHistory();

private:
    Ui::MessengerSendHistory *ui;
    WalletModel *walletModel;
    ClientModel *clientModel;
    const PlatformStyle *platformStyle;

    void fillUpSentTable();
    void fillTable(HistoryTransactionsMap &transactions);
    void read(const std::string& txnId);
    void clearView();

private Q_SLOTS:

    void on_itemActivated(QTableWidgetItem* selecteditem);
    void on_transactionsTableCellSelected(int row, int col);
    void on_transactionsTableCellPressed(int row, int col);

};

#endif // BITCOIN_QT_MESSAGEPAGE_H
