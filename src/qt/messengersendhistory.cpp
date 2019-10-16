// Copyright (c) 2019 Michal Siek
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <algorithm>
#include <array>
#include <memory>
#include <vector>

#include <QMessageBox>
#include <QLabel>
#include <QPushButton>
#include <QSettings>
#include <QButtonGroup>
#include <QTableWidgetItem>
#include <QString>
#include <QStyledItemDelegate>

#include <messages/message_utils.h>
#include <messages/message_encryption.h>
#include <qt/messengersendhistory.h>
#include <qt/forms/ui_messengersendhistory.h>
#include <qt/walletmodel.h>

#ifdef ENABLE_WALLET
#include <wallet/wallet.h>
#endif

namespace
{
    enum TransactionsTableColumn
    {
        DATE = 0,
        TO = 1,
        SUBJECT = 2
    };
}

class DateDisplayDelegate : public QStyledItemDelegate
{
    QString displayText(const QVariant &value, const QLocale&) const override
    {
        std::time_t t = value.toULongLong();
        std::tm *ptm = std::localtime(&t);
        char buffer[32];
        std::strftime(buffer, sizeof(buffer), "%d.%m.%Y %H:%M", ptm);
        return buffer;
    }
} datedelegate;

MessengerSendHistory::MessengerSendHistory(const PlatformStyle *_platformStyle, WalletModel* _walletModel, ClientModel* _clientModel, QWidget* parent) :
    QDialog(parent),
    ui(new Ui::MessengerSendHistory),
    walletModel(_walletModel),
    clientModel(_clientModel),
    platformStyle(_platformStyle)
{
    ui->setupUi(this);

    ui->transactionsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->transactionsTable->setItemDelegateForColumn(0, &datedelegate);
    ui->transactionsTable->setContextMenuPolicy(Qt::CustomContextMenu);

    connect(ui->transactionsTable, SIGNAL(cellClicked(int, int)), this, SLOT(on_transactionsTableCellSelected(int, int)));
    connect(ui->transactionsTable, SIGNAL(cellPressed(int,int)), this, SLOT(on_transactionsTableCellPressed(int, int)));
    connect(ui->transactionsTable, SIGNAL(itemActivated(QTableWidgetItem*)), this, SLOT(on_itemActivated(QTableWidgetItem*)));
    connect(ui->closeButton, SIGNAL(clicked()), this, SLOT(close()));

    fillUpSentTable();
}

MessengerSendHistory::~MessengerSendHistory()
{
    delete ui;
}

void MessengerSendHistory::read(const std::string& txnId)
{
#ifdef ENABLE_WALLET
    if (walletModel)
    {
        try
        {
            interfaces::Wallet& wlt = walletModel->wallet();
            std::shared_ptr<CWallet> wallet = GetWallet(wlt.getWalletName());

            if (wallet == nullptr) {
                throw std::runtime_error("Wallet " + wlt.getWalletName() + " unavailabel");
            }

            LOCK2(cs_main, wallet->cs_wallet);

            CMessengerKey privateRsaKey, publicRsaKey;
            if (!wallet->GetMessengerKeys(privateRsaKey, publicRsaKey)) {
                return;
            }

            const uint256 hash = uint256S(txnId);
            auto it = wallet->encrMsgHistory.find(hash);
            if (it == wallet->encrMsgHistory.end()) {
                throw std::runtime_error("Message not found");
            }

            std::vector<unsigned char> decrypted_data = createDecryptedMessage(
                reinterpret_cast<unsigned char*>(it->second.data.data()),
                it->second.data.size(),
                privateRsaKey.toString().c_str());

            std::string label;
            if (!walletModel->wallet().getMsgAddress(it->second.addr, &label))
            {
                label = UNKNOWN_SENDER;
            }

            ui->toLabel->setText(label.c_str());
            ui->subjectLabel->setText(it->second.subject.c_str());
            ui->messageView->setPlainText(std::string(decrypted_data.begin(), decrypted_data.end()).c_str());
        }
        catch(std::exception const& e)
        {
            QMessageBox msgBox;
            msgBox.setText(e.what());
            msgBox.exec();
        }
        catch(...)
        {
            QMessageBox msgBox;
            msgBox.setText("Unknown exception occured");
            msgBox.exec();
        }
    }
#endif
}

void MessengerSendHistory::fillUpSentTable()
{
    if (!walletModel)
    {
        return;
    }

    interfaces::Wallet& wlt = walletModel->wallet();
    std::shared_ptr<CWallet> wallet = GetWallet(wlt.getWalletName());
    if (wallet == nullptr)
    {
        return;
    }

    HistoryTransactionsMap& transactions = wallet->encrMsgHistory;
    fillTable(transactions);

}

void MessengerSendHistory::fillTable(HistoryTransactionsMap& transactions)
{
    ui->transactionsTable->clearContents();
    ui->transactionsTable->setRowCount(0);
    ui->transactionsTable->setRowCount(transactions.size());
    ui->transactionsTable->setSortingEnabled(false);

    int row = 0;
    for (auto index  = transactions.begin(); index != transactions.end(); ++index)
    {
        const HistoryTransactionValue &it  = index->second;
        QTableWidgetItem *item = new QTableWidgetItem(QString::number(it.time));
        item->setData(Qt::UserRole, index->first.ToString().c_str());

        std::string label;
        if (!walletModel->wallet().getMsgAddress(it.addr, &label))
        {
            label = UNKNOWN_SENDER;
        }
        QTableWidgetItem *to_item = new QTableWidgetItem(QString(label.c_str()));
        to_item->setData(Qt::UserRole, it.addr.c_str());
        ui->transactionsTable->setItem(row, TransactionsTableColumn::TO, to_item);

        ui->transactionsTable->setItem(row, TransactionsTableColumn::DATE, item);
        ui->transactionsTable->setItem(row, TransactionsTableColumn::SUBJECT, new QTableWidgetItem(it.subject.c_str()));

        ++row;
    }


    ui->transactionsTable->setSortingEnabled(true);
    if (ui->transactionsTable->horizontalHeader()->sortIndicatorSection() >= ui->transactionsTable->columnCount())
    {
        ui->transactionsTable->horizontalHeader()->setSortIndicator(0, Qt::DescendingOrder);
    }

}

void MessengerSendHistory::on_itemActivated(QTableWidgetItem* selecteditem)
{
    QTableWidgetItem* item = ui->transactionsTable->item(selecteditem->row(), TransactionsTableColumn::DATE);
    QString txnId = item->data(Qt::UserRole).toString();
    read(txnId.toUtf8().constData());
}

void MessengerSendHistory::on_transactionsTableCellSelected(int row, int col)
{
    ui->transactionsTable->selectRow(row);
    QTableWidgetItem* item = ui->transactionsTable->item(row, TransactionsTableColumn::DATE);
    QString txnId = item->data(Qt::UserRole).toString();
    read(txnId.toUtf8().constData());
}

void MessengerSendHistory::on_transactionsTableCellPressed(int row, int)
{
    ui->transactionsTable->selectRow(row);
}

void MessengerSendHistory::clearView()
{
    ui->toLabel->clear();
    ui->subjectLabel->clear();
    ui->messageView->clear();
}
