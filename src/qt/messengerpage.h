// Copyright (c) 2019 Michal Siek
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_MESSENGERPAGE_H
#define BITCOIN_QT_MESSENGERPAGE_H

#include <policy/feerate.h>
#include <qt/walletmodel.h>

#include <QWidget>
#include <univalue.h>

#include <wallet/wallet.h>

class WalletModel;
class ClientModel;
class QPlainTextEdit;
class PlatformStyle;
class QButtonGroup;
class CWalletTx;
class MessengerBookModel;
class QTableWidgetItem;

namespace Ui {
    class MessengerPage;

}

namespace
{
    enum TabName
    {
        TAB_SEND = 0,
        TAB_READ = 1
    };

    enum TransactionsTableColumn
    {
        DATE = 0,
        FROM = 1,
        SUBJECT = 2
    };
}

QT_BEGIN_NAMESPACE
class QModelIndex;
QT_END_NAMESPACE

class MessengerPage : public QWidget
{
    Q_OBJECT

public:
    explicit MessengerPage(const PlatformStyle *platformStyle, QWidget *parent = 0);
    ~MessengerPage();

    void setClientModel(ClientModel *clientModel);
    void setModel(WalletModel *model);

private:
    Ui::MessengerPage *ui;
    WalletModel *walletModel;
    ClientModel *clientModel;
    std::string changeAddress;
    bool fFeeMinimized;
    CFeeRate feeRate;
    QButtonGroup *groupFee;
    const PlatformStyle *platformStyle;

    void fillMyAddressTab();
    void minimizeFeeSection(bool fMinimize);
    void updateFeeMinimizedLabel();
    void updateCoinControlState(CCoinControl& ctrl);


    std::vector<unsigned char> createData(const std::string& fromAddress,
        const std::string& toAddress,
        const std::string& subject,
        const std::string& message,
        const std::string& signature);

    void sendByMining(
        std::shared_ptr<CWallet> pwallet,
        std::vector<unsigned char> data,
        std::string subject,
        std::string message,
        std::string fromAddress,
        std::string toAddress,
        int numThreads);
protected:
    virtual void showEvent(QShowEvent * event);

public Q_SLOTS:
    void setBalance(const interfaces::WalletBalances& balances);
    void clearMessenger();

private Q_SLOTS:
    void send();
    void read(const std::string& txnId);
    void fillUpTable();
    void fillTable(TransactionsMap& transactions);

    bool confirmWindow(const CAmount totalAmount, const std::string& recipient);

    void on_buttonChooseFee_clicked();
    void on_buttonMinimizeFee_clicked();
    void setMinimumFee();
    void updateFeeSectionControls();
    void updateMinFeeLabel();
    void updateSmartFeeLabel();
    void updateDisplayUnit();
    void coinControlFeatureChanged(bool);
    void coinControlButtonClicked();
    void coinControlChangeChecked(int);
    void coinControlChangeEdited(const QString &);
    void coinControlUpdateLabels();
    void coinControlClipboardQuantity();
    void coinControlClipboardAmount();
    void coinControlClipboardFee();
    void coinControlClipboardAfterFee();
    void coinControlClipboardBytes();
    void coinControlClipboardLowOutput();
    void coinControlClipboardChange();

    void setUiMining(bool started);
    void lockUISending();
    void unlockUISending();

    void on_transactionsTableCellSelected(int row, int col);
    void on_transactionsTableCellPressed(int row, int col);
    void on_addressBookPressed();

    void on_itemActivated(QTableWidgetItem* selecteditem);

    void on_transactionTableContextMenuRequest(QPoint pos);
    void setMessageReply();
    void copySenderAddresssToClipboard();
    void addToAddressBook();

    void on_searchTxnEdited(const QString& text);
    void on_sendHistoryBtn_clicked();
    void on_sendByMining_clicked();
    void on_tabWidget_tabBarClicked(int index);
};

#endif // BITCOIN_QT_MESSAGEPAGE_H
