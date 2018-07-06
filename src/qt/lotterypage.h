// Copyright (c) 2018 Slawek Mozdzonek
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_LOTTERYPAGE_H
#define BITCOIN_QT_LOTTERYPAGE_H

#include <policy/feerate.h>
#include <qt/walletmodel.h>

#include <QFile>
#include <QWidget>
#include <QListWidgetItem>
#include <univalue.h>

class WalletModel;
class QPlainTextEdit;
class PlatformStyle;
class QButtonGroup;

namespace Ui {
    class LotteryPage;
}

QT_BEGIN_NAMESPACE
class QModelIndex;
QT_END_NAMESPACE

class LotteryPage : public QWidget
{
    Q_OBJECT

public:
    explicit LotteryPage(const PlatformStyle *platformStyle, QWidget *parent = 0);
    ~LotteryPage();
    void setModel(WalletModel *model);

private:
    Ui::LotteryPage *ui;
    WalletModel *walletModel;
    std::string changeAddress;
    QListWidgetItem *selectedItem;
    bool fFeeMinimized;
    CFeeRate feeRate;
    QButtonGroup *groupFee;

private:
    void unlockWallet();
    void dumpListToFile(const QString& fileName);
    void loadListFromFile(const QString& fileName);
    void minimizeFeeSection(bool fMinimize);
    void updateFeeMinimizedLabel();
    void updateCoinControlState(CCoinControl& ctrl);

public Q_SLOTS:
    void setBalance(const interfaces::WalletBalances& balances);

private Q_SLOTS:
    void makeBet();
    void getBet();

    void on_buttonChooseFee_clicked();
    void on_buttonMinimizeFee_clicked();
    void setMinimumFee();
    void updateFeeSectionControls();
    void updateMinFeeLabel();
    void updateSmartFeeLabel();
    void updateDisplayUnit();
};

#endif // BITCOIN_QT_LOTTERYPAGE_H
