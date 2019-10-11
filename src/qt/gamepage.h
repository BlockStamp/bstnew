// Copyright (c) 2018 Slawek Mozdzonek
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_GAMEPAGE_H
#define BITCOIN_QT_GAMEPAGE_H

#include <mutex>
#include <policy/feerate.h>
#include <qt/walletmodel.h>

#include <QWidget>

class WalletModel;
class ClientModel;
class QPlainTextEdit;
class PlatformStyle;
class QButtonGroup;
class QListWidgetItem;

namespace Ui {
    class GamePage;
}

QT_BEGIN_NAMESPACE
class QModelIndex;
QT_END_NAMESPACE

class GamePage : public QWidget
{
    Q_OBJECT

public:
    explicit GamePage(const PlatformStyle *platformStyle, QWidget *parent = 0);
    ~GamePage();
    
    void setClientModel(ClientModel *clientModel);
    void setModel(WalletModel *model);

private:
    Ui::GamePage *ui;
    WalletModel *walletModel;
    ClientModel *clientModel;
    std::string changeAddress;
    bool fFeeMinimized;
    CFeeRate feeRate;
    QButtonGroup *groupFee;
    const PlatformStyle *platformStyle;

private:
    void minimizeFeeSection(bool fMinimize);
    void updateFeeMinimizedLabel();
    void updateCoinControlState(CCoinControl& ctrl);
    void clearGameTypeBox();
    std::string makeBetPattern();
    void updateBetNumberLimit();
    void updateBetDefinition(const int* definition, int rowsNum, int colsNum);
    void updateBetDefinition(int rowsNum);
    void updateBetList();
    int getRouletteRewardRatio();
    void initBetList(int val);

protected:
    virtual void showEvent(QShowEvent * event);

public Q_SLOTS:
    void setBalance(const interfaces::WalletBalances& balances);

private Q_SLOTS:
    void makeBet();

    void updateGameType();
    void updateBetType();
    void addBet();
    void deleteBet();
    
    void updateRewardView();
    void updateBetListSlot();
    void updateBetNumberSlot();

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
};

#endif // BITCOIN_QT_GAMEPAGE_H
