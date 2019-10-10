// Copyright (c) 2018 Slawek Mozdzonek
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <QMessageBox>
#include <QFileDialog>
#include <QTextStream>
#include <QFile>
#include <QSettings>
#include <QButtonGroup>
#include <QIntValidator>

#include <qt/addresstablemodel.h>
#include <qt/bitcoinunits.h>
#include <qt/coincontroldialog.h>
#include <qt/clientmodel.h>
#include <qt/gamepage.h>
#include <qt/forms/ui_gamepage.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/askpassphrasedialog.h>
#include <qt/gametxdialog.h>

#include <consensus/validation.h>
#include <key_io.h>
#include <wallet/coincontrol.h>
#include <validation.h>
#include <wallet/wallet.h>
#include <validation.h>
#include <policy/policy.h>
#include <utilstrencodings.h>
#include <stdint.h>
#include <amount.h>
#include <chainparams.h>
#include <net.h>
#include <utilmoneystr.h>
#include <wallet/coincontrol.h>
#include <wallet/fees.h>

#include <univalue.h>
#include <boost/algorithm/string.hpp>

#include <data/datautils.h>
#include <data/processunspent.h>
#include <games/gamestxs.h>
#include <games/gamesutils.h>
#include <games/modulo/modulotxs.h>
#include <games/modulo/moduloutils.h>
#include <games/modulo/moduloverify.h>

#include <qt/transactiontablemodel.h>
#include <array>
#include <limits>

using namespace modulo;

static const std::array<QString, 13> betTypes = { {QString("Straight"), QString("Split"), QString("Street"), 
                                                  QString("Corner"), QString("Line"), QString("Column"), 
                                                  QString("Dozen"), QString("Low"), QString("High"),
                                                  QString("Even"), QString("Odd"), QString("Red"), QString("Black")} };

static const std::array<int, 9> confTargets = { {2, 4, 6, 12, 24, 48, 144, 504, 1008} };
extern int getConfTargetForIndex(int index);
extern int getIndexForConfTarget(int target);

GamePage::GamePage(const PlatformStyle *_platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::GamePage),
    walletModel(0),
    clientModel(0),
    changeAddress(""),
    fFeeMinimized(true),
    platformStyle(_platformStyle)
{
    ui->setupUi(this);

    GUIUtil::setupAddressWidget(ui->lineEditCoinControlChange, this);

    // Coin Control
    connect(ui->pushButtonCoinControl, &QPushButton::clicked, this, &GamePage::coinControlButtonClicked);
    connect(ui->checkBoxCoinControlChange, &QCheckBox::stateChanged, this, &GamePage::coinControlChangeChecked);
    connect(ui->lineEditCoinControlChange, &QValidatedLineEdit::textEdited, this, &GamePage::coinControlChangeEdited);

    // Coin Control: clipboard actions
    QAction *clipboardQuantityAction = new QAction(tr("Copy quantity"), this);
    QAction *clipboardAmountAction = new QAction(tr("Copy amount"), this);
    QAction *clipboardFeeAction = new QAction(tr("Copy fee"), this);
    QAction *clipboardAfterFeeAction = new QAction(tr("Copy after fee"), this);
    QAction *clipboardBytesAction = new QAction(tr("Copy bytes"), this);
    QAction *clipboardLowOutputAction = new QAction(tr("Copy dust"), this);
    QAction *clipboardChangeAction = new QAction(tr("Copy change"), this);
    connect(clipboardQuantityAction, &QAction::triggered, this, &GamePage::coinControlClipboardQuantity);
    connect(clipboardAmountAction, &QAction::triggered, this, &GamePage::coinControlClipboardAmount);
    connect(clipboardFeeAction, &QAction::triggered, this, &GamePage::coinControlClipboardFee);
    connect(clipboardAfterFeeAction, &QAction::triggered, this, &GamePage::coinControlClipboardAfterFee);
    connect(clipboardBytesAction, &QAction::triggered, this, &GamePage::coinControlClipboardBytes);
    connect(clipboardLowOutputAction, &QAction::triggered, this, &GamePage::coinControlClipboardLowOutput);
    connect(clipboardChangeAction, &QAction::triggered, this, &GamePage::coinControlClipboardChange);
    ui->labelCoinControlQuantity->addAction(clipboardQuantityAction);
    ui->labelCoinControlAmount->addAction(clipboardAmountAction);
    ui->labelCoinControlFee->addAction(clipboardFeeAction);
    ui->labelCoinControlAfterFee->addAction(clipboardAfterFeeAction);
    ui->labelCoinControlBytes->addAction(clipboardBytesAction);
    ui->labelCoinControlLowOutput->addAction(clipboardLowOutputAction);
    ui->labelCoinControlChange->addAction(clipboardChangeAction);

    // init transaction fee section
    QSettings settings;
    if (!settings.contains("fFeeSectionMinimized"))
        settings.setValue("fFeeSectionMinimized", true);
    if (!settings.contains("nFeeRadio") && settings.contains("nTransactionFee") && settings.value("nTransactionFee").toLongLong() > 0) // compatibility
        settings.setValue("nFeeRadio", 1); // custom
    if (!settings.contains("nFeeRadio"))
        settings.setValue("nFeeRadio", 0); // recommended
    if (!settings.contains("nSmartFeeSliderPosition"))
        settings.setValue("nSmartFeeSliderPosition", 0);
    if (!settings.contains("nTransactionFee"))
        settings.setValue("nTransactionFee", (qint64)DEFAULT_PAY_TX_FEE);
    if (!settings.contains("fPayOnlyMinFee"))
        settings.setValue("fPayOnlyMinFee", false);
    groupFee = new QButtonGroup(this);
	groupFee->addButton(ui->radioSmartFee);
	groupFee->addButton(ui->radioCustomFee);
    groupFee->setId(ui->radioSmartFee, 0);
    groupFee->setId(ui->radioCustomFee, 1);
    groupFee->button((int)std::max(0, std::min(1, settings.value("nFeeRadio").toInt())))->setChecked(true);
    ui->customFee->setValue(settings.value("nTransactionFee").toLongLong());
    ui->checkBoxMinimumFee->setChecked(settings.value("fPayOnlyMinFee").toBool());
    minimizeFeeSection(settings.value("fFeeSectionMinimized").toBool());

    ui->betNumberSpinBox->setMinimum(1);
    ui->rewardRatioSpinBox->setMinimum(2);
    ui->rewardRatioSpinBox->setMaximum(MAX_REWARD);
    ui->amountSpinBox->setDecimals(8);
    ui->amountSpinBox->setMaximum(MAX_PAYOFF/COIN);
}

GamePage::~GamePage()
{
    delete ui;
}

void GamePage::minimizeFeeSection(bool fMinimize)
{
    ui->labelFeeMinimized->setVisible(fMinimize);
    ui->buttonChooseFee  ->setVisible(fMinimize);
    ui->buttonMinimizeFee->setVisible(!fMinimize);
    ui->frameFeeSelection->setVisible(!fMinimize);
    ui->horizontalLayoutSmartFee->setContentsMargins(0, (fMinimize ? 0 : 6), 0, 0);
    fFeeMinimized = fMinimize;
}

void GamePage::on_buttonChooseFee_clicked()
{
    minimizeFeeSection(false);
}

void GamePage::on_buttonMinimizeFee_clicked()
{
    updateFeeMinimizedLabel();
    minimizeFeeSection(true);
}

void GamePage::updateFeeMinimizedLabel()
{
    if(!walletModel || !walletModel->getOptionsModel())
        return;

    if (ui->radioSmartFee->isChecked())
        ui->labelFeeMinimized->setText(ui->labelSmartFee->text());
    else {
        ui->labelFeeMinimized->setText(BitcoinUnits::formatWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), ui->customFee->value()) + "/kB");
    }
}

void GamePage::updateMinFeeLabel()
{
    if (walletModel && walletModel->getOptionsModel())
        ui->checkBoxMinimumFee->setText(tr("Pay only the required fee of %1").arg(
            BitcoinUnits::formatWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), walletModel->wallet().getRequiredFee(1000)) + "/kB")
        );
}

void GamePage::updateCoinControlState(CCoinControl& ctrl)
{
    if (ui->radioCustomFee->isChecked()) {
        ctrl.m_feerate = CFeeRate(ui->customFee->value());
    } else {
        ctrl.m_feerate.reset();
    }
    // Avoid using global defaults when sending money from the GUI
    // Either custom fee will be used or if not selected, the confirmation target from dropdown box
    ctrl.m_confirm_target = getConfTargetForIndex(ui->confTargetSelector->currentIndex());
    ctrl.m_signal_bip125_rbf = ui->optInRBF->isChecked();
}

void GamePage::updateSmartFeeLabel()
{
    if(!walletModel || !walletModel->getOptionsModel())
        return;
    CCoinControl coin_control;
    updateCoinControlState(coin_control);
    coin_control.m_feerate.reset(); // Explicitly use only fee estimation rate for smart fee labels
    int returned_target;
    FeeReason reason;
    feeRate = CFeeRate(walletModel->wallet().getMinimumFee(1000, coin_control, &returned_target, &reason));

    ui->labelSmartFee->setText(BitcoinUnits::formatWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), feeRate.GetFeePerK()) + "/kB");

    if (reason == FeeReason::FALLBACK) {
        ui->labelSmartFee2->show(); // (Smart fee not initialized yet. This usually takes a few blocks...)
        ui->labelFeeEstimation->setText("");
        ui->fallbackFeeWarningLabel->setVisible(true);
        int lightness = ui->fallbackFeeWarningLabel->palette().color(QPalette::WindowText).lightness();
        QColor warning_colour(255 - (lightness / 5), 176 - (lightness / 3), 48 - (lightness / 14));
        ui->fallbackFeeWarningLabel->setStyleSheet("QLabel { color: " + warning_colour.name() + "; }");
        ui->fallbackFeeWarningLabel->setIndent(QFontMetrics(ui->fallbackFeeWarningLabel->font()).width("x"));
    }
    else
    {
        ui->labelSmartFee2->hide();
        ui->labelFeeEstimation->setText(tr("Estimated to begin confirmation within %n block(s).", "", returned_target));
        ui->fallbackFeeWarningLabel->setVisible(false);
    }

    updateFeeMinimizedLabel();
}

void GamePage::setMinimumFee()
{
    ui->customFee->setValue(walletModel->wallet().getRequiredFee(1000));
}

void GamePage::updateFeeSectionControls()
{
    ui->confTargetSelector      ->setEnabled(ui->radioSmartFee->isChecked());
    ui->labelSmartFee           ->setEnabled(ui->radioSmartFee->isChecked());
    ui->labelSmartFee2          ->setEnabled(ui->radioSmartFee->isChecked());
    ui->labelSmartFee3          ->setEnabled(ui->radioSmartFee->isChecked());
    ui->labelFeeEstimation      ->setEnabled(ui->radioSmartFee->isChecked());
    ui->checkBoxMinimumFee      ->setEnabled(ui->radioCustomFee->isChecked());
    ui->labelMinFeeWarning      ->setEnabled(ui->radioCustomFee->isChecked());
    ui->labelCustomPerKilobyte  ->setEnabled(ui->radioCustomFee->isChecked() && !ui->checkBoxMinimumFee->isChecked());
    ui->customFee               ->setEnabled(ui->radioCustomFee->isChecked() && !ui->checkBoxMinimumFee->isChecked());
}

void GamePage::setBalance(const interfaces::WalletBalances& balances)
{
    if(walletModel && walletModel->getOptionsModel())
    {
        ui->labelBalance->setText(BitcoinUnits::formatWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), balances.balance));
    }
}

void GamePage::updateDisplayUnit()
{
    setBalance(walletModel->wallet().getBalances());
    ui->customFee->setDisplayUnit(walletModel->getOptionsModel()->getDisplayUnit());
    updateMinFeeLabel();
    updateSmartFeeLabel();
    updateRewardView();
}

void GamePage::setClientModel(ClientModel *_clientModel)
{
    this->clientModel = _clientModel;

    if (_clientModel) {
        connect(_clientModel, SIGNAL(numBlocksChanged(int,QDateTime,double,bool)), this, SLOT(updateSmartFeeLabel()));
    }
}

void GamePage::setModel(WalletModel *model)
{
    walletModel = model;

    interfaces::WalletBalances balances = walletModel->wallet().getBalances();
    setBalance(balances);
    connect(walletModel, SIGNAL(balanceChanged(interfaces::WalletBalances)), this, SLOT(setBalance(interfaces::WalletBalances)));
    connect(walletModel->getOptionsModel(), SIGNAL(displayUnitChanged(int)), this, SLOT(updateDisplayUnit()));

    for (const int n : confTargets) {
        ui->confTargetSelector->addItem(tr("%1 (%2 blocks)").arg(GUIUtil::formatNiceTimeOffset(n*Params().GetConsensus().nPowTargetSpacing)).arg(n));
    }
    connect(ui->confTargetSelector, SIGNAL(currentIndexChanged(int)), this, SLOT(updateSmartFeeLabel()));
    connect(ui->checkBoxMinimumFee, SIGNAL(stateChanged(int)), this, SLOT(setMinimumFee()));
    connect(groupFee, SIGNAL(buttonClicked(int)), this, SLOT(updateFeeSectionControls()));
    connect(ui->checkBoxMinimumFee, SIGNAL(stateChanged(int)), this, SLOT(updateFeeSectionControls()));
    connect(ui->optInRBF, SIGNAL(stateChanged(int)), this, SLOT(updateSmartFeeLabel()));
    ui->customFee->setSingleStep(model->wallet().getRequiredFee(1000));
    updateFeeSectionControls();
    updateMinFeeLabel();
    updateSmartFeeLabel();

    // set default rbf checkbox state
    ui->optInRBF->setCheckState(Qt::Checked);

    // set the smartfee-sliders default value (wallets default conf.target or last stored value)
    QSettings settings;
    if (settings.value("nSmartFeeSliderPosition").toInt() != 0) {
        // migrate nSmartFeeSliderPosition to nConfTarget
        // nConfTarget is available since 0.15 (replaced nSmartFeeSliderPosition)
        int nConfirmTarget = 25 - settings.value("nSmartFeeSliderPosition").toInt(); // 25 == old slider range
        settings.setValue("nConfTarget", nConfirmTarget);
        settings.remove("nSmartFeeSliderPosition");
    }
    if (settings.value("nConfTarget").toInt() == 0)
        ui->confTargetSelector->setCurrentIndex(getIndexForConfTarget(model->wallet().getConfirmTarget()));
    else
        ui->confTargetSelector->setCurrentIndex(getIndexForConfTarget(settings.value("nConfTarget").toInt()));

    ui->gameTypeComboBox->addItem(QString("Roulette"));
    ui->gameTypeComboBox->addItem(QString("Lottery"));

    ui->rewardRatioSpinBox->setValue(36);
    ui->rewardRatioSpinBox->setEnabled(false);

    for(size_t i=0; i<betTypes.size(); ++i)
    {
        ui->betTypeComboBox->addItem(betTypes[i]);
    }
    ui->betTypeComboBox->setEnabled(true);

    connect(ui->gameTypeComboBox, SIGNAL(currentIndexChanged(const QString &)), this, SLOT(updateGameType()));
    connect(ui->betTypeComboBox, SIGNAL(currentIndexChanged(const QString &)), this, SLOT(updateBetType()));
    connect(ui->betNumberSpinBox, SIGNAL(valueChanged(int)), this, SLOT(updateBetListSlot()));
    connect(ui->betListComboBox, SIGNAL(currentIndexChanged(const QString &)), this, SLOT(updateBetNumberSlot()));    
    connect(ui->rewardRatioSpinBox, SIGNAL(valueChanged(int)), this, SLOT(updateRewardView()));
    connect(ui->betListWidget, SIGNAL(itemSelectionChanged()), this, SLOT(updateRewardView()));
    connect(ui->addBetButton, SIGNAL(clicked()), this, SLOT(addBet()));
    connect(ui->deleteBetButton, SIGNAL(clicked()), this, SLOT(deleteBet()));
    connect(ui->makeBetButton, SIGNAL(clicked()), this, SLOT(makeBet()));
    ui->maxRewardValLabel->setText(BitcoinUnits::formatWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), 0));
    updateBetNumberLimit();
    updateBetList();
    
    // Coin Control
    connect(walletModel->getOptionsModel(), &OptionsModel::displayUnitChanged, this, &GamePage::coinControlUpdateLabels);
    connect(walletModel->getOptionsModel(), &OptionsModel::coinControlFeaturesChanged, this, &GamePage::coinControlFeatureChanged);
    connect(ui->addBetButton, SIGNAL(clicked()), this, SLOT(coinControlUpdateLabels()));
    connect(ui->deleteBetButton, SIGNAL(clicked()), this, SLOT(coinControlUpdateLabels()));
    ui->frameCoinControl->setVisible(walletModel->getOptionsModel()->getCoinControlFeatures());
    coinControlUpdateLabels();
}

void GamePage::showEvent(QShowEvent * event)
{
    coinControlUpdateLabels();
}

// Coin Control: copy label "Quantity" to clipboard
void GamePage::coinControlClipboardQuantity()
{
    GUIUtil::setClipboard(ui->labelCoinControlQuantity->text());
}

// Coin Control: copy label "Amount" to clipboard
void GamePage::coinControlClipboardAmount()
{
    GUIUtil::setClipboard(ui->labelCoinControlAmount->text().left(ui->labelCoinControlAmount->text().indexOf(" ")));
}

// Coin Control: copy label "Fee" to clipboard
void GamePage::coinControlClipboardFee()
{
    GUIUtil::setClipboard(ui->labelCoinControlFee->text().left(ui->labelCoinControlFee->text().indexOf(" ")).replace(ASYMP_UTF8, ""));
}

// Coin Control: copy label "After fee" to clipboard
void GamePage::coinControlClipboardAfterFee()
{
    GUIUtil::setClipboard(ui->labelCoinControlAfterFee->text().left(ui->labelCoinControlAfterFee->text().indexOf(" ")).replace(ASYMP_UTF8, ""));
}

// Coin Control: copy label "Bytes" to clipboard
void GamePage::coinControlClipboardBytes()
{
    GUIUtil::setClipboard(ui->labelCoinControlBytes->text().replace(ASYMP_UTF8, ""));
}

// Coin Control: copy label "Dust" to clipboard
void GamePage::coinControlClipboardLowOutput()
{
    GUIUtil::setClipboard(ui->labelCoinControlLowOutput->text());
}

// Coin Control: copy label "Change" to clipboard
void GamePage::coinControlClipboardChange()
{
    GUIUtil::setClipboard(ui->labelCoinControlChange->text().left(ui->labelCoinControlChange->text().indexOf(" ")).replace(ASYMP_UTF8, ""));
}

// Coin Control: settings menu - coin control enabled/disabled by user
void GamePage::coinControlFeatureChanged(bool checked)
{
    ui->frameCoinControl->setVisible(checked);

    if (!checked && walletModel) // coin control features disabled
        CoinControlDialog::coinControl()->SetNull();

    coinControlUpdateLabels();
}

// Coin Control: button inputs -> show actual coin control dialog
void GamePage::coinControlButtonClicked()
{
    CoinControlDialog dlg(platformStyle);
    dlg.setModel(walletModel);
    dlg.exec();
    coinControlUpdateLabels();
}

// Coin Control: checkbox custom change address
void GamePage::coinControlChangeChecked(int state)
{
    if (state == Qt::Unchecked)
    {
        CoinControlDialog::coinControl()->destChange = CNoDestination();
        ui->labelCoinControlChangeLabel->clear();
    }
    else
        // use this to re-validate an already entered address
        coinControlChangeEdited(ui->lineEditCoinControlChange->text());

    ui->lineEditCoinControlChange->setEnabled((state == Qt::Checked));
}

// Coin Control: custom change address changed
void GamePage::coinControlChangeEdited(const QString& text)
{
    if (walletModel && walletModel->getAddressTableModel())
    {
        // Default to no change address until verified
        CoinControlDialog::coinControl()->destChange = CNoDestination();
        ui->labelCoinControlChangeLabel->setStyleSheet("QLabel{color:red;}");

        const CTxDestination dest = DecodeDestination(text.toStdString());

        if (text.isEmpty()) // Nothing entered
        {
            ui->labelCoinControlChangeLabel->setText("");
        }
        else if (!IsValidDestination(dest)) // Invalid address
        {
            ui->labelCoinControlChangeLabel->setText(tr("Warning: Invalid BST address"));
        }
        else // Valid address
        {
            if (!walletModel->wallet().isSpendable(dest)) {
                ui->labelCoinControlChangeLabel->setText(tr("Warning: Unknown change address"));

                // confirmation dialog
                QMessageBox::StandardButton btnRetVal = QMessageBox::question(this, tr("Confirm custom change address"), tr("The address you selected for change is not part of this wallet. Any or all funds in your wallet may be sent to this address. Are you sure?"),
                    QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel);

                if(btnRetVal == QMessageBox::Yes)
                    CoinControlDialog::coinControl()->destChange = dest;
                else
                {
                    ui->lineEditCoinControlChange->setText("");
                    ui->labelCoinControlChangeLabel->setStyleSheet("QLabel{color:black;}");
                    ui->labelCoinControlChangeLabel->setText("");
                }
            }
            else // Known change address
            {
                ui->labelCoinControlChangeLabel->setStyleSheet("QLabel{color:black;}");

                // Query label
                QString associatedLabel = walletModel->getAddressTableModel()->labelForAddress(text);
                if (!associatedLabel.isEmpty())
                    ui->labelCoinControlChangeLabel->setText(associatedLabel);
                else
                    ui->labelCoinControlChangeLabel->setText(tr("(no label)"));

                CoinControlDialog::coinControl()->destChange = dest;
            }
        }
    }
}

// Coin Control: update labels
void GamePage::coinControlUpdateLabels()
{
    if (!walletModel || !walletModel->getOptionsModel())
        return;

    updateCoinControlState(*CoinControlDialog::coinControl());

    // set pay amounts
    CoinControlDialog::payAmounts.clear();
    CoinControlDialog::fSubtractFeeFromAmount = false;

    CAmount camount = 0;
    for(int i=0;i<ui->betListWidget->count();++i)
    {
        QString betTypePattern=ui->betListWidget->item(i)->text();
        int idx = betTypePattern.indexOf("@");
        QString amountStr = betTypePattern.right(betTypePattern.length()-idx-1);
        bool ok(false);
        double amount = amountStr.toDouble(&ok);
        if(ok)
        {
            camount += static_cast<CAmount>(amount*COIN);
        }
    }
    CoinControlDialog::payAmounts.append(camount);
    //CoinControlDialog::fSubtractFeeFromAmount = true;

    if (CoinControlDialog::coinControl()->HasSelected())
    {
        // actual coin control calculation
        CoinControlDialog::updateLabels(walletModel, ui->widgetCoinControl, false, 0);

        // show coin control stats
        ui->labelCoinControlAutomaticallySelected->hide();
        ui->widgetCoinControl->show();
    }
    else
    {
        // hide coin control stats
        ui->labelCoinControlAutomaticallySelected->show();
        ui->widgetCoinControl->hide();
        ui->labelCoinControlInsuffFunds->hide();
    }
}

void GamePage::clearGameTypeBox()
{
    int count = ui->betListWidget->count();
    for(int i=0;i<count;++i)
    {
        delete ui->betListWidget->takeItem(0);
    }
}

void GamePage::initBetList(int val)
{
    ui->betListComboBox->clear();
    QString rowDef("{");
    rowDef+=QString::number(val);
    rowDef+=QString("}");
    ui->betListComboBox->addItem(rowDef);
}

void GamePage::updateBetListSlot()
{
    if(ui->gameTypeComboBox->currentIndex() == 0)//roulette
    {
        ui->betListComboBox->setCurrentIndex(ui->betNumberSpinBox->value()-1);
    }
    else if(ui->gameTypeComboBox->currentIndex() == 1)//lottery
    {
        initBetList(ui->betNumberSpinBox->value());
    }
}

void GamePage::updateBetNumberSlot()
{
    if(ui->gameTypeComboBox->currentIndex() == 0)//roulette
    {
        ui->betNumberSpinBox->setValue(ui->betListComboBox->currentIndex()+1);
    }
}

void GamePage::updateBetType()
{
    if(ui->gameTypeComboBox->currentIndex() == 0)//roulette
    {
        if(ui->betTypeComboBox->currentIndex() < 7)
        {
            ui->betNumberSpinBox->setEnabled(true);
            ui->betListComboBox->setEnabled(true);
        }
        if(ui->betTypeComboBox->currentIndex() >= 7)
        {
            ui->betNumberSpinBox->setEnabled(false);
            ui->betListComboBox->setEnabled(false);
        }
        updateBetList();
        ui->rewardRatioSpinBox->setValue(getRouletteRewardRatio());
    }
    else if(ui->gameTypeComboBox->currentIndex() == 1)//lottery
    {
        ui->betNumberSpinBox->setEnabled(true);
        ui->betListComboBox->setEnabled(false);
    }
    updateBetNumberLimit();
}

int GamePage::getRouletteRewardRatio()
{
    int ratio=0;
    if(ui->gameTypeComboBox->currentIndex() == 0)//roulette
    {
        if(ui->betTypeComboBox->currentText()==QString("Straight"))
        {
            ratio=36;
        }
        else if(ui->betTypeComboBox->currentText()==QString("Split"))
        {
            ratio=18;
        }
        else if(ui->betTypeComboBox->currentText()==QString("Street"))
        {
            ratio=12;
        }
        else if(ui->betTypeComboBox->currentText()==QString("Corner"))
        {
            ratio=9;
        }
        else if(ui->betTypeComboBox->currentText()==QString("Line"))
        {
            ratio=6;
        }
        else if(ui->betTypeComboBox->currentText()==QString("Column") || ui->betTypeComboBox->currentText()==QString("Dozen"))
        {
            ratio=3;
        }
        else if(ui->betTypeComboBox->currentText()==QString("High") || ui->betTypeComboBox->currentText()==QString("Low") ||
                ui->betTypeComboBox->currentText()==QString("Even") || ui->betTypeComboBox->currentText()==QString("Odd") ||
                ui->betTypeComboBox->currentText()==QString("Red") || ui->betTypeComboBox->currentText()==QString("Black"))
        {
            ratio=2;
        }
    }
    
    return ratio;
}

void GamePage::updateGameType()
{
    clearGameTypeBox();
    if(ui->gameTypeComboBox->currentIndex() == 0)//roulette
    {
        ui->rewardRatioSpinBox->setValue(getRouletteRewardRatio());
        ui->rewardRatioSpinBox->setEnabled(false);
        ui->betTypeComboBox->setEnabled(true);
        ui->betListComboBox->setEnabled(true);
    }
    else if(ui->gameTypeComboBox->currentIndex() == 1)//lottery
    {
        ui->rewardRatioSpinBox->setEnabled(true);
        ui->betTypeComboBox->setCurrentIndex(0);
        ui->betTypeComboBox->setEnabled(false);
        ui->betListComboBox->setEnabled(false);
        
        ui->betNumberSpinBox->setValue(1);
        initBetList(ui->betNumberSpinBox->value());
    }
    updateBetNumberLimit();
    updateRewardView();
    updateBetList();
}

void GamePage::updateBetDefinition(const int* definition, int rowsNum, int colsNum)
{
    ui->betListComboBox->clear();
    for(int i=0;i<rowsNum;++i)
    {
        QString rowDef("{");
        for(int j=0;j<colsNum-1;++j)
        {
            rowDef+=QString::number(*(definition+j+(i*colsNum)));
            rowDef+=QString(", ");
        }
        int j=colsNum-1;
        rowDef+=QString::number(*(definition+j+(i*colsNum)));
        rowDef+=QString("}");
        ui->betListComboBox->addItem(rowDef);
    }
}

void GamePage::updateBetDefinition(int rowsNum)
{
    ui->betListComboBox->clear();
    for(int i=0;i<rowsNum;++i)
    {
        QString rowDef("{");
        rowDef+=QString::number(i+1);
        rowDef+=QString("}");
        ui->betListComboBox->addItem(rowDef);
    }
}

void GamePage::updateBetList()
{
    if(ui->gameTypeComboBox->currentIndex() == 0)//roulette
    {
        if(ui->betTypeComboBox->currentText()==QString("Straight"))
        {
            updateBetDefinition(36);
        }
        else if(ui->betTypeComboBox->currentText()==QString("Split"))
        {
            updateBetDefinition(&split[0][0], splitBetsNum, 2);
        }
        else if(ui->betTypeComboBox->currentText()==QString("Street"))
        {
            updateBetDefinition(&street[0][0], streetBetsNum, 3);
        }
        else if(ui->betTypeComboBox->currentText()==QString("Corner"))
        {
            updateBetDefinition(&corner[0][0], cornerBetsNum, 4);
        }
        else if(ui->betTypeComboBox->currentText()==QString("Line"))
        {
            updateBetDefinition(&line[0][0], lineBetsNum, 6);
        }
        else if(ui->betTypeComboBox->currentText()==QString("Column"))
        {
            updateBetDefinition(&column[0][0], columnBetsNum, 12);
        }
        else if(ui->betTypeComboBox->currentText()==QString("Dozen"))
        {
            updateBetDefinition(&dozen[0][0], dozenBetsNum, 12);
        }
        else if(ui->betTypeComboBox->currentText()==QString("Even"))
        {
            updateBetDefinition(&even[0], 1, 18);
        }
        else if(ui->betTypeComboBox->currentText()==QString("Odd"))
        {
            updateBetDefinition(&odd[0], 1, 18);
        }
        else if(ui->betTypeComboBox->currentText()==QString("Low"))
        {
            updateBetDefinition(&low[0], 1, 18);
        }
        else if(ui->betTypeComboBox->currentText()==QString("High"))
        {
            updateBetDefinition(&high[0], 1, 18);
        }
        else if(ui->betTypeComboBox->currentText()==QString("Red"))
        {
            updateBetDefinition(&red[0], 1, 18);
        }
        else if(ui->betTypeComboBox->currentText()==QString("Black"))
        {
            updateBetDefinition(&black[0], 1, 18);
        }
    }
    else if(ui->gameTypeComboBox->currentIndex() == 1)//roulette
    {
        updateBetDefinition(1);
    }
}

void GamePage::updateBetNumberLimit()
{
    if(ui->gameTypeComboBox->currentIndex() == 0)//roulette
    {
        if(ui->betTypeComboBox->currentText()==QString("Straight"))
        {
            ui->betNumberSpinBox->setMaximum(36);
        }
        else if(ui->betTypeComboBox->currentText()==QString("Split"))
        {
            ui->betNumberSpinBox->setMaximum(splitBetsNum);
        }
        else if(ui->betTypeComboBox->currentText()==QString("Street"))
        {
            ui->betNumberSpinBox->setMaximum(streetBetsNum);
        }
        else if(ui->betTypeComboBox->currentText()==QString("Corner"))
        {
            ui->betNumberSpinBox->setMaximum(cornerBetsNum);
        }
        else if(ui->betTypeComboBox->currentText()==QString("Line"))
        {
            ui->betNumberSpinBox->setMaximum(lineBetsNum);
        }
        else if(ui->betTypeComboBox->currentText()==QString("Column"))
        {
            ui->betNumberSpinBox->setMaximum(columnBetsNum);
        }
        else if(ui->betTypeComboBox->currentText()==QString("Dozen"))
        {
            ui->betNumberSpinBox->setMaximum(dozenBetsNum);
        }
        else if(ui->betTypeComboBox->currentText()==QString("Even") || ui->betTypeComboBox->currentText()==QString("Odd") ||
                ui->betTypeComboBox->currentText()==QString("Low") || ui->betTypeComboBox->currentText()==QString("High") ||
                ui->betTypeComboBox->currentText()==QString("Red") || ui->betTypeComboBox->currentText()==QString("Black"))
        {
            ui->betNumberSpinBox->setMaximum(1);
        }
    }
    else if(ui->gameTypeComboBox->currentIndex() == 1)//lottery
    {
        ui->betNumberSpinBox->setMaximum(ui->rewardRatioSpinBox->value());
    }
}

void GamePage::deleteBet()
{
    QListWidgetItem *it;
    it = ui->betListWidget->currentItem();
    delete ui->betListWidget->takeItem(ui->betListWidget->row(it));

    updateRewardView();
}

void GamePage::addBet()
{
    if((ui->gameTypeComboBox->currentIndex() == 1) && //lottery
       (ui->betNumberSpinBox->value() > ui->rewardRatioSpinBox->value()))
    {
        QMessageBox msgBox;
        msgBox.setText("Bet number is greater than reward ratio");
        msgBox.exec();
        return;
    }

    QString betString;
    double amount=ui->amountSpinBox->value();
    if(amount<=0.0)
    {
        QMessageBox msgBox;
        msgBox.setText("Amount is out of range");
        msgBox.exec();
        return;
    }
    if(ui->gameTypeComboBox->currentIndex() == 0)//roulette
    {
        betString+=ui->betTypeComboBox->currentText().toLower();
        if(ui->betTypeComboBox->currentIndex() > 0 && ui->betTypeComboBox->currentIndex() < 7)//split, street, corner, column, line, dozen
        {
            betString+=QString("_");
            betString+=QString::number(ui->betListComboBox->currentIndex()+1);
        }
        else if(ui->betTypeComboBox->currentIndex() == 0)//straight
        {
            betString+=QString("_");
            betString+=QString::number(ui->betNumberSpinBox->value());            
        }
        betString+=QString("@");
        betString+=QString::number(amount, 'f', 8);

        QListWidgetItem *newItem = new QListWidgetItem;
        newItem->setText(betString);
        ui->betListWidget->insertItem(0, newItem);
    }
    else if(ui->gameTypeComboBox->currentIndex() == 1)//lottery
    {
        betString+=QString::number(ui->betNumberSpinBox->value());
        betString+=QString("@");
        betString+=QString::number(amount, 'f', 8);

        QListWidgetItem *newItem = new QListWidgetItem;
        newItem->setText(betString);
        ui->betListWidget->insertItem(0, newItem);
    }

    updateRewardView();
}

void GamePage::updateRewardView()
{
    int reward;
    double betAmount;
    int* betArray;
    int betLen;
    std::string betType;
    double payoff=0.0;
    
    QListWidgetItem *it;
    it = ui->betListWidget->currentItem();
    if(it!=nullptr)
    {
        std::string betTypePattern=it->text().toStdString();
        if(!betTypePattern.empty())
        {
            try
            {
                if(ui->gameTypeComboBox->currentIndex() == 0)//roulette
                {
                    int range=36;
                    getRouletteBet(betTypePattern, betArray, betLen, reward, betAmount, betType, range);
                }
                else if(ui->gameTypeComboBox->currentIndex() == 1)//lottery
                {
                    int range=ui->rewardRatioSpinBox->value();
                    getModuloBet(betTypePattern, betArray, betLen, reward, betAmount, betType, range);
                }
            }
            catch(std::exception const& e)
            {
                QMessageBox msgBox;
                msgBox.setText(e.what());
                msgBox.exec();
            }
            payoff=(betAmount*reward);
        }
    }

    if(walletModel && walletModel->getOptionsModel())
    {
        ui->maxRewardValLabel->setText(BitcoinUnits::formatWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), static_cast<CAmount>(payoff*COIN)));
    }
    updateBetNumberLimit();
}

void GamePage::unlockWallet()
{
    if (walletModel->getEncryptionStatus() == WalletModel::Locked)
    {
        AskPassphraseDialog dlg(AskPassphraseDialog::Unlock, this);
        dlg.setModel(walletModel);
        dlg.exec();
    }
}

std::string GamePage::makeBetPattern()
{
    std::string betTypePattern;
    for(int i=0;i<ui->betListWidget->count();++i)
    {
        if(!betTypePattern.empty())
        {
            betTypePattern+=std::string("+");
        }
        betTypePattern+=ui->betListWidget->item(i)->text().toStdString();
    }

    return betTypePattern;
}

void GamePage::makeBet()
{
    if(walletModel)
    {
        try
        {
            interfaces::Wallet& wlt = walletModel->wallet();
            std::shared_ptr<CWallet> wallet = GetWallet(wlt.getWalletName());
            if(wallet != nullptr)
            {
                CWallet* const pwallet=wallet.get();
                std::vector<CAmount> betAmounts;
                std::vector<std::string> betTypes;

                std::string betTypePattern=makeBetPattern();
                int range=ui->rewardRatioSpinBox->value();
                bool isRoulette=false;//lottery
                if(ui->gameTypeComboBox->currentIndex() == 0)//roulette
                {
                    isRoulette=true;
                    range=36;
                }
                parseBetType(betTypePattern, range, betAmounts, betTypes, isRoulette);
                const CAmount betSum = betAmountsSum(betAmounts);

                std::string arg=int2hex(range)+std::string("_");
                std::string msg=HexStr(arg.begin(), arg.end());
                const std::string plus_msg("+");
                const std::string at_msg("@");
                for(size_t i=0;i<betTypes.size();++i)
                {
                    msg+=HexStr(betTypes[i].begin(), betTypes[i].end());
                    std::string amountStr = at_msg + std::to_string(betAmounts[i]);
                    msg+=HexStr(amountStr.begin(), amountStr.end());
                    if(i<betTypes.size()-1)
                    {
                        msg+=HexStr(plus_msg.begin(), plus_msg.end());
                    }
                }

                // Always use a CCoinControl instance, use the CoinControlDialog instance if CoinControl has been enabled
                CCoinControl coin_control;
                if (walletModel->getOptionsModel()->getCoinControlFeatures())
                {
                    coin_control = *CoinControlDialog::coinControl();
                }
                updateCoinControlState(coin_control);
                coinControlUpdateLabels();

                const CRecipient recipient = createMakeBetDestination(betSum, msg);

                LOCK2(cs_main, pwallet->cs_wallet);

                CAmount curBalance = pwallet->GetBalance();

                CReserveKey reservekey(pwallet);
                CAmount nFeeRequired;
                int nChangePosInOut=1;
                std::string strFailReason;
                CTransactionRef tx;

                unlockWallet();

                if(!pwallet->CreateTransaction({recipient}, nullptr, tx, reservekey, nFeeRequired, nChangePosInOut, strFailReason, coin_control, true, true))
                {
                    if (nFeeRequired > curBalance)
                    {
                        strFailReason = strprintf("Error: This transaction requires a transaction fee of at least %s", FormatMoney(nFeeRequired));
                    }        
                    throw std::runtime_error(std::string("CreateTransaction failed with reason: ")+strFailReason);
                }

                CAmount rewardSum{}, betsSum{};
                if (!modulo::ver_2::checkBetsPotentialReward(rewardSum, betsSum, *tx))
                {
                    throw std::runtime_error("checkBetsPotentialReward failed with reason: potential reward or sum of bets over limit");
                }

                CValidationState state;
                if(!pwallet->CommitTransaction(tx, {}, {}, reservekey, g_connman.get(), state))
                {
                    throw std::runtime_error(std::string("CommitTransaction failed with reason: ")+FormatStateMessage(state));
                }
                
                QString qtxid=QString::fromStdString(tx->GetHash().GetHex());
                QString qgameType=ui->gameTypeComboBox->currentText();
                QString qrewardRatio=QString::number(ui->rewardRatioSpinBox->value());
                QString qbetTypePattern=QString::fromStdString(makeBetPattern());
                
                GameTxDialog *dlg = new GameTxDialog(qtxid, qgameType, qrewardRatio, qbetTypePattern, static_cast<double>(nFeeRequired)/COIN, walletModel->getOptionsModel()->getDisplayUnit());
                dlg->setAttribute(Qt::WA_DeleteOnClose);
                dlg->show();
                clearGameTypeBox();
            }
            else
            {
                throw std::runtime_error(std::string("No wallet found"));
            }
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
}

