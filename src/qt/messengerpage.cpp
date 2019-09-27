// Copyright (c) 2019 Michal Siek
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <algorithm>

#include <QMessageBox>
#include <QFileDialog>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>
#include <QStyledItemDelegate>
#include <QClipboard>

#include <qt/addresstablemodel.h>
#include <qt/messengerbookmodel.h>
#include <qt/bitcoinunits.h>
#include <qt/clientmodel.h>
#include <qt/coincontroldialog.h>
#include <qt/messengerpage.h>
#include <qt/forms/ui_messengerpage.h>
#include <qt/guiutil.h>
#include <qt/messengeraddressbook.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/walletmodel.h>
#include <qt/askpassphrasedialog.h>
#include <qt/askmessengerpassphrasedialog.h>
#include <qt/storetxdialog.h>
#include <qt/sendcoinsdialog.h>

#include <chainparams.h>
#include <key_io.h>
#include <wallet/coincontrol.h>
#include <validation.h>
#ifdef ENABLE_WALLET
#include <wallet/wallet.h>
#endif
#include <net.h>
#include <utilmoneystr.h>
#include <consensus/validation.h>

#include <data/datautils.h>
#include <data/retrievedatatxs.h>

#include <messages/message_encryption.h>
#include <messages/message_utils.h>
#include <rpc/util.h>

#include <QSettings>
#include <QButtonGroup>
#include <array>
#include <vector>

const char* UNKNOWN_SENDER = "";

static const std::array<int, 9> confTargets = { {2, 4, 6, 12, 24, 48, 144, 504, 1008} };
extern int getConfTargetForIndex(int index);
extern int getIndexForConfTarget(int target);

//TODO: 8=tag length, fix it with define
static constexpr int maxDataSize=MAX_OP_RETURN_RELAY-6-8;

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
} dateDelegate;

MessengerPage::MessengerPage(const PlatformStyle *_platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::MessengerPage),
    walletModel(0),
    clientModel(0),
    changeAddress(""),
    fFeeMinimized(true),
    platformStyle(_platformStyle)
{
    ui->setupUi(this);

    GUIUtil::setupAddressWidget(ui->lineEditCoinControlChange, this);

    // Coin Control
    connect(ui->pushButtonCoinControl, &QPushButton::clicked, this, &MessengerPage::coinControlButtonClicked);
    connect(ui->checkBoxCoinControlChange, &QCheckBox::stateChanged, this, &MessengerPage::coinControlChangeChecked);
    connect(ui->lineEditCoinControlChange, &QValidatedLineEdit::textEdited, this, &MessengerPage::coinControlChangeEdited);

    // Coin Control: clipboard actions
    QAction *clipboardQuantityAction = new QAction(tr("Copy quantity"), this);
    QAction *clipboardAmountAction = new QAction(tr("Copy amount"), this);
    QAction *clipboardFeeAction = new QAction(tr("Copy fee"), this);
    QAction *clipboardAfterFeeAction = new QAction(tr("Copy after fee"), this);
    QAction *clipboardBytesAction = new QAction(tr("Copy bytes"), this);
    QAction *clipboardLowOutputAction = new QAction(tr("Copy dust"), this);
    QAction *clipboardChangeAction = new QAction(tr("Copy change"), this);
    connect(clipboardQuantityAction, &QAction::triggered, this, &MessengerPage::coinControlClipboardQuantity);
    connect(clipboardAmountAction, &QAction::triggered, this, &MessengerPage::coinControlClipboardAmount);
    connect(clipboardFeeAction, &QAction::triggered, this, &MessengerPage::coinControlClipboardFee);
    connect(clipboardAfterFeeAction, &QAction::triggered, this, &MessengerPage::coinControlClipboardAfterFee);
    connect(clipboardBytesAction, &QAction::triggered, this, &MessengerPage::coinControlClipboardBytes);
    connect(clipboardLowOutputAction, &QAction::triggered, this, &MessengerPage::coinControlClipboardLowOutput);
    connect(clipboardChangeAction, &QAction::triggered, this, &MessengerPage::coinControlClipboardChange);
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

    ui->transactionTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->transactionTable->setItemDelegateForColumn(0, &dateDelegate);
    ui->transactionTable->setContextMenuPolicy(Qt::CustomContextMenu);
    ui->messageViewEdit->setReadOnly(true);
    ui->fromLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);

    connect(ui->sendButton, SIGNAL(clicked()), this, SLOT(send()));
    connect(ui->transactionTable, SIGNAL(cellClicked(int, int)), this, SLOT(on_transactionsTableCellSelected(int, int)));
    connect(ui->transactionTable, SIGNAL(cellPressed(int,int)), this, SLOT(on_transactionsTableCellPressed(int, int)));
    connect(ui->transactionTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(on_transactionTableContextMenuRequest(QPoint)));
    connect(ui->transactionTable, SIGNAL(itemActivated(QTableWidgetItem*)), this, SLOT(on_itemActivated(QTableWidgetItem*)));

    connect(ui->addressBookButton, SIGNAL(clicked()), this, SLOT(on_addressBookPressed()));
    connect(ui->addressBookButton_read, SIGNAL(clicked()), this, SLOT(on_addressBookPressed()));
    connect(ui->searchTxnEdit, SIGNAL(textChanged(QString)), this, SLOT(on_searchTxnEdited(QString)));
}

MessengerPage::~MessengerPage()
{
    delete ui;
}

void MessengerPage::minimizeFeeSection(bool fMinimize)
{
    ui->labelFeeMinimized->setVisible(fMinimize);
    ui->buttonChooseFee  ->setVisible(fMinimize);
    ui->buttonMinimizeFee->setVisible(!fMinimize);
    ui->frameFeeSelection->setVisible(!fMinimize);
    ui->horizontalLayoutSmartFee->setContentsMargins(0, (fMinimize ? 0 : 6), 0, 0);
    fFeeMinimized = fMinimize;
}

void MessengerPage::on_buttonChooseFee_clicked()
{
    minimizeFeeSection(false);
}

void MessengerPage::on_buttonMinimizeFee_clicked()
{
    updateFeeMinimizedLabel();
    minimizeFeeSection(true);
}

void MessengerPage::updateFeeMinimizedLabel()
{
    if(!walletModel || !walletModel->getOptionsModel())
        return;

    if (ui->radioSmartFee->isChecked())
        ui->labelFeeMinimized->setText(ui->labelSmartFee->text());
    else {
        ui->labelFeeMinimized->setText(BitcoinUnits::formatWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), ui->customFee->value()) + "/kB");
    }
}

void MessengerPage::updateMinFeeLabel()
{
    if (walletModel && walletModel->getOptionsModel())
        ui->checkBoxMinimumFee->setText(tr("Pay only the required fee of %1").arg(
            BitcoinUnits::formatWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), walletModel->wallet().getRequiredFee(1000)) + "/kB")
        );
}

void MessengerPage::updateCoinControlState(CCoinControl& ctrl)
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

void MessengerPage::updateSmartFeeLabel()
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

void MessengerPage::setMinimumFee()
{
    ui->customFee->setValue(walletModel->wallet().getRequiredFee(1000));
}

void MessengerPage::updateFeeSectionControls()
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

void MessengerPage::setBalance(const interfaces::WalletBalances& balances)
{
    if(walletModel && walletModel->getOptionsModel())
    {
        ui->labelBalance->setText(BitcoinUnits::formatWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), balances.balance));
    }
}

void MessengerPage::updateDisplayUnit()
{
    setBalance(walletModel->wallet().getBalances());
    ui->customFee->setDisplayUnit(walletModel->getOptionsModel()->getDisplayUnit());
    updateMinFeeLabel();
    updateSmartFeeLabel();
}

void MessengerPage::setClientModel(ClientModel *_clientModel)
{
    this->clientModel = _clientModel;

    if (_clientModel) {
        connect(_clientModel, SIGNAL(numBlocksChanged(int,QDateTime,double,bool)), this, SLOT(updateSmartFeeLabel()));
    }
}

void MessengerPage::setModel(WalletModel *model)
{
    walletModel = model;
    connect(walletModel, &WalletModel::updateMsgs, this, &MessengerPage::fillUpTable);

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

    // Coin Control
    connect(walletModel->getOptionsModel(), &OptionsModel::displayUnitChanged, this, &MessengerPage::coinControlUpdateLabels);
    connect(walletModel->getOptionsModel(), &OptionsModel::coinControlFeaturesChanged, this, &MessengerPage::coinControlFeatureChanged);
    ui->frameCoinControl->setVisible(walletModel->getOptionsModel()->getCoinControlFeatures());
    coinControlUpdateLabels();
}

void MessengerPage::showEvent(QShowEvent * event)
{
    coinControlUpdateLabels();
}


// Coin Control: copy label "Quantity" to clipboard
void MessengerPage::coinControlClipboardQuantity()
{
    GUIUtil::setClipboard(ui->labelCoinControlQuantity->text());
}

// Coin Control: copy label "Amount" to clipboard
void MessengerPage::coinControlClipboardAmount()
{
    GUIUtil::setClipboard(ui->labelCoinControlAmount->text().left(ui->labelCoinControlAmount->text().indexOf(" ")));
}

// Coin Control: copy label "Fee" to clipboard
void MessengerPage::coinControlClipboardFee()
{
    GUIUtil::setClipboard(ui->labelCoinControlFee->text().left(ui->labelCoinControlFee->text().indexOf(" ")).replace(ASYMP_UTF8, ""));
}

// Coin Control: copy label "After fee" to clipboard
void MessengerPage::coinControlClipboardAfterFee()
{
    GUIUtil::setClipboard(ui->labelCoinControlAfterFee->text().left(ui->labelCoinControlAfterFee->text().indexOf(" ")).replace(ASYMP_UTF8, ""));
}

// Coin Control: copy label "Bytes" to clipboard
void MessengerPage::coinControlClipboardBytes()
{
    GUIUtil::setClipboard(ui->labelCoinControlBytes->text().replace(ASYMP_UTF8, ""));
}

// Coin Control: copy label "Dust" to clipboard
void MessengerPage::coinControlClipboardLowOutput()
{
    GUIUtil::setClipboard(ui->labelCoinControlLowOutput->text());
}

// Coin Control: copy label "Change" to clipboard
void MessengerPage::coinControlClipboardChange()
{
    GUIUtil::setClipboard(ui->labelCoinControlChange->text().left(ui->labelCoinControlChange->text().indexOf(" ")).replace(ASYMP_UTF8, ""));
}

// Coin Control: settings menu - coin control enabled/disabled by user
void MessengerPage::coinControlFeatureChanged(bool checked)
{
    ui->frameCoinControl->setVisible(checked);

    if (!checked && walletModel) // coin control features disabled
        CoinControlDialog::coinControl()->SetNull();

    coinControlUpdateLabels();
}

// Coin Control: button inputs -> show actual coin control dialog
void MessengerPage::coinControlButtonClicked()
{
    CoinControlDialog dlg(platformStyle);
    dlg.setModel(walletModel);
    dlg.exec();
    coinControlUpdateLabels();
}

// Coin Control: checkbox custom change address
void MessengerPage::coinControlChangeChecked(int state)
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
void MessengerPage::coinControlChangeEdited(const QString& text)
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
void MessengerPage::coinControlUpdateLabels()
{
    if (!walletModel || !walletModel->getOptionsModel())
        return;

    updateCoinControlState(*CoinControlDialog::coinControl());

    // set pay amounts
    CoinControlDialog::payAmounts.clear();
    CoinControlDialog::fSubtractFeeFromAmount = false;

    CAmount camount = 0;
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

void MessengerPage::unlockWallet()
{
    if (walletModel->getEncryptionStatus() == WalletModel::Locked)
    {
        AskPassphraseDialog dlg(AskPassphraseDialog::Unlock, this);
        dlg.setModel(walletModel);
        dlg.exec();
    }
}

void MessengerPage::unlockMessenger()
{
    if (walletModel->getMessengerEncryptionStatus() == WalletModel::Locked)
    {
        AskMessengerPassphraseDialog dlg(AskMessengerPassphraseDialog::Unlock, this);
        dlg.setModel(walletModel);
        dlg.exec();
    }
}

void MessengerPage::on_transactionsTableCellSelected(int row, int col)
{
    ui->transactionTable->selectRow(row);
    QTableWidgetItem* item = ui->transactionTable->item(row, TransactionsTableColumn::DATE);
    QString txnId = item->data(Qt::UserRole).toString();
    read(txnId.toUtf8().constData());
}

void MessengerPage::on_transactionsTableCellPressed(int row, int)
{
    ui->transactionTable->selectRow(row);
}

void MessengerPage::clearMessenger()
{
    ui->addressEdit->clear();
    ui->subjectEdit->clear();
    ui->messageStoreEdit->clear();

    ui->transactionTable->clearContents();
    ui->transactionTable->setRowCount(0);
    ui->fromLabel->clear();
    ui->messageViewEdit->clear();

    fillUpTable();
}

void MessengerPage::read(const std::string& txnId)
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

            wallet->BlockUntilSyncedToCurrentChain();
            LOCK2(cs_main, wallet->cs_wallet);

            WalletModel::MessengerUnlockContext ctx(walletModel->requestMessengerUnlock());
            if (!ctx.isValid())
            {
                return;
            }

            CMessengerKey privateRsaKey, publicRsaKey;
            if (!wallet->GetMessengerKeys(privateRsaKey, publicRsaKey)) {
                return;
            }

            const uint256 hash = uint256S(txnId);
            auto it = wallet->encrMsgMapWallet.find(hash);
            if (it == wallet->encrMsgMapWallet.end()) {
                throw std::runtime_error("Message not found");
            }

            std::vector<char> OPreturnData;
            const CWalletTx& wtx = it->second.wltTx;
            wtx.tx->loadOpReturn(OPreturnData);

            std::string from, subject, body;
            decryptMessageAndSplit(OPreturnData, privateRsaKey.toString(), from, subject, body);

            std::string label;
            if (!walletModel->wallet().getMsgAddress(from, &label))
            {
                label = UNKNOWN_SENDER;
            }

            ui->fromLabel->setText(label.c_str());
            ui->subjectReadLabel->setText(subject.c_str());
            ui->messageViewEdit->setPlainText(body.c_str());
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

void MessengerPage::send()
{
#ifdef ENABLE_WALLET
    if (walletModel)
    {
        try
        {
            interfaces::Wallet& wlt = walletModel->wallet();
            std::shared_ptr<CWallet> wallet = GetWallet(wlt.getWalletName());
            if(wallet != nullptr)
            {
                CWallet* const pwallet=wallet.get();

                pwallet->BlockUntilSyncedToCurrentChain();

                LOCK2(cs_main, pwallet->cs_wallet);

                CAmount curBalance = pwallet->GetBalance();

                WalletModel::MessengerUnlockContext ctx(walletModel->requestMessengerUnlock());
                if (!ctx.isValid())
                {
                    return;
                }

                CMessengerKey privateRsaKey, publicRsaKey;
                if (!wallet->GetMessengerKeys(privateRsaKey, publicRsaKey))
                {
                    return;
                }

                char* signature = signMessage(privateRsaKey.toString(), publicRsaKey.toString());
                std::vector<unsigned char> data = getData(publicRsaKey.toString(), signature);

                CRecipient recipient;
                recipient.scriptPubKey << OP_RETURN << data;
                recipient.nAmount=0;
                recipient.fSubtractFeeFromAmount=false;

                std::vector<CRecipient> vecSend;
                vecSend.push_back(recipient);

                CReserveKey reservekey(pwallet);
                CAmount nFeeRequired;
                int nChangePosInOut=1;
                std::string strFailReason;
                CTransactionRef tx;

                unlockWallet();

                // Always use a CCoinControl instance, use the CoinControlDialog instance if CoinControl has been enabled
                CCoinControl coin_control;
                if (walletModel->getOptionsModel()->getCoinControlFeatures())
                {
                    coin_control = *CoinControlDialog::coinControl();
                }
                updateCoinControlState(coin_control);
                coinControlUpdateLabels();

                if(!pwallet->CreateTransaction(vecSend, nullptr, tx, reservekey, nFeeRequired, nChangePosInOut, strFailReason, coin_control))
                {
                    if (nFeeRequired > curBalance)
                    {
                        strFailReason = strprintf("Error: This transaction requires a transaction fee of at least %s", FormatMoney(nFeeRequired));
                    }
                    throw std::runtime_error(std::string("CreateTransaction failed with reason: ")+strFailReason);
                }

                CValidationState state;
                if(!pwallet->CommitTransaction(tx, {}, {}, reservekey, g_connman.get(), state))
                {
                    throw std::runtime_error(std::string("CommitTransaction failed with reason: ")+FormatStateMessage(state));
                }

                QString qtxid=QString::fromStdString(tx->GetHash().GetHex());

                StoreTxDialog *dlg = new StoreTxDialog(qtxid, static_cast<double>(nFeeRequired)/COIN, walletModel->getOptionsModel()->getDisplayUnit());
                dlg->setAttribute(Qt::WA_DeleteOnClose);
                dlg->show();

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
#endif
}

std::vector<unsigned char> MessengerPage::getData(const std::string& fromAddress, char* signature)
{
    std::string msg = MSG_RECOGNIZE_TAG
            + signature
            + MSG_DELIMITER
            + fromAddress
            + MSG_DELIMITER
            + ui->subjectEdit->text().toUtf8().constData()
            + MSG_DELIMITER
            + ui->messageStoreEdit->toPlainText().toUtf8().constData();

    if (msg.length()>maxDataSize)
    {
        throw std::runtime_error(strprintf("Data size is greater than %d bytes", maxDataSize));
    }

    std::string publicKey = ui->addressEdit->toPlainText().toUtf8().constData();
    if (publicKey.empty())
    {
        throw std::runtime_error("Missing receiver public key, message can't be encrypted");
    }

    CMessengerKey receiverPublicKey(publicKey, CMessengerKey::PUBLIC_KEY);

    std::vector<unsigned char> retData = createEncryptedMessage(
        reinterpret_cast<const unsigned char*>(msg.c_str()),
        msg.length(),
        receiverPublicKey.toString().c_str());

    return retData;
}

void MessengerPage::fillUpTable()
{
    interfaces::Wallet& wlt = walletModel->wallet();
    std::shared_ptr<CWallet> wallet = GetWallet(wlt.getWalletName());
    if (wallet == nullptr) {
        return;
    }

    TransactionsMap& transactions = wallet->encrMsgMapWallet;
    fillTable(transactions);
}

void MessengerPage::fillTable(TransactionsMap& transactions)
{
    ui->transactionTable->clearContents();
    ui->transactionTable->setRowCount(0);
    ui->transactionTable->setRowCount(transactions.size());
    ui->transactionTable->setSortingEnabled(false);

    int row = 0;
    for (auto index  = transactions.begin(); index != transactions.end(); ++index)
    {
        const TransactionValue &it  = index->second;
        QTableWidgetItem *item = new QTableWidgetItem(QString::number(it.wltTx.nTimeSmart > 0 ? it.wltTx.nTimeSmart : it.wltTx.nTimeReceived));
        item->setData(Qt::UserRole, index->first.ToString().c_str());

        std::string label;
        if (!walletModel->wallet().getMsgAddress(it.from, &label))
        {
            label = UNKNOWN_SENDER;
        }
        QTableWidgetItem *from_item = new QTableWidgetItem(QString(label.c_str()));
        from_item->setData(Qt::UserRole, it.from.c_str());
        ui->transactionTable->setItem(row, TransactionsTableColumn::FROM, from_item);

        ui->transactionTable->setItem(row, TransactionsTableColumn::DATE, item);
        ui->transactionTable->setItem(row, TransactionsTableColumn::SUBJECT, new QTableWidgetItem(it.subject.c_str()));

        ++row;
    }


    ui->transactionTable->setSortingEnabled(true);
    if (ui->transactionTable->horizontalHeader()->sortIndicatorSection() >= ui->transactionTable->columnCount())
    {
        ui->transactionTable->horizontalHeader()->setSortIndicator(0, Qt::DescendingOrder);
    }
}

void MessengerPage::on_addressBookPressed()
{
    MessengerAddressBook book(platformStyle, this);
    book.setModel(walletModel->getMsgAddressTableModel());
    if (book.exec())
    {
        ui->addressEdit->setPlainText(book.getReturnValue());
        ui->tabWidget->setCurrentIndex(TabName::TAB_SEND);
        ui->subjectEdit->setFocus();
    }
    fillUpTable();
    ui->fromLabel->setText("");
    ui->subjectReadLabel->setText("");
    ui->messageViewEdit->setPlainText("");
}

void MessengerPage::on_transactionTableContextMenuRequest(QPoint pos)
{
    if (ui->transactionTable->rowCount() == 0)
    {
        return;
    }

    int row = ui->transactionTable->selectionModel()->currentIndex().row();
    QMenu *menu = new QMenu(this);

    QAction *replyItem = new QAction(tr("Reply"), this);
    connect(replyItem, SIGNAL(triggered()), this, SLOT(setMessageReply()));
    menu->addAction(replyItem);

    QAction *copyAddressItem = new QAction(tr("Copy address"), this);
    connect(copyAddressItem, SIGNAL(triggered()), this, SLOT(copySenderAddresssToClipboard()));
    menu->addAction(copyAddressItem);

    if (ui->transactionTable->item(row, TransactionsTableColumn::FROM)->text() == UNKNOWN_SENDER)
    {
        QAction *addToBookItem = new QAction(tr("Add to address book"), this);
        connect(addToBookItem, SIGNAL(triggered()), this, SLOT(addToAddressBook()));
        menu->addAction(addToBookItem);
    }

    menu->popup(ui->transactionTable->mapToGlobal(pos));
}

void MessengerPage::setMessageReply()
{
    int row = ui->transactionTable->selectionModel()->currentIndex().row();
    QString address = ui->transactionTable->item(row, TransactionsTableColumn::FROM)->data(Qt::UserRole).toString();
    QString subject = ui->transactionTable->item(row, TransactionsTableColumn::SUBJECT)->text();

    ui->addressEdit->setPlainText(address);
    ui->subjectEdit->setText(subject);
    ui->tabWidget->setCurrentIndex(TabName::TAB_SEND);
    ui->messageStoreEdit->setFocus();
}

void MessengerPage::copySenderAddresssToClipboard()
{
    int row = ui->transactionTable->selectionModel()->currentIndex().row();
    QString address = ui->transactionTable->item(row, TransactionsTableColumn::FROM)->data(Qt::UserRole).toString();

    QClipboard *clipboard = QApplication::clipboard();
    clipboard->setText(address);
}

void MessengerPage::addToAddressBook()
{
    int row = ui->transactionTable->selectionModel()->currentIndex().row();
    QString address = ui->transactionTable->item(row, TransactionsTableColumn::FROM)->data(Qt::UserRole).toString();

    MessengerAddressBook book(platformStyle, this);
    book.setModel(walletModel->getMsgAddressTableModel());
    book.initAddAddress(address.toStdString());
    if (book.exec())
    {
        ui->addressEdit->setPlainText(book.getReturnValue());
        ui->subjectEdit->setFocus();
    }
    fillUpTable();
    ui->fromLabel->setText("");
    ui->subjectReadLabel->setText("");
    ui->messageViewEdit->setPlainText("");
}

void MessengerPage::on_searchTxnEdited(const QString& text)
{
    interfaces::Wallet& wlt = walletModel->wallet();
    std::shared_ptr<CWallet> wallet = GetWallet(wlt.getWalletName());
    if (wallet == nullptr) {
        return;
    }

    TransactionsMap filtered;
    for (auto &it : wallet->encrMsgMapWallet)
    {
        if (it.second.subject.find(text.toStdString()) != std::string::npos)
        {
            filtered.insert(it);
        }
    }
    fillTable(filtered);
}

void MessengerPage::on_itemActivated(QTableWidgetItem* selecteditem)
{
    QTableWidgetItem* item = ui->transactionTable->item(selecteditem->row(), TransactionsTableColumn::DATE);
    QString txnId = item->data(Qt::UserRole).toString();
    read(txnId.toUtf8().constData());
}
