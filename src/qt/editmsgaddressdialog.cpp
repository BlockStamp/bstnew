// Copyright (c) 2011-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/editmsgaddressdialog.h>
#include <qt/forms/ui_editmsgaddressdialog.h>

#include <qt/addresstablemodel.h>
#include <qt/guiutil.h>
#include <qt/messengerbookmodel.h>
#include <QDataWidgetMapper>
#include <QMessageBox>

#include <messages/message_utils.h>
#include <key.h>

static void setupAddressWidget(QTextEdit *widget, QWidget *parent)
{
    parent->setFocusProxy(widget);
    widget->setFont(GUIUtil::fixedPitchFont());

    const QString dummyRsaPubKey =
    "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnvanuzAlf2ojpCDpeJgR\n"
    "+bYAMCgkaDo2DQ4cpYn/EvIQI8AWiE29iA83B35zM9Qxd7NcRE1sxci1x52hE9Lz\n"
    "kZ3Nl3nrEe2DqD6KQWqctTu6YNtcPZBmOah3eFNdGULYvy7UvXQe/yIGbGvyjuRI\n"
    "OLKODYL30yH6AQZI6eM98NXbP6bw76y21/zzZDDMoEEcjYd++pq18BUzBH1Sy1fv\n"
    "Cqvd1DDy5HpM73zt10ppZm/vPUjRezhMCb3+4NdGCB0/9jZRCbt+klqaXSwHxy+8\n"
    "Bvf9L1QF6cR5Tzy/+mDfRnXzHBo7Hv/abT1EvqPZH/6D95FcK9TJTdij/bx4Hof1\n"
    "IQIDAQAB\n"
    "-----END PUBLIC KEY-----";

    widget->setPlaceholderText("Enter a public RSA key, e.g.\n" + dummyRsaPubKey);
}

EditMsgAddressDialog::EditMsgAddressDialog(Mode _mode, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::EditMsgAddressDialog),
    mapper(0),
    mode(_mode),
    model(0)
{
    ui->setupUi(this);
    setupAddressWidget(ui->addressEdit, this);

    switch(mode)
    {
    case NewSendingAddress:
        setWindowTitle(tr("New sending address"));
        break;
    case EditSendingAddress:
        setWindowTitle(tr("Edit sending address"));
        break;
    }

    mapper = new QDataWidgetMapper(this);
    mapper->setSubmitPolicy(QDataWidgetMapper::ManualSubmit);

    GUIUtil::ItemDelegate* delegate = new GUIUtil::ItemDelegate(mapper);
    connect(delegate, &GUIUtil::ItemDelegate::keyEscapePressed, this, &EditMsgAddressDialog::reject);
    mapper->setItemDelegate(delegate);

    connect(ui->addressEdit, &QTextEdit::textChanged, this, &EditMsgAddressDialog::validateRsaKey);
}

EditMsgAddressDialog::~EditMsgAddressDialog()
{
    delete ui;
}

void EditMsgAddressDialog::setModel(MessengerBookModel *_model)
{
    this->model = _model;
    if(!_model)
        return;

    mapper->setModel(_model);
    mapper->addMapping(ui->labelEdit, MessengerBookModel::Label);
    mapper->addMapping(ui->addressEdit, MessengerBookModel::Address, "plainText");
}

void EditMsgAddressDialog::loadRow(int row)
{
    mapper->setCurrentIndex(row);
}

bool EditMsgAddressDialog::saveCurrentRow()
{
    if(!model)
        return false;

    switch(mode)
    {
    case NewSendingAddress:
        {
        CMessengerKey addressKey(ui->addressEdit->toPlainText().toStdString(), CMessengerKey::PUBLIC_KEY);
        address = model->addRow(
            ui->labelEdit->text(),
            QString(addressKey.toString().c_str()));
        }
        break;
    case EditSendingAddress:
        if(mapper->submit())
        {
            CMessengerKey addressKey(ui->addressEdit->toPlainText().toStdString(), CMessengerKey::PUBLIC_KEY);
            address = QString(addressKey.toString().c_str());
        }
        break;
    }
    return !address.isEmpty();
}

void EditMsgAddressDialog::validateRsaKey()
{
    if (checkRSApublicKey(ui->addressEdit->toPlainText().toStdString())) {
        ui->warningLabel->setVisible(false);
    }
    else {
        QPalette p;
        p.setColor(ui->warningLabel->foregroundRole(), Qt::red);
        ui->warningLabel->setPalette(p);
        ui->warningLabel->setText("Invalid RSA public key");
        ui->warningLabel->setVisible(true);
    }
}

void EditMsgAddressDialog::accept()
{
    if(!model)
        return;

    if(!saveCurrentRow())
    {
        switch(model->getEditStatus())
        {
        case MessengerBookModel::OK:
            // Failed with unknown reason. Just reject.
            break;
        case MessengerBookModel::NO_CHANGES:
            // No changes were made during edit operation. Just reject.
            break;
        case MessengerBookModel::INVALID_ADDRESS:
            QMessageBox::warning(this, windowTitle(),
                tr("The entered key is not a valid RSA public key.").arg(ui->addressEdit->toPlainText()),
                QMessageBox::Ok, QMessageBox::Ok);
            break;
        case MessengerBookModel::DUPLICATE_ADDRESS:
            QMessageBox::warning(this, windowTitle(),
                getDuplicateAddressWarning(),
                QMessageBox::Ok, QMessageBox::Ok);
            break;
        case MessengerBookModel::DUPLICATE_LABEL:
            QMessageBox::warning(this, windowTitle(),
                tr("The entered label already exists in address book."),
                QMessageBox::Ok, QMessageBox::Ok);
            break;
        }
        return;
    }
    QDialog::accept();
}

QString EditMsgAddressDialog::getDuplicateAddressWarning() const
{
    QString dup_address = ui->addressEdit->toPlainText();
    QString existing_label = model->labelForAddress(dup_address);

    return tr(
        "The entered address \"%1\" is already in the address book with "
        "label \"%2\"."
        ).arg(dup_address).arg(existing_label);
}

QString EditMsgAddressDialog::getAddress() const
{
    return address;
}

void EditMsgAddressDialog::initData(const std::string& label, const std::string& address)
{
    ui->labelEdit->setText(QString(label.c_str()));
    ui->addressEdit->setPlainText(QString(address.c_str()));
}
