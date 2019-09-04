// Copyright (c) 2019 Tomasz Slabon @ BioinfoBank institute
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <qt/askmessengerpassphrasedialog.h>
#include <qt/forms/ui_askpassphrasedialog.h>

#include <qt/guiconstants.h>
#include <qt/walletmodel.h>

#include <support/allocators/secure.h>

#include <iostream>

#include <QKeyEvent>
#include <QMessageBox>
#include <QPushButton>

AskMessengerPassphraseDialog::AskMessengerPassphraseDialog(Mode _mode, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::AskPassphraseDialog),
    mode(_mode),
    model(0),
    fCapsLock(false)
{
    ui->setupUi(this);

    ui->passEdit1->setMinimumSize(ui->passEdit1->sizeHint());
    ui->passEdit2->setMinimumSize(ui->passEdit2->sizeHint());
    ui->passEdit3->setMinimumSize(ui->passEdit3->sizeHint());

    ui->passEdit1->setMaxLength(MAX_PASSPHRASE_SIZE);
    ui->passEdit2->setMaxLength(MAX_PASSPHRASE_SIZE);
    ui->passEdit3->setMaxLength(MAX_PASSPHRASE_SIZE);

    // Setup Caps Lock detection.
    ui->passEdit1->installEventFilter(this);
    ui->passEdit2->installEventFilter(this);
    ui->passEdit3->installEventFilter(this);

    switch(mode)
    {
        case Encrypt: // Ask passphrase x2
            ui->warningLabel->setText(tr("Enter the new passphrase to the messenger.<br/>Please use a passphrase of <b>ten or more random characters</b>, or <b>eight or more words</b>."));
            ui->passLabel1->hide();
            ui->passEdit1->hide();
            setWindowTitle(tr("Encrypt messenger"));
            break;
        case Unlock: // Ask passphrase
            ui->warningLabel->setText(tr("This operation needs your messenger passphrase to unlock the messenger."));
            ui->passLabel2->hide();
            ui->passEdit2->hide();
            ui->passLabel3->hide();
            ui->passEdit3->hide();
            setWindowTitle(tr("Unlock messenger"));
            break;
        case Decrypt:   // Ask passphrase
            ui->warningLabel->setText(tr("This operation needs your messenger passphrase to decrypt the messenger."));
            ui->passLabel2->hide();
            ui->passEdit2->hide();
            ui->passLabel3->hide();
            ui->passEdit3->hide();
            setWindowTitle(tr("Decrypt messenger"));
            break;
        case ChangePass: // Ask old passphrase + new passphrase x2
            setWindowTitle(tr("Change passphrase"));
            ui->warningLabel->setText(tr("Enter the old passphrase and new passphrase to the messenger."));
            break;
    }
    textChanged();
    connect(ui->toggleShowPasswordButton, &QPushButton::toggled, this, &AskMessengerPassphraseDialog::toggleShowPassword);
    connect(ui->passEdit1, &QLineEdit::textChanged, this, &AskMessengerPassphraseDialog::textChanged);
    connect(ui->passEdit2, &QLineEdit::textChanged, this, &AskMessengerPassphraseDialog::textChanged);
    connect(ui->passEdit3, &QLineEdit::textChanged, this, &AskMessengerPassphraseDialog::textChanged);
}

AskMessengerPassphraseDialog::~AskMessengerPassphraseDialog()
{
    secureClearPassFields();
    delete ui;
}

void AskMessengerPassphraseDialog::setModel(WalletModel *_model)
{
    this->model = _model;
}

void AskMessengerPassphraseDialog::accept()
{
    SecureString oldpass, newpass1, newpass2;
    if(!model)
        return;
    oldpass.reserve(MAX_PASSPHRASE_SIZE);
    newpass1.reserve(MAX_PASSPHRASE_SIZE);
    newpass2.reserve(MAX_PASSPHRASE_SIZE);
    // TODO: get rid of this .c_str() by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make this input mlock()'d to begin with.
    oldpass.assign(ui->passEdit1->text().toStdString().c_str());
    newpass1.assign(ui->passEdit2->text().toStdString().c_str());
    newpass2.assign(ui->passEdit3->text().toStdString().c_str());

    secureClearPassFields();

    switch(mode)
    {
    case Encrypt: {
        if(newpass1.empty() || newpass2.empty())
        {
            // Cannot encrypt with empty passphrase
            break;
        }
        QMessageBox::StandardButton retval = QMessageBox::question(this, tr("Confirm messenger encryption"),
                 tr("Warning: If you encrypt the messenger and lose your passphrase, you will <b>LOSE ALL OF YOUR MESSENGER COMMUNICATION</b>!") + "<br><br>" + tr("Are you sure you wish to encrypt the messenger?"),
                 QMessageBox::Yes|QMessageBox::Cancel,
                 QMessageBox::Cancel);
        if(retval == QMessageBox::Yes)
        {
            if(newpass1 == newpass2)
            {
                if(model->setMessengerEncrypted(true, newpass1))
                {
                    QMessageBox::warning(this, tr("Messenger encrypted"),
                                         "<qt><br><br><b>" +
                                         tr("IMPORTANT: Any previous backups you have made of your messenger wallet file "
                                         "should be replaced with the newly generated, encrypted messenger wallet file. "
                                         "For security reasons, previous backups of the unencrypted messenger walet file "
                                         "will become useless as soon as you start using the new, encrypted messenger wallet.") +
                                         "</b></qt>");
                }
                else
                {
                    QMessageBox::critical(this, tr("Messenger encryption failed"),
                                         tr("Messenger encryption failed due to an internal error. The messenger was not encrypted."));
                }
                QDialog::accept(); // Success
            }
            else
            {
                QMessageBox::critical(this, tr("Messenger encryption failed"),
                                     tr("The supplied passphrases do not match."));
            }
        }
        else
        {
            QDialog::reject(); // Cancelled
        }
        } break;
    case Unlock:
        if(!model->setMessengerLocked(false, oldpass))
        {
            QMessageBox::critical(this, tr("Messenger unlock failed"),
                                  tr("The passphrase entered for the messenger decryption was incorrect."));
        }
        else
        {
            QDialog::accept(); // Success
        }
        break;
    case Decrypt:
        if(!model->setMessengerEncrypted(false, oldpass))
        {
            QMessageBox::critical(this, tr("Messenger decryption failed"),
                                  tr("The passphrase entered for the messenger decryption was incorrect."));
        }
        else
        {
            QDialog::accept(); // Success
        }
        break;
    case ChangePass:
        if(newpass1 == newpass2)
        {
            if(model->changeMessengerPassphrase(oldpass, newpass1))
            {
                QMessageBox::information(this, tr("Messenger encrypted"),
                                     tr("Messenger passphrase was successfully changed."));
                QDialog::accept(); // Success
            }
            else
            {
                QMessageBox::critical(this, tr("Messenger encryption failed"),
                                     tr("The passphrase entered for the messenger decryption was incorrect."));
            }
        }
        else
        {
            QMessageBox::critical(this, tr("Messenger encryption failed"),
                                 tr("The supplied passphrases do not match."));
        }
        break;
    }
}

void AskMessengerPassphraseDialog::textChanged()
{
    // Validate input, set Ok button to enabled when acceptable
    bool acceptable = false;
    switch(mode)
    {
    case Encrypt: // New passphrase x2
        acceptable = !ui->passEdit2->text().isEmpty() && !ui->passEdit3->text().isEmpty();
        break;
    case Unlock: // Old passphrase x1
    case Decrypt:
        acceptable = !ui->passEdit1->text().isEmpty();
        break;
    case ChangePass: // Old passphrase x1, new passphrase x2
        acceptable = !ui->passEdit1->text().isEmpty() && !ui->passEdit2->text().isEmpty() && !ui->passEdit3->text().isEmpty();
        break;
    }
    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(acceptable);
}

bool AskMessengerPassphraseDialog::event(QEvent *event)
{
    // Detect Caps Lock key press.
    if (event->type() == QEvent::KeyPress) {
        QKeyEvent *ke = static_cast<QKeyEvent *>(event);
        if (ke->key() == Qt::Key_CapsLock) {
            fCapsLock = !fCapsLock;
        }
        if (fCapsLock) {
            ui->capsLabel->setText(tr("Warning: The Caps Lock key is on!"));
        } else {
            ui->capsLabel->clear();
        }
    }
    return QWidget::event(event);
}

void AskMessengerPassphraseDialog::toggleShowPassword(bool show)
{
    ui->toggleShowPasswordButton->setDown(show);
    const auto mode = show ? QLineEdit::Normal : QLineEdit::Password;
    ui->passEdit1->setEchoMode(mode);
    ui->passEdit2->setEchoMode(mode);
    ui->passEdit3->setEchoMode(mode);
}

bool AskMessengerPassphraseDialog::eventFilter(QObject *object, QEvent *event)
{
    /* Detect Caps Lock.
     * There is no good OS-independent way to check a key state in Qt, but we
     * can detect Caps Lock by checking for the following condition:
     * Shift key is down and the result is a lower case character, or
     * Shift key is not down and the result is an upper case character.
     */
    if (event->type() == QEvent::KeyPress) {
        QKeyEvent *ke = static_cast<QKeyEvent *>(event);
        QString str = ke->text();
        if (str.length() != 0) {
            const QChar *psz = str.unicode();
            bool fShift = (ke->modifiers() & Qt::ShiftModifier) != 0;
            if ((fShift && *psz >= 'a' && *psz <= 'z') || (!fShift && *psz >= 'A' && *psz <= 'Z')) {
                fCapsLock = true;
                ui->capsLabel->setText(tr("Warning: The Caps Lock key is on!"));
            } else if (psz->isLetter()) {
                fCapsLock = false;
                ui->capsLabel->clear();
            }
        }
    }
    return QDialog::eventFilter(object, event);
}

static void SecureClearQLineEdit(QLineEdit* edit)
{
    // Attempt to overwrite text so that they do not linger around in memory
    edit->setText(QString(" ").repeated(edit->text().size()));
    edit->clear();
}

void AskMessengerPassphraseDialog::secureClearPassFields()
{
    SecureClearQLineEdit(ui->passEdit1);
    SecureClearQLineEdit(ui->passEdit2);
    SecureClearQLineEdit(ui->passEdit3);
}
