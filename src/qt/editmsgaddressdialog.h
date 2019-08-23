// Copyright (c) 2019 Michal Siek @ BioinfoBank Institute
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_EDITMSGADDRESSDIALOG_H
#define BITCOIN_QT_EDITMSGADDRESSDIALOG_H

#include <QDialog>

class MessengerBookModel;

namespace Ui {
    class EditAddressDialog;
}

QT_BEGIN_NAMESPACE
class QDataWidgetMapper;
QT_END_NAMESPACE

/** Dialog for editing an address and associated information.
 */
class EditMsgAddressDialog : public QDialog
{
    Q_OBJECT

public:
    enum Mode {
        NewSendingAddress,
        EditReceivingAddress,
        EditSendingAddress
    };

    explicit EditMsgAddressDialog(Mode mode, QWidget *parent = 0);
    ~EditMsgAddressDialog();

    void setModel(MessengerBookModel *model);
    void loadRow(int row);

    QString getAddress() const;
    void setAddress(const QString &address);

public Q_SLOTS:
    void accept();

private:
    bool saveCurrentRow();

    /** Return a descriptive string when adding an already-existing address fails. */
    QString getDuplicateAddressWarning() const;

    Ui::EditAddressDialog *ui;
    QDataWidgetMapper *mapper;
    Mode mode;
    MessengerBookModel *model;

    QString address;
};

#endif // BITCOIN_QT_EDITMSGADDRESSDIALOG_H
