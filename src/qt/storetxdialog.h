// Copyright (c) 2011-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_STORETXDIALOG_H
#define BITCOIN_QT_STORETXDIALOG_H

#include <QDialog>

namespace Ui {
    class TransactionDescDialog;
}


/** Dialog showing transaction details. */
class StoreTxDialog : public QDialog
{
    Q_OBJECT

public:
    explicit StoreTxDialog(const QString txid, double fee, int unit, QWidget *parent = 0);
    ~StoreTxDialog();

private:
    Ui::TransactionDescDialog *ui;
};

#endif // BITCOIN_QT_STORETXDIALOG_H
