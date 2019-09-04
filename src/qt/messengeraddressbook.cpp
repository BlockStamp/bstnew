// Copyright (c) 2011-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <qt/messengeraddressbook.h>
#include <qt/forms/ui_addressbookpage.h>
#include <qt/messengerbookmodel.h>

#include <qt/bitcoingui.h>
#include <qt/editmsgaddressdialog.h>
#include <qt/guiutil.h>
#include <qt/platformstyle.h>

#include <QIcon>
#include <QMenu>
#include <QMessageBox>
#include <QSortFilterProxyModel>


class MsgAddressBookSortFilterProxyModel final : public QSortFilterProxyModel
{

public:
    MsgAddressBookSortFilterProxyModel(QObject* parent)
        : QSortFilterProxyModel(parent)
    {
        setDynamicSortFilter(true);
        setFilterCaseSensitivity(Qt::CaseInsensitive);
        setSortCaseSensitivity(Qt::CaseInsensitive);
    }

protected:
    bool filterAcceptsRow(int row, const QModelIndex& parent) const
    {
        auto model = sourceModel();
        auto label = model->index(row, MessengerBookModel::Label, parent);
        auto address = model->index(row, MessengerBookModel::Address, parent);

        if (filterRegExp().indexIn(model->data(address).toString()) < 0 &&
            filterRegExp().indexIn(model->data(label).toString()) < 0) {
            return false;
        }

        return true;
    }
};

MessengerAddressBook::MessengerAddressBook(const PlatformStyle *platformStyle, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::AddressBookPage),
    model(0)
{
    ui->setupUi(this);

    if (!platformStyle->getImagesOnButtons()) {
        ui->newAddress->setIcon(QIcon());
        ui->copyAddress->setIcon(QIcon());
        ui->deleteAddress->setIcon(QIcon());
        ui->exportButton->setIcon(QIcon());
    } else {
        ui->newAddress->setIcon(platformStyle->SingleColorIcon(":/icons/add"));
        ui->copyAddress->setIcon(platformStyle->SingleColorIcon(":/icons/editcopy"));
        ui->deleteAddress->setIcon(platformStyle->SingleColorIcon(":/icons/remove"));
        ui->exportButton->setIcon(platformStyle->SingleColorIcon(":/icons/export"));
    }

    setWindowTitle(tr("Choose the address to send message"));

    connect(ui->tableView, &QTableView::doubleClicked, this, &QDialog::accept);
    ui->tableView->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->tableView->setFocus();
    ui->closeButton->setText(tr("C&hoose"));
    ui->exportButton->hide();

    ui->labelExplanation->setText(tr("These are addresses for use in messenger"));
    ui->deleteAddress->setVisible(true);
    ui->newAddress->setVisible(true);


    // Context menu actions
    QAction *copyAddressAction = new QAction(tr("&Copy Address"), this);
    QAction *copyLabelAction = new QAction(tr("Copy &Label"), this);
    QAction *editAction = new QAction(tr("&Edit"), this);
    deleteAction = new QAction(ui->deleteAddress->text(), this);

    // Build context menu
    contextMenu = new QMenu(this);
    contextMenu->addAction(copyAddressAction);
    contextMenu->addAction(copyLabelAction);
    contextMenu->addAction(editAction);
    contextMenu->addSeparator();

    // Connect signals for context menu actions
    connect(copyAddressAction, &QAction::triggered, this, &MessengerAddressBook::on_copyAddress_clicked);
    connect(copyLabelAction, &QAction::triggered, this, &MessengerAddressBook::onCopyLabelAction);
    connect(editAction, &QAction::triggered, this, &MessengerAddressBook::onEditAction);
    connect(deleteAction, &QAction::triggered, this, &MessengerAddressBook::on_deleteAddress_clicked);

    connect(ui->tableView, &QWidget::customContextMenuRequested, this, &MessengerAddressBook::contextualMenu);

    connect(ui->closeButton, &QPushButton::clicked, this, &QDialog::accept);
}

MessengerAddressBook::~MessengerAddressBook()
{
    delete ui;
}

void MessengerAddressBook::setModel(MessengerBookModel *_model)
{
    this->model = _model;
    if(!_model)
        return;

    proxyModel = new MsgAddressBookSortFilterProxyModel(this);
    proxyModel->setSourceModel(_model);

    connect(ui->searchLineEdit, &QLineEdit::textChanged, proxyModel, &QSortFilterProxyModel::setFilterWildcard);

    ui->tableView->setModel(proxyModel);
    ui->tableView->sortByColumn(0, Qt::AscendingOrder);

    ui->tableView->setColumnHidden(1, true);

    // Set column widths
    ui->tableView->horizontalHeader()->setSectionResizeMode(MessengerBookModel::Label, QHeaderView::Stretch);
    ui->tableView->horizontalHeader()->setSectionResizeMode(MessengerBookModel::Address, QHeaderView::ResizeToContents);

    connect(ui->tableView->selectionModel(), &QItemSelectionModel::selectionChanged,
        this, &MessengerAddressBook::selectionChanged);

    // Select row for newly created address
    connect(_model, &MessengerBookModel::rowsInserted, this, &MessengerAddressBook::selectNewAddress);

    selectionChanged();
}

void MessengerAddressBook::on_copyAddress_clicked()
{
    GUIUtil::copyEntryData(ui->tableView, MessengerBookModel::Address);
}

void MessengerAddressBook::onCopyLabelAction()
{
    GUIUtil::copyEntryData(ui->tableView, MessengerBookModel::Label);
}

void MessengerAddressBook::onEditAction()
{
    if(!model)
        return;

    if(!ui->tableView->selectionModel())
        return;

    QModelIndexList indexes = ui->tableView->selectionModel()->selectedRows();
    if(indexes.isEmpty())
        return;

    EditMsgAddressDialog dlg(EditMsgAddressDialog::EditSendingAddress, this);
    dlg.setModel(model);
    QModelIndex origIndex = proxyModel->mapToSource(indexes.at(0));
    dlg.loadRow(origIndex.row());
    dlg.exec();
}

void MessengerAddressBook::on_newAddress_clicked()
{
    if(!model)
        return;

    EditMsgAddressDialog dlg(EditMsgAddressDialog::NewSendingAddress, this);
    dlg.setModel(model);
    if(dlg.exec())
    {
        newAddressToSelect = dlg.getAddress();
    }
}

void MessengerAddressBook::on_deleteAddress_clicked()
{
    QTableView *table = ui->tableView;
    if(!table->selectionModel())
        return;

    QModelIndexList indexes = table->selectionModel()->selectedRows();
    if(!indexes.isEmpty())
    {
        table->model()->removeRow(indexes.at(0).row());
    }
}

void MessengerAddressBook::selectionChanged()
{
    // Set button states based on selected tab and selection
    QTableView *table = ui->tableView;
    if(!table->selectionModel())
        return;

    if(table->selectionModel()->hasSelection())
    {
        // In sending tab, allow deletion of selection
        ui->deleteAddress->setEnabled(true);
        ui->deleteAddress->setVisible(true);
        deleteAction->setEnabled(true);
        ui->copyAddress->setEnabled(true);
    }
    else
    {
        ui->deleteAddress->setEnabled(false);
        ui->copyAddress->setEnabled(false);
    }
}

void MessengerAddressBook::done(int retval)
{
    QTableView *table = ui->tableView;
    if(!table->selectionModel() || !table->model()) {
        return;
    }

    // Figure out which address was selected, and return it
    QModelIndexList indexes = table->selectionModel()->selectedRows(MessengerBookModel::Address);

    for (const QModelIndex& index : indexes) {
        QVariant address = table->model()->data(index);
        returnValue = address.toString();
    }

    if(returnValue.isEmpty())
    {
        // If no address entry selected, return rejected
        retval = Rejected;
    }

    QDialog::done(retval);
}

void MessengerAddressBook::contextualMenu(const QPoint &point)
{
    QModelIndex index = ui->tableView->indexAt(point);
    if(index.isValid())
    {
        contextMenu->exec(QCursor::pos());
    }
}

void MessengerAddressBook::selectNewAddress(const QModelIndex &parent, int begin, int /*end*/)
{
    QModelIndex idx = proxyModel->mapFromSource(model->index(begin, MessengerBookModel::Address, parent));
    if(idx.isValid() && (idx.data(Qt::EditRole).toString() == newAddressToSelect))
    {
        // Select row of newly created address, once
        ui->tableView->setFocus();
        ui->tableView->selectRow(idx.row());
        newAddressToSelect.clear();
    }
}
