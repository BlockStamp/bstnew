#ifndef BDB_TX_H
#define BDB_TX_H

#include <memory>
#include <vector>
#include <db_cxx.h>

#include <boost/filesystem/path.hpp>

namespace fs = boost::filesystem;

class TxBerkeleyDb {
public:
    TxBerkeleyDb(const fs::path dir, const std::string& dbName);
    ~TxBerkeleyDb();
    TxBerkeleyDb(const TxBerkeleyDb&) = delete;
    TxBerkeleyDb& operator=(const TxBerkeleyDb&) = delete;

    bool SaveTxData(uint32_t height, uint32_t txid, const std::vector<char>& txdata);

private:
    std::unique_ptr<DbEnv> env;
    std::unique_ptr<Db> db;
};



#endif
