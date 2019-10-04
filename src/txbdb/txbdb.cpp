#include "txbdb.h"
#include <memory>
#include <vector>

#include <db_cxx.h>


namespace {

int Comp(Db *, const Dbt* first, const Dbt* second) {
    uint64_t firstKey = *(uint64_t*)first->get_data();
    uint64_t secondKey = *(uint64_t*)second->get_data();

    if (firstKey > secondKey) return 1;
    if (firstKey < secondKey) return -1;
    return 0;
}

}

TxBerkeleyDb::TxBerkeleyDb(const fs::path dir, const std::string& dbName) {
    u_int32_t env_flags = DB_CREATE | DB_INIT_MPOOL;
    u_int32_t db_flags = DB_CREATE;

    env = std::unique_ptr<DbEnv>(new DbEnv(0));

    try {
        env->open(dir.c_str(), env_flags, 0);
        db = std::unique_ptr<Db>(new Db(env.get(), 0));
        db->set_bt_compare(Comp);
        db->open(
            nullptr,
            dbName.c_str(),
            nullptr,
            DB_BTREE,
            db_flags,
            0);
    }
    catch(const std::exception& e) {
        std::cerr << e.what() << std::endl;
        //TODO: add logging
    }

}

TxBerkeleyDb::~TxBerkeleyDb() {
    try {
        if (db) {
            db->close(0);
        }

        if (env) {
            env->close(0);
        }
    }
    catch(std::exception& e) {
        std::cerr << e.what() << std::endl;
    }
}

bool TxBerkeleyDb::SaveTxData(uint32_t height, uint32_t txidx, const std::vector<char> &txdata) {
    uint64_t keyData = (uint64_t)height << 32 | txidx;

    Dbt key(&keyData, sizeof(keyData));
    Dbt value((void*)txdata.data(), txdata.size());

    if (db) {
        return (db->put(nullptr, &key, &value, 0) == 0);
    }

    return false;
}
