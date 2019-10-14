// Copyright (c) 2014-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <validation.h>
#include <net.h>

#include <test/test_bitcoin.h>

#include <boost/signals2/signal.hpp>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(main_tests, TestingSetup)

static void TestBlockSubsidyChange(const Consensus::Params& consensusParams)
{
    const int blockSubsidyChangeHeight = consensusParams.SubsidyChangeHeight;
    const CAmount subsidyBeforeChange = 50 * COIN;
    const CAmount subsidyAfterChange = 1 * COIN;

    CAmount subsidy = GetBlockSubsidy(0, consensusParams);
    BOOST_CHECK_EQUAL(subsidyBeforeChange, subsidy);

    subsidy = GetBlockSubsidy(blockSubsidyChangeHeight-1, consensusParams);
    BOOST_CHECK_EQUAL(subsidyBeforeChange, subsidy);

    subsidy = GetBlockSubsidy(blockSubsidyChangeHeight, consensusParams);
    BOOST_CHECK_EQUAL(subsidyAfterChange, subsidy);

    subsidy = GetBlockSubsidy(blockSubsidyChangeHeight+1, consensusParams);
    BOOST_CHECK_EQUAL(subsidyAfterChange, subsidy);
}

static void TestBlockSubsidyChange(int nSubsidyChangeHeight)
{
    Consensus::Params consensusParams;
    consensusParams.SubsidyChangeHeight = nSubsidyChangeHeight;
    TestBlockSubsidyChange(consensusParams);
}

BOOST_AUTO_TEST_CASE(block_subsidy_test)
{
    const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);
    TestBlockSubsidyChange(chainParams->GetConsensus()); // As in main
    TestBlockSubsidyChange(150); // As in regtest
    TestBlockSubsidyChange(1000); // Just another interval
}

BOOST_AUTO_TEST_CASE(subsidy_limit_test)
{
    const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);
    CAmount nSum = 0;
    for (int nHeight = 0; nHeight < 50*1050000; ++nHeight) {
        CAmount nSubsidy = GetBlockSubsidy(nHeight, chainParams->GetConsensus());
        BOOST_CHECK(nSubsidy == 50 * COIN || nSubsidy == 1 * COIN);
        nSum += nSubsidy;
        BOOST_CHECK(MoneyRange(nSum));
    }

    BOOST_CHECK_EQUAL(nSum, CAmount{8608386500000000});
}

static bool ReturnFalse() { return false; }
static bool ReturnTrue() { return true; }

BOOST_AUTO_TEST_CASE(test_combiner_all)
{
    boost::signals2::signal<bool (), CombinerAll> Test;
    BOOST_CHECK(Test());
    Test.connect(&ReturnFalse);
    BOOST_CHECK(!Test());
    Test.connect(&ReturnTrue);
    BOOST_CHECK(!Test());
    Test.disconnect(&ReturnFalse);
    BOOST_CHECK(Test());
    Test.disconnect(&ReturnTrue);
    BOOST_CHECK(Test());
}
BOOST_AUTO_TEST_SUITE_END()
