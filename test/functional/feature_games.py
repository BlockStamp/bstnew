#!/usr/bin/env python3

"""
Test game functionalities (makebet and automatic getbet)
"""

import math
from decimal import Decimal
from test_framework.test_framework import BitcoinTestFramework


def assert_equal(a, b):
    assert a == b


def assert_almost_equal(bigger, smaller):
    assert bigger > smaller
    assert math.isclose(bigger, smaller, abs_tol=0.001)


class MakeBetTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2

    def generate_block(self):
        self.nodeA.generate(nblocks=1)
        self.sync_all()

    def reach_block_subsidy_of_1(self):
        self.log.info("Mining 8000 blocks")
        for i in range(8):
            self.nodeA.generate(nblocks=1000)
        self.sync_all()

    def assert_number_of_txs_current_block(self, num_txs):
        count = self.nodeA.getblockcount()
        hash = self.nodeA.getblockhash(count)
        block = self.nodeA.getblock(hash)
        assert len(block["tx"]) == num_txs

    def roulette_must_succeed(self):
        self.log.info("Testing roulette")

        bal_1 = self.nodeA.getbalance()
        self.nodeA.makebet(type_of_bet="red@1+black@1")
        bal_2 = self.nodeA.getbalance()
        assert_almost_equal(bal_1, bal_2+2*1)

        self.generate_block()
        bal_3 = self.nodeA.getbalance()
        block_amount = 50
        assert_equal(bal_2 + block_amount, bal_3)

        self.generate_block()
        bal_4 = self.nodeA.getbalance()
        won_amount = 2*1
        assert_equal(bal_3 + won_amount + block_amount, bal_4)

        self.generate_block()
        bal_5 = self.nodeA.getbalance()
        assert_equal(bal_4 + block_amount, bal_5)

    def lottery_must_succeed(self):
        self.log.info("Testing lottery")

        bal_1 = self.nodeA.getbalance()
        self.nodeA.makebet(type_of_bet="1@5", range=4)
        self.nodeA.makebet(type_of_bet="2@5", range=4)
        self.nodeA.makebet(type_of_bet="3@5", range=4)
        self.nodeA.makebet(type_of_bet="4@5", range=4)
        bal_2 = self.nodeA.getbalance()
        assert_almost_equal(bal_1, bal_2 + 4*5)

        self.generate_block()
        bal_3 = self.nodeA.getbalance()
        block_amount = 50
        assert_equal(bal_2 + block_amount, bal_3)

        self.generate_block()
        bal_4 = self.nodeA.getbalance()
        won_amount = 4*5
        assert_equal(bal_3 + won_amount + block_amount, bal_4)

        self.generate_block()
        bal_5 = self.nodeA.getbalance()
        assert_equal(bal_4 + block_amount, bal_5)

    def roulette_two_nodes(self):
        self.log.info("Testing roulette - two nodes")

        bal_A_1 = self.nodeA.getbalance()
        self.nodeA.makebet(type_of_bet="red@8+black@8")
        bal_A_2 = self.nodeA.getbalance()
        assert_almost_equal(bal_A_1, bal_A_2+2*8)

        bal_B_1 = self.nodeB.getbalance()
        self.nodeB.makebet(type_of_bet="red@3+black@3")
        bal_B_2 = self.nodeB.getbalance()
        assert_almost_equal(bal_B_1, bal_B_2+2*3)

        self.sync_all()
        self.generate_block()

        bal_A_3 = self.nodeA.getbalance()
        block_amount = 50
        assert_equal(bal_A_2 + block_amount, bal_A_3)
        bal_B_3 = self.nodeB.getbalance()
        assert_equal(bal_B_2, bal_B_3)

        self.generate_block()
        bal_A_4 = self.nodeA.getbalance()
        won_amount_A = 2*8
        assert_equal(bal_A_3 + won_amount_A + block_amount, bal_A_4)
        bal_B_4 = self.nodeB.getbalance()
        won_amount_B = 2*3
        assert_equal(bal_B_3 + won_amount_B, bal_B_4)

        self.generate_block()
        bal_A_5 = self.nodeA.getbalance()
        assert_equal(bal_A_4 + block_amount, bal_A_5)
        bal_B_5 = self.nodeB.getbalance()
        assert_equal(bal_B_4, bal_B_5)

    def roulette_three_games_one_after_another(self):
        self.log.info("Testing roulette - three games one after another")

        bal_1 = self.nodeA.getbalance()
        self.nodeA.makebet(type_of_bet="red@7.15+black@7.15")
        bal_2 = self.nodeA.getbalance()
        assert_almost_equal(bal_1, bal_2 + Decimal(2*7.15))

        self.generate_block()
        self.nodeA.makebet(type_of_bet="dozen_1@5+dozen_2@5+dozen_3@5")
        bal_3 = self.nodeA.getbalance()
        block_amount = 50
        assert_almost_equal(bal_2 + block_amount, bal_3 + 3*5)

        self.generate_block()
        self.nodeA.makebet(type_of_bet="1@10", range=2)
        self.nodeA.makebet(type_of_bet="2@10", range=2)
        bal_4 = self.nodeA.getbalance()
        won_amount = Decimal(2*7.15)
        assert_almost_equal(bal_3 + block_amount + won_amount, bal_4 + 2*10)

        self.generate_block()
        bal_5 = self.nodeA.getbalance()
        won_amount = 3*5
        assert_equal(bal_4 + block_amount + won_amount, bal_5)

        self.generate_block()
        bal_6 = self.nodeA.getbalance()
        won_amount = 2*10
        assert_equal(bal_5 + block_amount + won_amount, bal_6)

        self.generate_block()
        bal_7 = self.nodeA.getbalance()
        assert_equal(bal_6 + block_amount, bal_7)

    def bet_sum_exceeds_block_subsidy_of_50(self):
        self.log.info("Testing bet sum exceeds block subsidy of 50")

        # block subsidy is 50
        self.nodeA.makebet(type_of_bet="red@3+black@5")                  # 8
        self.nodeA.makebet(type_of_bet="dozen_1@2+dozen_2@1+dozen_3@5")  # 8
        self.nodeA.makebet(type_of_bet="even@1+odd@7")                   # 8
        self.nodeA.makebet(type_of_bet="even@7+odd@1")                   # 8
        self.nodeA.makebet(type_of_bet="1@2+2@2+3@2+4@2", range=4)       # 8
        self.nodeA.makebet(type_of_bet="red@4+black@4")                  # 8
        self.nodeA.makebet(type_of_bet="even@4+odd@4")                   # 8
        self.nodeA.makebet(type_of_bet="even@4+odd@4")                   # 8

        self.generate_block()
        # coinbase + 5 makebets
        self.assert_number_of_txs_current_block(1+6)

        self.generate_block()
        # coinbase + 2 makebets + getbet
        self.assert_number_of_txs_current_block(1+2+1)

        self.generate_block()
        # coinbase + getbet
        self.assert_number_of_txs_current_block(1+1)

        self.generate_block()
        # coinbase
        self.assert_number_of_txs_current_block(1)

    def bet_sum_exceeds_block_subsidy_of_1(self):
        self.log.info("Testing bet sum exceeds block subsidy of 1")
        self.reach_block_subsidy_of_1()

        # block subsidy is 50
        self.nodeB.makebet(type_of_bet="red@0.2+black@0.2")                    # 0.4
        self.nodeA.makebet(type_of_bet="dozen_1@0.1+dozen_2@0.1+dozen_3@0.2")  # 0.4
        self.nodeB.makebet(type_of_bet="even@0.3+odd@0.1")                     # 0.4
        self.nodeA.makebet(type_of_bet="even@0.1+odd@0.3")                     # 0.4
        self.sync_all()

        self.generate_block()
        # coinbase + 2 makebets
        self.assert_number_of_txs_current_block(1+2)

        self.generate_block()
        # coinbase + 2 makebets + getbet
        self.assert_number_of_txs_current_block(1+2+1)

        self.generate_block()
        # coinbase + getbet
        self.assert_number_of_txs_current_block(1+1)

        self.generate_block()
        # coinbase
        self.assert_number_of_txs_current_block(1)

    def potential_bets_reward_exceeds_limit(self):
        self.log.info("Testing potential bets reward exceeds limit")
        # potential bets reward limit is: 104,857,600,000,000(1024*1024*100,000,000)
        self.nodeA.makebet(type_of_bet="1@1", range=524288)    # 52,428,800,000,000
        self.nodeA.makebet(type_of_bet="1@1", range=524287)    # 52,428,700,000,000
        self.nodeA.makebet(type_of_bet="red@0.25+black@0.25")  # 100,000,000
        self.nodeA.makebet(type_of_bet="red@0.25+black@0.25")  # 100,000,000

        self.generate_block()
        # coinbase + 3 makebets
        self.assert_number_of_txs_current_block(1+3)

        self.generate_block()
        # coinbase + 1 makebet + getbet
        self.assert_number_of_txs_current_block(1+1+1)

        self.generate_block()
        self.generate_block()

    def potential_bets_reward_exceeds_limit_after_subsidy_change(self):
        self.log.info("Testing potential bets reward exceeds limit after subsidy change")
        # potential bets reward limit is: 104,857,600,000,000(1024*1024*100,000,000)
        self.nodeA.makebet(type_of_bet="1@0.1", range=5242880)    # 52,428,800,000,000
        self.nodeA.makebet(type_of_bet="1@0.1", range=5242870)    # 52,428,700,000,000
        self.nodeA.makebet(type_of_bet="red@0.25+black@0.25")     # 100,000,000
        self.nodeA.makebet(type_of_bet="red@0.2+black@0.2")       # 80,000,000

        self.generate_block()
        # coinbase + 3 makebets
        self.assert_number_of_txs_current_block(1+3)

        self.generate_block()
        # coinbase + 1 makebet + getbet
        self.assert_number_of_txs_current_block(1+1+1)

        self.generate_block()
        self.generate_block()

    def run_test(self):
        self.nodeA = self.nodes[0]
        self.nodeB = self.nodes[1]

        # test scenarios:
        self.roulette_must_succeed()
        self.lottery_must_succeed()
        self.roulette_two_nodes()
        self.roulette_three_games_one_after_another()
        self.bet_sum_exceeds_block_subsidy_of_50()
        self.potential_bets_reward_exceeds_limit
        self.bet_sum_exceeds_block_subsidy_of_1()
        self.potential_bets_reward_exceeds_limit_after_subsidy_change()


if __name__ == '__main__':
    MakeBetTest().main()

