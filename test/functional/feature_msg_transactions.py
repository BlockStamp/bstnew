#!/usr/bin/env python3

"""
Test message transactions functionalities
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.messengertools import get_msgs_for_node, check_msg_txn, get_low_32_bits, get_txn_cost, \
    MSG_TXN_ACCEPTED_DEPTH
from test_framework.blocktools import create_block, create_coinbase
from test_framework.messages import uint256_from_str, hex_str_to_bytes, CTransaction, CTxOut, CTxIn, COutPoint, ToHex
from test_framework.script import CScript, OP_RETURN
from test_framework.util import assert_equal, connect_nodes_bi
import struct
import copy
import time

class MessengerTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.extra_args = [["-txindex"]] * self.num_nodes
        self.setup_clean_chain = True

    def init_test(self):
        self.nodeA = self.nodes[0]
        self.nodeB = self.nodes[1]
        self.nodeC = self.nodes[2]
        self.nodeD = self.nodes[3]
        self.nodeA.generate(nblocks=1000)

    def sync_all_till_block(self, tip):
        self.nodeA.waitforblock(tip)
        self.sync_all()

    def sync_all_till_txns_in_mempool(self, num_txns):
        timeout = 30
        wait = 1
        stop_time = time.time() + timeout
        while time.time() <= stop_time:
            if len(self.nodeA.getrawmempool()) == num_txns:
                break
            time.sleep(wait)
            print('X')
        else:
            print("some msg txns did not enter mempools!!!!!!!!!!!!!!!!!")
            # raise AssertionError("some msg txns did not enter mempools")
        self.sync_all()

    def create_block_with_msgs(self, txns=[]):
        coinbase = create_coinbase(self.nodeA.getblockcount() + 1)
        block = create_block(int(self.nodeA.getbestblockhash(), 16),
                             coinbase,
                             self.nodeA.getblock(self.nodeA.getbestblockhash())['time'] + 1)
        block.vtx.extend(txns)
        block.hashMerkleRoot = block.calc_merkle_root()
        block.rehash()
        block.solve()

        return block

    def test_mining_msg_txns(self):
        nodeA_key = self.nodeA.getmsgkey()
        nodeC_key = self.nodeC.getmsgkey()

        print(self.nodeC.createmsgtransaction(subject="Message from node C to A",
                                        message="Some content",
                                        public_key=nodeA_key,
                                        threads=4))

        print(self.nodeA.createmsgtransaction(subject="Message from node A to C",
                                        message="Another content",
                                        public_key=nodeC_key,
                                        threads=4))

        print(self.nodeC.createmsgtransaction(subject="Second message from node C to A",
                                        message="Yet another content",
                                        public_key=nodeA_key,
                                        threads=4))

        self.sync_all_till_txns_in_mempool(num_txns=3)

        self.curr_tip = self.nodeA.generate(nblocks=1)[0]
        print("new_block", self.curr_tip)
        self.sync_all_till_block(self.curr_tip)

        nodeA_msgs = get_msgs_for_node(self.nodeA)
        nodeA_msgs.sort()

        # remove laster
        if len(nodeA_msgs) != 2:
            print("nodeA mempool", self.nodeA.getrawmempool())
            print("nodeB mempool", self.nodeB.getrawmempool())
            print("nodeC mempool", self.nodeC.getrawmempool())
            print("nodeD mempool", self.nodeD.getrawmempool())

        assert len(nodeA_msgs) == 2
        check_msg_txn(sender_key=nodeC_key,
                      subject="Message from node C to A",
                      content="Some content",
                      msg_str=str(nodeA_msgs[0]))

        check_msg_txn(sender_key=nodeC_key,
                      subject="Second message from node C to A",
                      content="Yet another content",
                      msg_str=str(nodeA_msgs[1]))

        nodeC_msgs = get_msgs_for_node(self.nodeC)
        assert len(nodeC_msgs) == 1
        check_msg_txn(sender_key=nodeA_key,
                      subject="Message from node A to C",
                      content="Another content",
                      msg_str=str(nodeC_msgs[0]))

        nodeB_msgs = get_msgs_for_node(self.nodeB)
        assert len(nodeB_msgs) == 0

    def get_target(self, txn):
        block_subsidy = 5000000000
        txn_cost = get_txn_cost(txn)

        ratio = block_subsidy // txn_cost
        block_target = uint256_from_str(
            hex_str_to_bytes("0000000000ffff00000000000000000000000000000000000000000000000000")[::-1])

        target = block_target * ratio
        return target

    def create_op_return_data(self, tip_height, tip_hash, nonce):
        op_return_data = bytearray("MSGFREE:", "utf-8")
        op_return_data += struct.pack("<I", tip_height)
        op_return_data += struct.pack("<I", tip_hash)
        op_return_data += struct.pack("<I", nonce)  # placeholder for additional info
        op_return_data += bytearray(1200)  # placeholder for encrypted msg
        return op_return_data

    def mine_msg_txn(self, tip_height, tip_hash):
        print("tip_height", tip_height)
        print("tip_hash", tip_hash)
        nonce = 0
        op_return_data = self.create_op_return_data(tip_height, tip_hash, nonce)

        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(0, 0xfffffffe), b"", 0xffffffff))
        tx.vout.append(CTxOut(0, CScript([OP_RETURN, op_return_data])))
        tx.rehash()

        target = self.get_target(tx)

        while tx.sha256 ^ 0x8000000000000000000000000000000000000000000000000000000000000000 > target:
            nonce += 1
            op_return_data[16:20] = struct.pack("<I", nonce)
            tx.vout[0] = CTxOut(0, CScript([OP_RETURN, op_return_data]))
            tx.rehash()

        print("Found nonce", nonce, "\tCurrent txn hash", tx.hash)
        return tx

    def mine_msg_txn_incorrectly(self, tip_height, tip_hash):
        nonce = 0
        op_return_data = self.create_op_return_data(tip_height, tip_hash, nonce)

        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(0, 0xfffffffe), b"", 0xffffffff))
        tx.vout.append(CTxOut(0, CScript([OP_RETURN, op_return_data])))
        tx.rehash()

        lower_bound = self.get_target(tx)
        upper_bound = uint256_from_str(
            hex_str_to_bytes("00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")[::-1])

        print("lower_bound", float(lower_bound), "upper_bound", float(upper_bound))

        while tx.sha256 ^ 0x8000000000000000000000000000000000000000000000000000000000000000 <= lower_bound or \
            tx.sha256 ^ 0x8000000000000000000000000000000000000000000000000000000000000000 > upper_bound:
                nonce += 1
                op_return_data[16:20] = struct.pack("<I", nonce)
                tx.vout[0] = CTxOut(0, CScript([OP_RETURN, op_return_data]))
                tx.rehash()

        print("Incorrect nonce", nonce, "\tCurrent INCORRECT txn hash", tx.hash)
        return tx

    def send_correct_block_with_msg_txn(self):
        tip_height = self.nodeA.getblockcount()
        tip_hash = get_low_32_bits(int(self.nodeA.getbestblockhash(), 16))

        msg_txn = self.mine_msg_txn(tip_height, tip_hash)
        correct_block = self.create_block_with_msgs([msg_txn])
        assert_equal(None, self.nodeA.submitblock(ToHex(correct_block)))

        self.curr_tip = correct_block.hash
        self.correct_msg_txn = msg_txn

        print("correct_block", self.curr_tip)
        self.sync_all_till_block(self.curr_tip)

        print(self.nodeA.getbestblockhash())
        print(self.nodeB.getbestblockhash())
        print(self.nodeC.getbestblockhash())
        print(self.nodeD.getbestblockhash())

        print(self.nodeA.getblockcount())
        print(self.nodeB.getblockcount())
        print(self.nodeC.getblockcount())
        print(self.nodeD.getblockcount())

        print(self.nodeA.getrawmempool())
        print(self.nodeB.getrawmempool())
        print(self.nodeC.getrawmempool())
        print(self.nodeD.getrawmempool())

    def send_block_with_duplicated_txns(self):
        tip_height = self.nodeA.getblockcount()
        tip_hash = get_low_32_bits(int(self.nodeA.getbestblockhash(), 16))

        msg_txn = self.mine_msg_txn(tip_height, tip_hash)
        msg_txn_copy = copy.deepcopy(msg_txn)
        print("duplicated msg", msg_txn.hash)

        block_duplicated_msgs = self.create_block_with_msgs([msg_txn, msg_txn_copy])
        assert_equal("duplicate-msg-txns-in-block", self.nodeA.submitblock(ToHex(block_duplicated_msgs)))
        self.sync_all_till_block(self.curr_tip)

    def send_block_with_msg_transactions_incorrect_tip_height(self):
        tip_height = self.nodeA.getblockcount()
        tip_hash = get_low_32_bits(int(self.nodeA.getbestblockhash(), 16))

        msg_txn = self.mine_msg_txn(tip_height+1, tip_hash)
        bad_block = self.create_block_with_msgs([msg_txn])
        print("too high tip msg", msg_txn.hash)
        print("block with too high tip", bad_block.hash)
        assert_equal("bad-msg-txn-in-block", self.nodeA.submitblock(ToHex(bad_block)))

        msg_txn = self.mine_msg_txn(tip_height-1, tip_hash)
        bad_block = self.create_block_with_msgs([msg_txn])
        print("too low tip msg", msg_txn.hash)
        print("block with too low tip", bad_block.hash)
        assert_equal("bad-msg-txn-in-block", self.nodeA.submitblock(ToHex(bad_block)))

        self.sync_all_till_block(self.curr_tip)

    def send_block_with_msg_transactions_with_hash_above_target(self):
        tip_height = self.nodeA.getblockcount()
        tip_hash = get_low_32_bits(int(self.nodeA.getbestblockhash(), 16))

        msg_txn = self.mine_msg_txn_incorrectly(tip_height, tip_hash)
        bad_block = self.create_block_with_msgs([msg_txn])
        print("hash above target msg", msg_txn.hash)
        print("block with hash above target msg", bad_block.hash)
        assert_equal("bad-msg-txn-in-block", self.nodeA.submitblock(ToHex(bad_block)))
        self.sync_all_till_block(self.curr_tip)

        print("block counts after hash above target message")
        print(self.nodeA.getblockcount())
        print(self.nodeB.getblockcount())
        print(self.nodeC.getblockcount())
        print(self.nodeD.getblockcount())

    def send_blocks_with_copied_msg_from_recent_transactions(self):
        copied_msg_txn = self.correct_msg_txn
        assert copied_msg_txn.hash in self.nodeA.getblock(self.curr_tip)["tx"]

        bad_block = self.create_block_with_msgs([copied_msg_txn])
        print("msg txn copied from previous block", copied_msg_txn.hash)
        print("block with copied msg txn", bad_block.hash)
        assert_equal("bad-msg-txn-in-block", self.nodeB.submitblock(ToHex(bad_block)))
        self.sync_all_till_block(self.curr_tip)

        self.curr_tip = self.nodes[0].generate(nblocks=5)[4]
        self.sync_all_till_block(self.curr_tip)
        print("block counts after generating 5 new blocks")
        print(self.nodeA.getblockcount())
        print(self.nodeB.getblockcount())
        print(self.nodeC.getblockcount())
        print(self.nodeD.getblockcount())

        # restart nodeD to check if it loads recent transactions correctly
        self.restart_node(3, ["-txindex"])
        connect_nodes_bi(self.nodes, 2, 3)

        bad_block = self.create_block_with_msgs([copied_msg_txn])
        print("msg txn copied from 6 blocks ago", copied_msg_txn.hash)
        print("block with copied msg txn from 6 blocks ago", bad_block.hash)
        assert_equal("bad-msg-txn-in-block", self.nodeA.submitblock(ToHex(bad_block)))

        bad_block = self.create_block_with_msgs([copied_msg_txn])
        print("msg txn copied from 6 blocks ago", copied_msg_txn.hash)
        print("block with copied msg txn from 6 blocks ago", bad_block.hash)
        assert_equal("bad-msg-txn-in-block", self.nodeD.submitblock(ToHex(bad_block)))
        self.sync_all_till_block(self.curr_tip)

    def send_blocks_with_copied_msg_from_old_transactions(self):
        self.curr_tip = self.nodes[0].generate(nblocks=1)[0]
        self.sync_all_till_block(self.curr_tip)
        print("block counts after generating 1 new block - msg transaction should not be cached")
        print(self.nodeA.getblockcount())
        print(self.nodeB.getblockcount())
        print(self.nodeC.getblockcount())
        print(self.nodeD.getblockcount())

        copied_msg_txn = self.correct_msg_txn
        assert copied_msg_txn.hash in self.nodeA.getblock(
            self.nodeA.getblockhash(self.nodeA.getblockcount() - MSG_TXN_ACCEPTED_DEPTH))["tx"]

        # restart nodeD to check if it loads recent transactions correctly
        self.restart_node(3, ["-txindex"])
        connect_nodes_bi(self.nodes, 2, 3)

        bad_block = self.create_block_with_msgs([copied_msg_txn])
        print("msg txn copied from 7 blocks ago", copied_msg_txn.hash)
        print("block with copied msg txn from 7 blocks ago", bad_block.hash)
        assert_equal("bad-msg-txn-in-block", self.nodeA.submitblock(ToHex(bad_block)))

        bad_block = self.create_block_with_msgs([copied_msg_txn])
        print("msg txn copied from 7 blocks ago - nodeD", copied_msg_txn.hash)
        print("block with copied msg txn from 7 blocks ago - nodeD", bad_block.hash)
        assert_equal("bad-msg-txn-in-block", self.nodeD.submitblock(ToHex(bad_block)))

    def run_test(self):
        self.init_test()
        self.test_mining_msg_txns()
        self.send_correct_block_with_msg_txn()
        self.send_block_with_duplicated_txns()
        self.send_block_with_msg_transactions_incorrect_tip_height()
        self.send_block_with_msg_transactions_with_hash_above_target()
        self.send_blocks_with_copied_msg_from_recent_transactions()
        self.send_blocks_with_copied_msg_from_old_transactions()



if __name__ == '__main__':
    MessengerTest().main()

