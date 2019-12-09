#!/usr/bin/env python3

"""
Test message transactions functionalities
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.messengertools import get_msgs_for_node, check_msg_txn, get_low_32_bits, get_txn_cost
from test_framework.blocktools import create_block, create_coinbase
from test_framework.messages import uint256_from_str, hex_str_to_bytes, CTransaction, CTxOut, CTxIn, COutPoint
from test_framework.script import CScript, OP_RETURN
from test_framework.mininode import (
    P2PInterface,
    msg_block,
    msg_getdata,
)
import struct


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

        self.nodeA.add_p2p_connection(P2PInterface())
        self.nodeA.generate(nblocks=1000)

    def sync_all_till_block(self, tip):
        self.nodeA.waitforblock(tip)
        self.sync_all()

    def send_block_with_msgs(self, txns=[]):
        coinbase = create_coinbase(self.nodeA.getblockcount() + 1)
        block = create_block(int(self.nodeA.getbestblockhash(), 16),
                             coinbase,
                             self.nodeA.getblock(self.nodeA.getbestblockhash())['time'] + 1)
        block.vtx.extend(txns)
        block.hashMerkleRoot = block.calc_merkle_root()
        block.rehash()
        block.solve()
        block_message = msg_block(block)
        self.nodeA.p2p.send_message(block_message)

        return block.hash

    def test_mining_msg_txns(self):
        nodeA_key = self.nodeA.getmsgkey()
        nodeC_key = self.nodeC.getmsgkey()

        self.nodeC.createmsgtransaction(subject="Message from node C to A",
                                        message="Some content",
                                        public_key=nodeA_key,
                                        threads=4)

        self.nodeA.createmsgtransaction(subject="Message from node A to C",
                                        message="Another content",
                                        public_key=nodeC_key,
                                        threads=4)

        self.nodeC.createmsgtransaction(subject="Second message from node C to A",
                                        message="Yet another content",
                                        public_key=nodeA_key,
                                        threads=4)

        self.sync_all()

        new_block = self.nodes[0].generate(nblocks=1)[0]
        self.sync_all_till_block(new_block)

        nodeA_msgs = get_msgs_for_node(self.nodeA)
        nodeA_msgs.sort()
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

    def create_msg_txn(self, tip_height, tip_hash):
        nonce = 0

        op_return_data = bytearray()
        op_return_data += bytearray("MSGFREE:", "utf-8")
        op_return_data += struct.pack("<I", tip_height)
        op_return_data += struct.pack("<I", tip_hash)
        op_return_data += struct.pack("<I", nonce)  # placeholder for additional info
        op_return_data += bytearray(1200)  # placeholder for encrypted msg

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

        return tx

    def send_correct_msg_txn(self):
        tip_height = self.nodeA.getblockcount()
        tip_hash = get_low_32_bits(int(self.nodeA.getbestblockhash(), 16))

        msg_txn = self.create_msg_txn(tip_height, tip_hash)
        tip = self.send_block_with_msgs([msg_txn])
        self.sync_all_till_block(tip)

    def run_test(self):
        self.init_test()
        self.test_mining_msg_txns()
        self.send_correct_msg_txn()


if __name__ == '__main__':
    MessengerTest().main()

