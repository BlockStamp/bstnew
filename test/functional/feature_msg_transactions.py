#!/usr/bin/env python3

"""
Test message transactions functionalities
"""

import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.messengertools import get_msgs_for_node, check_msg_txn
from test_framework.blocktools import create_block, create_coinbase
from test_framework.mininode import (
    P2PInterface,
    msg_block,
    msg_getdata,
)


class MessengerTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True

    def init_test(self):
        self.nodeA = self.nodes[0]
        self.nodeB = self.nodes[1]
        self.nodeC = self.nodes[2]

        self.nodeA.add_p2p_connection(P2PInterface())
        self.blocks = [int(self.nodes[0].generate(nblocks=1000)[0], 16)]

        self.height = self.nodeA.getblockcount() + 1
        self.tip = int(self.nodeA.getbestblockhash(), 16)
        self.block_time = self.nodeA.getblock(self.nodeA.getbestblockhash())['time'] + 1

    def send_block_with_msgs(self, txns=[]):
        block = create_block(self.tip, create_coinbase(self.height), self.block_time)
        block.vtx.extend(txns)
        block.solve()
        block_message = msg_block(block)
        self.nodeA.p2p.send_message(block_message)
        self.tip = block.sha256
        self.blocks.append(self.tip)
        self.block_time += 1
        self.height += 1

        return block.sha256

    def test_create_msg_txns(self):
        nodeA_key = self.nodeA.getmsgkey()
        nodeC_key = self.nodeC.getmsgkey()

        time.sleep(1)
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

        self.send_block_with_msgs()
        self.sync_all()

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

    def run_test(self):
        self.init_test()
        self.test_create_msg_txns()


if __name__ == '__main__':
    MessengerTest().main()

