#!/usr/bin/env python3

"""
Test messenger functionalities
"""

from test_framework.test_framework import BitcoinTestFramework


class MessengerTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3

    def generate_block(self):
        self.nodeA.generate(nblocks=1)
        self.sync_all()

    def get_msgs_for_node(self, node):
        res = []
        txns = node.listmsgsinceblock()['transactions']

        for tx in txns:
            msg = node.readmessage(txid=tx['txid'])
            res.append(msg[1:-2])

        return res

    def check_msg_txn(self, sender_key, subject, content, msg_str):
        expected_str = sender_key + "\n" + subject + "\n" + content
        assert expected_str == msg_str

    def test_sending_msgs(self):
        nodeA_key = self.nodeA.getmsgkey()
        nodeC_key = self.nodeC.getmsgkey()

        self.nodeC.sendmessage(subject="Message from node C to A",
                               message="Some content",
                               public_key=nodeA_key)

        self.nodeA.sendmessage(subject="Message from node A to C",
                               message="Another content",
                               public_key=nodeC_key)

        self.nodeC.sendmessage(subject="Second message from node C to A",
                               message="Yet another content",
                               public_key=nodeA_key)

        self.generate_block()

        nodeA_msgs = self.get_msgs_for_node(self.nodeA)
        nodeA_msgs.sort()
        assert len(nodeA_msgs) == 2
        self.check_msg_txn(sender_key=nodeC_key,
                           subject="Message from node C to A",
                           content="Some content",
                           msg_str=str(nodeA_msgs[0]))

        self.check_msg_txn(sender_key=nodeC_key,
                           subject="Second message from node C to A",
                           content="Yet another content",
                           msg_str=str(nodeA_msgs[1]))

        nodeC_msgs = self.get_msgs_for_node(self.nodeC)
        assert len(nodeC_msgs) == 1
        self.check_msg_txn(sender_key=nodeA_key,
                           subject="Message from node A to C",
                           content="Another content",
                           msg_str=str(nodeC_msgs[0]))

        nodeB_msgs = self.get_msgs_for_node(self.nodeB)
        assert len(nodeB_msgs) == 0

    def run_test(self):
        self.nodeA = self.nodes[0]
        self.nodeB = self.nodes[1]
        self.nodeC = self.nodes[2]

        self.test_sending_msgs()

if __name__ == '__main__':
    MessengerTest().main()

