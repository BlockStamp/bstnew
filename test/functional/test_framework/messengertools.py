#!/usr/bin/env python3

"""Utilities for checking messenger features"""


def get_msgs_for_node(node):
    res = []
    txns = node.listmsgsinceblock()['transactions']

    for tx in txns:
        msg = node.readmessage(txid=tx['txid'])
        res.append(msg[1:-2])

    return res


def check_msg_txn(sender_key, subject, content, msg_str):
    expected_str = sender_key + "\n" + subject + "\n" + content
    assert expected_str == msg_str