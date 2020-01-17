#!/usr/bin/env python3

"""Utilities for checking messenger features"""

FEE_PER_BYTE = 1
MSG_TXN_ACCEPTED_DEPTH = 6
TARGET_MULTIPLIER = 8

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


def get_low_32_bits(num):
    return num & 0xFFFFFFFF


def get_txn_size(txn):
    return len(txn.serialize())


def get_txn_cost(txn):
    return get_txn_size(txn) * FEE_PER_BYTE
