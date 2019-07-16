#ifndef MESSAGE_ENCRYPTION_H
#define MESSAGE_ENCRYPTION_H

#include <memory>
#include <utility>

std::pair<std::unique_ptr<unsigned char[]>, size_t> createEncryptedMessage();

#endif
