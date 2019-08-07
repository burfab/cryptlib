#ifndef SHA_ALGORITHM_H
#define SHA_ALGORITHM_H

#include <cstdlib>

#include "hash_algorithm.hpp"

namespace cryptlib {


template<class WORD_TYPE, size_t T_DIGEST_LEN, size_t T_BLOCK_SIZE, size_t T_MESSAGE_LEN_PADDING_LEN>
class ShaAlgorithm : public HashAlgorithm {

protected:
  size_t getBlockSize() { return T_BLOCK_SIZE; }

public:

  ~ShaAlgorithm() {
    memset(m_digest, 0, getHashSizeBits() / 8);
    zeroOutBuffer();
  }

template <class T>
  void setFrom(T &alg) {
    std::copy(alg.m_digest,
              alg.m_digest + getHashSizeBits() / sizeof(m_digest[0]) / 8,
              this->m_digest);
    std::copy(alg.m_block, alg.getBlockSize() + alg.m_blockSize, this->m_block);
    this->m_blockIdx = alg.m_blockIdx;
    this->m_msgByteLen = alg.m_msgByteLen;
  }

  virtual inline size_t getHashSizeBits() {
    return T_DIGEST_LEN * sizeof(m_digest[0]) * 8;
  }
  virtual void getHash(uint8_t *const phash) {
    size_t i = 0;

    transformFinalBlock();

    size_t max_di = sizeof(m_digest) / sizeof(m_digest[0]) * sizeof(uint8_t);
    size_t smax = sizeof(m_digest[0]) * 8 - 8;

    size_t pi = 0;
    for (size_t di = 0; di < max_di; di++) {
      for (int s = smax; s > -1; s -= 8) {
        phash[pi++] = (m_digest[di] >> s) & 0xff;
      }
    }
  }
  void zeroOutBuffer() { memset(m_block, 0, T_BLOCK_SIZE); }
  
  virtual inline void transformBlock(const uint8_t *const begin,
                              const uint8_t *const end) {
    const uint8_t *iter = begin;
    while (iter != end) {
      transformByte(*iter);
      iter++;
    }
  }
  virtual inline void transformBytes(const uint8_t *const p0, const size_t &length) {
    transformBlock(p0, p0 + length);
  }

  virtual inline void transformByte(const uint8_t &byte) {
    m_block[m_blockIdx++] = byte;
    ++m_msgByteLen;
    if (m_blockIdx == T_BLOCK_SIZE) {
      processBlock();
      m_blockIdx = 0;
    }
  }
protected:
  virtual inline void processBlock() = 0;
  virtual inline void writeMessageLenToBuffer(const uint64_t &msgLen_bits)= 0;

  void transformFinalBlock() {
    uint64_t msgLen_bits = m_msgByteLen * 8;
    const size_t BLOCKSIZE = T_BLOCK_SIZE;
    const size_t MESSAGE_PADDING_LEN = T_MESSAGE_LEN_PADDING_LEN;

    if (m_blockIdx == T_BLOCK_SIZE)
      processBlock();

    m_block[m_blockIdx++] = 0x80;
    if (m_blockIdx > T_BLOCK_SIZE - T_MESSAGE_LEN_PADDING_LEN) {
      memset(m_block + m_blockIdx, 0x00, T_BLOCK_SIZE - m_blockIdx);
      processBlock();
    }
    if (m_blockIdx < T_BLOCK_SIZE - T_MESSAGE_LEN_PADDING_LEN)
      memset(m_block + m_blockIdx, 0x00, T_BLOCK_SIZE - 8 - m_blockIdx);

    m_blockIdx = BLOCKSIZE - MESSAGE_PADDING_LEN;

    writeMessageLenToBuffer(msgLen_bits);

    processBlock();
  }

protected:
  WORD_TYPE m_digest[T_DIGEST_LEN];
  uint8_t m_block[T_BLOCK_SIZE];

  size_t m_blockIdx = 0;
  size_t m_msgByteLen = 0;
};
} // namespace cryptlib
#endif // !SHA_ALGORITHM_H