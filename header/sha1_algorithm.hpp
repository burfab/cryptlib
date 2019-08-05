#ifndef SHA1_HASHALGORITHM_H

#include <cstdlib>

#include "hash_algorithm.hpp"

namespace cryptlib{

class Sha1Algorithm : public HashAlgorithm {

private:
  static const size_t kBLOCKSIZE_BYTES = 64;

  // constants for hash calculation
  static const uint32_t kK0 = 0x5A827999;
  static const uint32_t kK1 = 0x6ED9EBA1;
  static const uint32_t kK2 = 0x8F1BBCDC;
  static const uint32_t kK3 = 0xCA62C1D6;

  // inital values for digest
  static const uint32_t kA = 0x67452301;
  static const uint32_t kB = 0xEFCDAB89;
  static const uint32_t kC = 0x98BADCFE;
  static const uint32_t kD = 0x10325476;
  static const uint32_t kE = 0xC3D2E1F0;

public:
  ~Sha1Algorithm() {
    memset(m_digest, 0, getHashSizeBits() / 8);
    zeroOutBuffer();
  }

  void setFrom(Sha1Algorithm &alg) {
    std::copy(alg.m_digest,
              alg.m_digest + getHashSizeBits() / sizeof(m_digest[0]) / 8,
              this->m_digest);
    std::copy(alg.m_block, alg.m_block + kBLOCKSIZE_BYTES, this->m_block);
    this->m_blockIdx = alg.m_blockIdx;
    this->m_msgByteLen = alg.m_msgByteLen;
  }

  void zeroOutBuffer() { memset(m_block, 0, kBLOCKSIZE_BYTES); }

  virtual void init() {
    m_digest[0] = kA;
    m_digest[1] = kB;
    m_digest[2] = kC;
    m_digest[3] = kD;
    m_digest[4] = kE;

    m_blockIdx = 0;
    m_msgByteLen = 0;
  }

  virtual void transformBlock(const uint8_t *const begin,
                              const uint8_t *const end) {
    const uint8_t *iter = begin;
    while (iter != end) {
      transformByte(*iter);
      iter++;
    }
  }
  virtual void transformBytes(const uint8_t *const p0, const size_t &length) {
    transformBlock(p0, p0 + length);
  }
  virtual void transformByte(const uint8_t &byte) {
    m_block[m_blockIdx++] = byte;
    ++m_msgByteLen;
    if (m_blockIdx == kBLOCKSIZE_BYTES) {
      calculate();
      m_blockIdx = 0;
    }
  }
  virtual size_t getHashSizeBits() { return 160; }

  virtual void getHash(uint8_t *const phash) {
    size_t i = 0;

    transformFinalBlock();

    phash[i++] = (m_digest[0] >> 24) & 0xFF;
    phash[i++] = (m_digest[0] >> 16) & 0xFF;
    phash[i++] = (m_digest[0] >> 8) & 0xFF;
    phash[i++] = (m_digest[0]) & 0xFF;

    phash[i++] = (m_digest[1] >> 24) & 0xFF;
    phash[i++] = (m_digest[1] >> 16) & 0xFF;
    phash[i++] = (m_digest[1] >> 8) & 0xFF;
    phash[i++] = (m_digest[1]) & 0xFF;

    phash[i++] = (m_digest[2] >> 24) & 0xFF;
    phash[i++] = (m_digest[2] >> 16) & 0xFF;
    phash[i++] = (m_digest[2] >> 8) & 0xFF;
    phash[i++] = (m_digest[2]) & 0xFF;

    phash[i++] = (m_digest[3] >> 24) & 0xFF;
    phash[i++] = (m_digest[3] >> 16) & 0xFF;
    phash[i++] = (m_digest[3] >> 8) & 0xFF;
    phash[i++] = (m_digest[3]) & 0xFF;

    phash[i++] = (m_digest[4] >> 24) & 0xFF;
    phash[i++] = (m_digest[4] >> 16) & 0xFF;
    phash[i++] = (m_digest[4] >> 8) & 0xFF;
    phash[i++] = (m_digest[4]) & 0xFF;
  }

private:
  void calculate() {
    uint32_t f, k, temp, w[80];

    for (size_t i = 0; i < 16; i++) {
      w[i] = (m_block[i * 4 + 0] << 24) | (m_block[i * 4 + 1] << 16) |
             (m_block[i * 4 + 2] << 8) | (m_block[i * 4 + 3]);
    }

    for (size_t i = 16; i < 80; i++) {
      w[i] = HashAlgorithm::LeftRotate(
          (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]), 1);
    }

    uint32_t a = m_digest[0];
    uint32_t b = m_digest[1];
    uint32_t c = m_digest[2];
    uint32_t d = m_digest[3];
    uint32_t e = m_digest[4];

    for (size_t i = 0; i < 80; i++) {
      if (i < 20) {
        f = (b & c) | (~b & d);
        k = kK0;
      } else if (i < 40) {
        f = b ^ c ^ d;
        k = kK1;
      } else if (i < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = kK2;
      } else {
        f = b ^ c ^ d;
        k = kK3;
      }

      temp = HashAlgorithm::LeftRotate(a, 5) + f + e + k + w[i];
      e = d;
      d = c;
      c = HashAlgorithm::LeftRotate(b, 30);
      b = a;
      a = temp;
    }
    m_digest[0] += a;
    m_digest[1] += b;
    m_digest[2] += c;
    m_digest[3] += d;
    m_digest[4] += e;

    m_blockIdx = 0;
  }

private:
  void transformFinalBlock() {
    uint64_t msgLen_bits = m_msgByteLen * 8;
    uint32_t highVal = (uint32_t)(msgLen_bits >> 32);
    uint32_t lowVal = (uint32_t)msgLen_bits;

    if (m_blockIdx == kBLOCKSIZE_BYTES)
      calculate();

    m_block[m_blockIdx++] = 0x80;
    if (m_blockIdx > 56) {
      memset(m_block + m_blockIdx, 0x00, kBLOCKSIZE_BYTES - m_blockIdx);
      calculate();
    }
    if (m_blockIdx < 56)
      memset(m_block + m_blockIdx, 0x00, 56 - m_blockIdx);

    m_block[56] = ((uint8_t)(highVal >> 24));
    m_block[57] = ((uint8_t)(highVal >> 16));
    m_block[58] = ((uint8_t)(highVal >> 8));
    m_block[59] = ((uint8_t)(highVal >> 0));

    m_block[60] = ((uint8_t)(lowVal >> 24));
    m_block[61] = ((uint8_t)(lowVal >> 16));
    m_block[62] = ((uint8_t)(lowVal >> 8));
    m_block[63] = ((uint8_t)(lowVal >> 0));

    m_blockIdx = kBLOCKSIZE_BYTES;
    calculate();
  }

  uint32_t m_digest[5];
  uint8_t m_block[Sha1Algorithm::kBLOCKSIZE_BYTES];

  size_t m_blockIdx = 0;
  size_t m_msgByteLen = 0;
};
#endif // !SHA1_HASHALGORITHM_H
};