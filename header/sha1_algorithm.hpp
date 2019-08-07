#ifndef SHA1_HASHALGORITHM_H

#include <cstdlib>

#include "sha_algorithm.hpp"

namespace cryptlib{

class Sha1Algorithm : public ShaAlgorithm<uint32_t, 5, 64, 8>{

public:
  virtual void init() {
    m_digest[0] = kA;
    m_digest[1] = kB;
    m_digest[2] = kC;
    m_digest[3] = kD;
    m_digest[4] = kE;

    m_blockIdx = 0;
    m_msgByteLen = 0;
  }

protected:

  virtual inline void writeMessageLenToBuffer(const uint64_t &msgLen_bits) {
    uint32_t val0 = (uint32_t)(msgLen_bits >> 32);
    uint32_t val1 = (uint32_t)msgLen_bits;
    
    m_block[m_blockIdx++] = ((uint8_t)(val0 >> 24));
    m_block[m_blockIdx++] = ((uint8_t)(val0 >> 16));
    m_block[m_blockIdx++] = ((uint8_t)(val0 >> 8));
    m_block[m_blockIdx++] = ((uint8_t)(val0));

    m_block[m_blockIdx++] = ((uint8_t)(val1>> 24));
    m_block[m_blockIdx++] = ((uint8_t)(val1>> 16));
    m_block[m_blockIdx++] = ((uint8_t)(val1>> 8));
    m_block[m_blockIdx++] = ((uint8_t)(val1));
}

  virtual inline void processBlock() {
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
        f = (b & c) | ((~b) & d);
        k = Sha1Algorithm::kROUND_CONSTANTS[0];
      } else if (i < 40) {
        f = b ^ c ^ d;
        k = Sha1Algorithm::kROUND_CONSTANTS[1];
      } else if (i < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = Sha1Algorithm::kROUND_CONSTANTS[2];
      } else {
        f = b ^ c ^ d;
        k = Sha1Algorithm::kROUND_CONSTANTS[3];
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
  const uint32_t kROUND_CONSTANTS[80] = {
      0x5A827999U,
      0x6ED9EBA1U,
      0x8F1BBCDCU,
      0xCA62C1D6U,
  };

  // inital values for digest
  static const uint32_t kA = 0x67452301;
  static const uint32_t kB = 0xEFCDAB89;
  static const uint32_t kC = 0x98BADCFE;
  static const uint32_t kD = 0x10325476;
  static const uint32_t kE = 0xC3D2E1F0;

};
};     // namespace cryptlib
#endif // !SHA1_HASHALGORITHM_H