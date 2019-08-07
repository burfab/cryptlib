#ifndef SHA256_HASHALGORITHM_H
#define SHA256_HASHALGORITHM_H

#include <cstdlib>

#include "sha_algorithm.hpp"

namespace cryptlib{

class Sha256Algorithm : public ShaAlgorithm<uint32_t, 8, 64, 8> {

private:

  static const uint32_t kA = 0x6a09e667U;
  static const uint32_t kB = 0xbb67ae85U;
  static const uint32_t kC = 0x3c6ef372U;
  static const uint32_t kD = 0xa54ff53aU;
  static const uint32_t kE = 0x510e527fU;
  static const uint32_t kF = 0x9b05688cU;
  static const uint32_t kG = 0x1f83d9abU;
  static const uint32_t kH = 0x5be0cd19U;

  const uint32_t kROUND_CONSTANTS[64] = {
      0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U,
      0x923f82a4U, 0xab1c5ed5U, 0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
      0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U, 0xe49b69c1U, 0xefbe4786U,
      0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
      0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U,
      0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
      0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U, 0xa2bfe8a1U, 0xa81a664bU,
      0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
      0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU,
      0x5b9cca4fU, 0x682e6ff3U, 0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
      0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U};

public:

  virtual void init() {
    m_digest[0] = kA;
    m_digest[1] = kB;
    m_digest[2] = kC;
    m_digest[3] = kD;
    m_digest[4] = kE;
    m_digest[5] = kF;
    m_digest[6] = kG;
    m_digest[7] = kH;

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
    
    m_block[m_blockIdx++] = ((uint8_t)(val1 >> 24));
    m_block[m_blockIdx++] = ((uint8_t)(val1 >> 16));
    m_block[m_blockIdx++] = ((uint8_t)(val1 >> 8));
    m_block[m_blockIdx++] = ((uint8_t)(val1));
}
  virtual inline void processBlock() {
    uint32_t s0, s1, ch, temp1, maj, temp2, w[64];

    for (size_t i = 0; i < 16; i++) {
      w[i] = (uint32_t)(m_block[i * sizeof(uint32_t) + 0]) << 24|
             (uint32_t)(m_block[i * sizeof(uint32_t) + 1]) << 16|
             (uint32_t)(m_block[i * sizeof(uint32_t) + 2]) << 8|
             (uint32_t)(m_block[i * sizeof(uint32_t) + 3]);
    }
    for(size_t i = 16; i < 64; i++){
      s0 = HashAlgorithm::RightRotate(w[i - 15], 7) ^
           HashAlgorithm::RightRotate(w[i - 15], 18) ^ (w[i - 15] >> 3);
      s1 = HashAlgorithm::RightRotate(w[i - 2], 17) ^
           HashAlgorithm::RightRotate(w[i - 2], 19) ^ (w[i - 2] >> 10);

      w[i] = w[i - 16] +  s0 + w[i - 7] + s1;
    }
    uint32_t a = m_digest[0];
    uint32_t b = m_digest[1];
    uint32_t c = m_digest[2];
    uint32_t d = m_digest[3];
    uint32_t e = m_digest[4];
    uint32_t f = m_digest[5];
    uint32_t g = m_digest[6];
    uint32_t h = m_digest[7];

    for(size_t i = 0; i < 64; i++){
      s0 = HashAlgorithm::RightRotate(a, 2) ^
           HashAlgorithm::RightRotate(a, 13) ^
           HashAlgorithm::RightRotate(a, 22);
      maj= (a & b) ^ (a & c) ^ (b & c);
      temp2 = s0 + maj;
      
      s1 = HashAlgorithm::RightRotate(e, 6) ^
           HashAlgorithm::RightRotate(e, 11) ^
           HashAlgorithm::RightRotate(e, 25);
      ch = (e & f) ^ ((~e) & g);
      temp1 = h + s1 + ch + Sha256Algorithm::kROUND_CONSTANTS[i] + w[i];

      h = g;
      g = f;
      f = e;
      e = d + temp1;
      d = c;
      c = b;
      b = a;
      a = temp1 + temp2;
    }

    m_digest[0] += a;
    m_digest[1] += b;
    m_digest[2] += c;
    m_digest[3] += d;
    m_digest[4] += e;
    m_digest[5] += f;
    m_digest[6] += g;
    m_digest[7] += h;

    m_blockIdx = 0;
  }

};
#endif // !SHA256_HASHALGORITHM_H
};