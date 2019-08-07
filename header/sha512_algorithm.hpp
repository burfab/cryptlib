#ifndef SHA512_HASHALGORITHM_H
#define SHA512_HASHALGORITHM_H

#include <cstdlib>

#include "sha_algorithm.hpp"

namespace cryptlib{

class Sha512Algorithm : public ShaAlgorithm<uint64_t, 8, 128, 16> {

private:

  static const uint64_t kA = 0x6a09e667f3bcc908ULL;
  static const uint64_t kB = 0xbb67ae8584caa73bULL;
  static const uint64_t kC = 0x3c6ef372fe94f82bULL;
  static const uint64_t kD = 0xa54ff53a5f1d36f1ULL;
  static const uint64_t kE = 0x510e527fade682d1ULL;
  static const uint64_t kF = 0x9b05688c2b3e6c1fULL;
  static const uint64_t kG = 0x1f83d9abfb41bd6bULL;
  static const uint64_t kH = 0x5be0cd19137e2179ULL;

  const uint64_t kROUND_CONSTANTS[80] = {
      0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
      0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
      0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
      0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
      0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
      0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
      0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
      0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
      0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
      0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
      0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
      0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
      0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
      0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
      0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
      0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
      0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
      0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
      0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
      0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
      0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
      0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
      0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
      0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
      0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
      0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
      0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

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
    uint32_t val0 = 0x0;
    uint32_t val1 = 0x0;
    uint32_t val2 = (uint32_t)(msgLen_bits >> 32);
    uint32_t val3 = (uint32_t)msgLen_bits;
    
    m_block[m_blockIdx++] = ((uint8_t)(val0 >> 24));
    m_block[m_blockIdx++] = ((uint8_t)(val0 >> 16));
    m_block[m_blockIdx++] = ((uint8_t)(val0 >> 8));
    m_block[m_blockIdx++] = ((uint8_t)(val0));
    
    m_block[m_blockIdx++] = ((uint8_t)(val1 >> 24));
    m_block[m_blockIdx++] = ((uint8_t)(val1 >> 16));
    m_block[m_blockIdx++] = ((uint8_t)(val1 >> 8));
    m_block[m_blockIdx++] = ((uint8_t)(val1));

    m_block[m_blockIdx++] = ((uint8_t)(val2 >> 24));
    m_block[m_blockIdx++] = ((uint8_t)(val2 >> 16));
    m_block[m_blockIdx++] = ((uint8_t)(val2 >> 8));
    m_block[m_blockIdx++] = ((uint8_t)(val2));

    m_block[m_blockIdx++] = ((uint8_t)(val3>> 24));
    m_block[m_blockIdx++] = ((uint8_t)(val3>> 16));
    m_block[m_blockIdx++] = ((uint8_t)(val3>> 8));
    m_block[m_blockIdx++] = ((uint8_t)(val3));
}
  virtual inline void processBlock() {
    uint64_t s0, s1, ch, temp1, maj, temp2, w[80];

    for (size_t i = 0; i < 16; i++) {
      w[i] = (uint64_t)(m_block[i * sizeof(uint64_t) + 0]) << 56 |
             (uint64_t)(m_block[i * sizeof(uint64_t) + 1]) << 48 |
             (uint64_t)(m_block[i * sizeof(uint64_t) + 2]) << 40 |
             (uint64_t)(m_block[i * sizeof(uint64_t) + 3]) << 32 |
             (uint64_t)(m_block[i * sizeof(uint64_t) + 4]) << 24 |
             (uint64_t)(m_block[i * sizeof(uint64_t) + 5]) << 16 |
             (uint64_t)(m_block[i * sizeof(uint64_t) + 6]) << 8 |
             (uint64_t)(m_block[i * sizeof(uint64_t) + 7]);
    }
    for(size_t i = 16; i < 80; i++){
      s0 = HashAlgorithm::RightRotate(w[i - 15], 1) ^
           HashAlgorithm::RightRotate(w[i - 15], 8) ^ (w[i - 15] >> 7);
      s1 = HashAlgorithm::RightRotate(w[i - 2], 19) ^
           HashAlgorithm::RightRotate(w[i - 2], 61) ^ (w[i - 2] >> 6);

      w[i] = w[i - 16] +  s0 + w[i - 7] + s1;
    }
    uint64_t a = m_digest[0];
    uint64_t b = m_digest[1];
    uint64_t c = m_digest[2];
    uint64_t d = m_digest[3];
    uint64_t e = m_digest[4];
    uint64_t f = m_digest[5];
    uint64_t g = m_digest[6];
    uint64_t h = m_digest[7];

    for(size_t i = 0; i < 80; i++){
      s0 = HashAlgorithm::RightRotate(a, 28) ^
           HashAlgorithm::RightRotate(a, 34) ^
           HashAlgorithm::RightRotate(a, 39);
      maj= (a & b) ^ (a & c) ^ (b & c);
      temp2 = s0 + maj;
      
      s1 = HashAlgorithm::RightRotate(e, 14) ^
           HashAlgorithm::RightRotate(e, 18) ^
           HashAlgorithm::RightRotate(e, 41);
      ch = (e & f) ^ ((~e) & g);
      temp1 = h + s1 + ch + Sha512Algorithm::kROUND_CONSTANTS[i] + w[i];

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
#endif // !SHA512_HASHALGORITHM_H
};