#include <stdint.h>
#include <string.h>

#define AES_BLOCK_SIZE 16

// Rijndael S-box calculation
static uint8_t aes_sbox(uint8_t x) {
  uint8_t y = x, z = x;
  y ^= y << 1;
  if (y & 0x80) y ^= 0x1B;
  z ^= z >> 1;
  z ^= z >> 2;
  z ^= z >> 4;
  z ^= 0x63;
  return y ^ z;
}

// Rijndael inverse S-box calculation
static uint8_t aes_rsbox(uint8_t x) {
  uint8_t y = x, z;
  z = y ^ (y >> 1) ^ (y >> 2) ^ (y >> 3) ^ (y >> 4);
  z ^= 0x63;
  y ^= (y << 1) ^ (y << 3) ^ (y << 6);
  y ^= 0x05 ^ 0x09 ^ 0x02;
  return z ^ y;
}

// Rijndael key schedule
static void aes_key_schedule(uint8_t * key, uint8_t * w, int n) {
  int i, j, k;
  uint8_t temp[4], temp2;

  memcpy(w, key, 16);

  for (i = 4; i * n < 4 * (10 + n); i++) {
    for (j = 0; j < 4; j++) {
      temp[j] = w[(i - 1) * 4 + j];
    }
    if (i % n == 0) {
      temp2 = temp[0];
      for (j = 0; j < 3; j++) {
        temp[j] = aes_sbox(temp[(j + 1) % 4]);
      }
      temp[3] = aes_sbox(temp2);
      temp[0] ^= 0x1 << (i / n - 1);
    }
    for (j = 0; j < 4; j++) {
      w[i * 4 + j] = w[(i - n) * 4 + j] ^ temp[j];
    }
  }
}

// Rijndael block encryption
static void aes_encrypt_block(uint8_t * in, uint8_t * out, uint8_t * w, int n) {
  int i, j, k;
  uint8_t state[4][4];

  for (i = 0; i < 4; i++) {
    for (j = 0; j < 4; j++) {
      state[i][j] = aes_sbox(state[i][j]);
    }
  }
  for (i = 0; i < 4; i++) {
    for (j = 0; j < 4; j++) {
      state[(i + j) % 4][j] = state[i][j];
    }
  }
  for (i = 1; i < 4; i++) {
    for (j = 0; j < 4; j++) {
      state[i][j] = state[i][j] ^ state[0][j];
    }
  }
}

for (i = 0; i < 4; i++) {
  for (j = 0; j < 4; j++) {
    state[i][j] ^= w[n * 16 + i * 4 + j];
  }
}

for (i = 0; i < 4; i++) {
  for (j = 0; j < 4; j++) {
    out[i * 4 + j] = state[j][i];
  }
}

// Rijndael block decryption
static void aes_decrypt_block(uint8_t * in, uint8_t * out, uint8_t * w, int n) {
  int i, j, k;
  uint8_t state[4][4];

  for (i = 0; i < 4; i++) {
    for (j = 0; j < 4; j++) {
      state[j][i] = in [i * 4 + j];
    }
  }

  for (k = 0; k < n; k++) {
    for (i = 0; i < 4; i++) {
      for (j = 0; j < 4; j++) {
        state[i][j] ^= w[(n - k) * 16 + i * 4 + j];
      }
    }
    for (i = 0; i < 4; i++) {
      for (j = 0; j < 4; j++) {
        state[i][j] = aes_rsbox(state[i][j]);
      }
    }
    for (i = 0; i < 4; i++) {
      for (j = 0; j < 4; j++) {
        state[(i + j) % 4][j] = state[i][j];
      }
    }
    for (i = 1; i < 4; i++) {
      for (j = 0; j < 4; j++) {
        state[i][j] = state[i][j] ^ state[0][j];
      }
    }
  }

  for (i = 0; i < 4; i++) {
    for (j = 0; j < 4; j++) {
      state[i][j] ^= w[i * 4 + j];
    }
  }

  for (i = 0; i < 4; i++) {
    for (j = 0; j < 4; j++) {
      out[i * 4 + j] = state[j][i];
    }
  }
}

// Rijndael block encryption
static void aes_encrypt(uint8_t * in, uint8_t * out, uint8_t * w, int n, int m) {
  int i, j;
  for (i = 0; i < m; i++) {
    aes_encrypt_block(in + i * AES_BLOCK_SIZE, out + i * AES_BLOCK_SIZE, w, n);
  }
}

// Rijndael block decryption
static void aes_decrypt(uint8_t * in, uint8_t * out, uint8_t * w, int n, int m) {
  int i, j;
  for (i = 0; i < m; i++) {
    aes_decrypt_block(in + i * AES_BLOCK_SIZE, out + i * AES_BLOCK_SIZE, w, n);
  }
}

// Rijndael CBC encryption
static void aes_cbc_encrypt(uint8_t * in, uint8_t * out, uint8_t * w, int n, int m, uint8_t * iv) {
  int i, j;
  uint8_t x[AES_BLOCK_SIZE];
  memcpy(x, iv, AES_BLOCK_SIZE);
  for (i = 0; i < m; i++) {
    for (j = 0; j < AES_BLOCK_SIZE; j++) {
      x[j] ^= in [i * AES_BLOCK_SIZE + j];
    }
    aes_encrypt_block(x, x, w, n);
    memcpy(out + i * AES_BLOCK_SIZE, x, AES_BLOCK_SIZE);
  }
}

// Rijndael CBC decryption
static void aes_cbc_decrypt(uint8_t * in, uint8_t * out, uint8_t * w, int n, int m, uint8_t * iv) {
    int i, j;
    uint8_t x[AES_BLOCK_SIZE], y[AES_BLOCK_SIZE];
    memcpy(y, iv, AES_BLOCK_SIZE);
    for (i = 0; i < m; i++)
      for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
          state[j][i] = in [i * 4 + j];
        }
      }

    for (k = n - 1; k >= 0; k--) {
      for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
          state[i][j] ^= w[k * 16 + i * 4 + j];
        }
      }
      if (k == 0) {
        break;
      }
      uint8_t temp[4][4];
      memcpy(temp, state, sizeof(state));
      for (i = 1; i < 4; i++) {
        for (j = 0; j < 4; j++) {
          state[i][(j + i) % 4] = temp[i][j];
        }
      }
      for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
          temp[i][j] = state[i][j];
        }
      }
      for (i = 0; i < 4; i++) {
        state[0][(i + 1) % 4] = aes_rsbox(temp[0][i]);
        state[1][(i + 2) % 4] = aes_rsbox(temp[1][i]);
        state[2][(i + 3) % 4] = aes_rsbox(temp[2][i]);
        state[3][(i + 4) % 4] = aes_rsbox(temp[3][i]);
      }
    }

    for (i = 0; i < 4; i++) {
      for (j = 0; j < 4; j++) {
        out[i * 4 + j] = state[j][i];
      }
    }

    // Perform key expansion on the given key
    static void aes_key_expansion(uint8_t * key, uint8_t * w, int n) {
        int i, j;
        uint8_t temp[4];
        int nk = n / 4;
        int nb = 4 * (nk + 1);

        for (i = 0; i < nk; i++) {
          w[4 * i] = key[4 * i];
          w[4 * i + 1] = key[4 * i + 1];
          w[4 * i + 2] = key[4 * i + 2];
          w[4 * i + 3] = key[4 * i + 3];
        }

        // AES encryption with 256-bit key
        int aes_encrypt_256(uint8_t * in, uint8_t * out, uint8_t * key) {
          int i;
          uint8_t w[240];
          aes_key_expansion(key, w, 32);
          for (i = 0; i < 16; i++) {
            out[i] = in [i];
          }
          aes_encrypt_block(out, out, w, 14);
          return 0;
        }

        // AES decryption with 256-bit key
        int aes_decrypt_256(uint8_t * in, uint8_t * out, uint8_t * key) {
            int i;
            uint8_t w[240];
            aes_key_expansion(key, w, 32);
            for (i = 0; i < 16; i++) {
              out[i] = in [i];
            }
            aes_decrypt_block(out, out, w, 14);
            return 0;
            int aes_encrypt_256(uint8_t * in, uint8_t * out, uint8_t * key) {
              aes_key_expansion(key, w, 32);
              aes_encrypt_block(out, out, w, 14);
              return 0;
            }
        }
    }
}