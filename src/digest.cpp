// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "dccp/cooling_failure_manager/digest.hpp"

#include <cstddef>
#include <cstdint>

namespace dccp::cooling_failure_manager {
namespace {

/// First 32 bits of the fractional parts of the cube roots of the first 64
/// primes (FIPS 180-4 section 4.2.2).
constexpr std::uint32_t kRoundConstants[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

/// First 32 bits of the fractional parts of the square roots of the first 8
/// primes (FIPS 180-4 section 5.3.3).
constexpr std::uint32_t kInitialState[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                                            0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};

constexpr char kHexDigits[] = "0123456789abcdef";

constexpr std::uint32_t rotate_right(std::uint32_t value, unsigned count) noexcept {
  return (value >> count) | (value << (32u - count));
}

void append_hex_byte(std::string& out, std::uint8_t byte) {
  out.push_back(kHexDigits[(byte >> 4) & 0x0Fu]);
  out.push_back(kHexDigits[byte & 0x0Fu]);
}

/// Decodes one lowercase hexadecimal digit; -1 for everything else, including
/// uppercase, so a digest never has two spellings.
int lowercase_hex_value(char digit) noexcept {
  if (digit >= '0' && digit <= '9') {
    return digit - '0';
  }
  if (digit >= 'a' && digit <= 'f') {
    return digit - 'a' + 10;
  }
  return -1;
}

/// Writes the 32-bit state into the digest in big-endian order.
std::array<std::uint8_t, Sha256::kDigestBytes> render_state(
    const std::array<std::uint32_t, 8>& state) noexcept {
  std::array<std::uint8_t, Sha256::kDigestBytes> out{};
  for (std::size_t word = 0; word < state.size(); ++word) {
    out[word * 4] = static_cast<std::uint8_t>((state[word] >> 24) & 0xFFu);
    out[word * 4 + 1] = static_cast<std::uint8_t>((state[word] >> 16) & 0xFFu);
    out[word * 4 + 2] = static_cast<std::uint8_t>((state[word] >> 8) & 0xFFu);
    out[word * 4 + 3] = static_cast<std::uint8_t>(state[word] & 0xFFu);
  }
  return out;
}

}  // namespace

void Sha256::reset() noexcept {
  state_ = {kInitialState[0], kInitialState[1], kInitialState[2], kInitialState[3],
            kInitialState[4], kInitialState[5], kInitialState[6], kInitialState[7]};
  buffer_.fill(0);
  buffered_ = 0;
  total_bytes_ = 0;
  finalized_ = false;
}

void Sha256::compress(const std::uint8_t* block) noexcept {
  std::uint32_t schedule[64];
  for (std::size_t index = 0; index < 16; ++index) {
    schedule[index] = (static_cast<std::uint32_t>(block[index * 4]) << 24) |
                      (static_cast<std::uint32_t>(block[index * 4 + 1]) << 16) |
                      (static_cast<std::uint32_t>(block[index * 4 + 2]) << 8) |
                      (static_cast<std::uint32_t>(block[index * 4 + 3]));
  }
  for (std::size_t index = 16; index < 64; ++index) {
    const std::uint32_t s0 = rotate_right(schedule[index - 15], 7) ^
                             rotate_right(schedule[index - 15], 18) ^ (schedule[index - 15] >> 3);
    const std::uint32_t s1 = rotate_right(schedule[index - 2], 17) ^
                             rotate_right(schedule[index - 2], 19) ^ (schedule[index - 2] >> 10);
    schedule[index] = schedule[index - 16] + s0 + schedule[index - 7] + s1;
  }

  std::uint32_t a = state_[0];
  std::uint32_t b = state_[1];
  std::uint32_t c = state_[2];
  std::uint32_t d = state_[3];
  std::uint32_t e = state_[4];
  std::uint32_t f = state_[5];
  std::uint32_t g = state_[6];
  std::uint32_t h = state_[7];

  for (std::size_t index = 0; index < 64; ++index) {
    const std::uint32_t big_s1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
    const std::uint32_t choose = (e & f) ^ ((~e) & g);
    const std::uint32_t temp1 = h + big_s1 + choose + kRoundConstants[index] + schedule[index];
    const std::uint32_t big_s0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22);
    const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
    const std::uint32_t temp2 = big_s0 + majority;

    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  state_[0] += a;
  state_[1] += b;
  state_[2] += c;
  state_[3] += d;
  state_[4] += e;
  state_[5] += f;
  state_[6] += g;
  state_[7] += h;
}

void Sha256::update(const void* data, std::size_t size) noexcept {
  if (finalized_) {
    // finish() sealed the object; the documented contract is reset() before
    // reuse. Absorbing bytes after sealing would silently produce a digest of a
    // message the caller never finished.
    return;
  }
  if (size == 0) {
    return;
  }
  // The byte counter is the FIPS 180-4 section 5.1.1 length field, which the
  // standard defines modulo 2^64. Reaching 2^64 bytes is impossible here because
  // every caller bounds its input far below that.
  total_bytes_ += static_cast<std::uint64_t>(size);
  const auto* bytes = static_cast<const std::uint8_t*>(data);
  std::size_t index = 0;

  if (buffered_ > 0) {
    while (index < size && buffered_ < kBlockBytes) {
      buffer_[buffered_++] = bytes[index++];
    }
    if (buffered_ == kBlockBytes) {
      compress(buffer_.data());
      buffered_ = 0;
    }
  }
  while (size - index >= kBlockBytes) {
    compress(bytes + index);
    index += kBlockBytes;
  }
  while (index < size) {
    buffer_[buffered_++] = bytes[index++];
  }
}

void Sha256::update_u32(std::uint32_t value) noexcept {
  // Big-endian: FIPS 180-4 hashes multi-byte values in network byte order.
  const std::uint8_t bytes[4] = {static_cast<std::uint8_t>((value >> 24) & 0xFFu),
                                 static_cast<std::uint8_t>((value >> 16) & 0xFFu),
                                 static_cast<std::uint8_t>((value >> 8) & 0xFFu),
                                 static_cast<std::uint8_t>(value & 0xFFu)};
  update(bytes, sizeof(bytes));
}

void Sha256::update_u64(std::uint64_t value) noexcept {
  std::uint8_t bytes[8];
  for (std::size_t index = 0; index < 8; ++index) {
    bytes[index] = static_cast<std::uint8_t>((value >> ((7 - index) * 8)) & 0xFFu);
  }
  update(bytes, sizeof(bytes));
}

std::array<std::uint8_t, Sha256::kDigestBytes> Sha256::finish() noexcept {
  if (finalized_) {
    // Sealed: the state is final, so the same digest is returned again rather
    // than a digest of a different message.
    return render_state(state_);
  }

  const std::uint64_t bit_length = total_bytes_ * 8u;
  buffer_[buffered_++] = 0x80u;
  if (buffered_ > 56) {
    while (buffered_ < kBlockBytes) {
      buffer_[buffered_++] = 0x00u;
    }
    compress(buffer_.data());
    buffered_ = 0;
  }
  while (buffered_ < 56) {
    buffer_[buffered_++] = 0x00u;
  }
  for (std::size_t index = 0; index < 8; ++index) {
    buffer_[56 + index] = static_cast<std::uint8_t>((bit_length >> ((7 - index) * 8)) & 0xFFu);
  }
  compress(buffer_.data());
  buffered_ = 0;
  finalized_ = true;
  return render_state(state_);
}

Result<Digest> Digest::parse_hex(std::string_view hex) {
  if (hex.size() != kBytes * 2) {
    return Error(ErrorCode::MalformedRecord, "digest must be exactly 64 lowercase hex characters")
        .with_subject(std::string(hex.substr(0, 80)));
  }
  std::array<std::uint8_t, kBytes> bytes{};
  for (std::size_t index = 0; index < kBytes; ++index) {
    const int high = lowercase_hex_value(hex[index * 2]);
    const int low = lowercase_hex_value(hex[index * 2 + 1]);
    if (high < 0 || low < 0) {
      return Error(ErrorCode::MalformedRecord, "digest must be lowercase hexadecimal")
          .with_subject(std::string(hex.substr(0, 80)));
    }
    bytes[index] = static_cast<std::uint8_t>((high << 4) | low);
  }
  return Digest(bytes);
}

std::string Digest::to_hex() const {
  std::string out;
  out.reserve(kBytes * 2);
  for (const std::uint8_t byte : bytes_) {
    append_hex_byte(out, byte);
  }
  return out;
}

bool Digest::is_zero() const noexcept {
  for (const std::uint8_t byte : bytes_) {
    if (byte != 0) {
      return false;
    }
  }
  return true;
}

Digest digest_bytes(std::string_view bytes) {
  Sha256 hasher;
  hasher.update(bytes);
  return Digest(hasher.finish());
}

std::string to_hex(std::string_view bytes) {
  std::string out;
  out.reserve(bytes.size() * 2);
  for (const char raw_byte : bytes) {
    append_hex_byte(out, static_cast<std::uint8_t>(raw_byte));
  }
  return out;
}

}  // namespace dccp::cooling_failure_manager
