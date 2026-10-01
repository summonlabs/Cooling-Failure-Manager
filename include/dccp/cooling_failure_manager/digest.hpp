// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef DCCP_COOLING_FAILURE_MANAGER_DIGEST_HPP
#define DCCP_COOLING_FAILURE_MANAGER_DIGEST_HPP

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "dccp/cooling_failure_manager/result.hpp"

namespace dccp::cooling_failure_manager {

/// SHA-256 (FIPS 180-4), implemented here so that canonical digests do not
/// depend on a third-party library or on platform crypto policy. This is an
/// integrity primitive, not a security boundary: see the README.
class Sha256 {
 public:
  static constexpr std::size_t kDigestBytes = 32;
  static constexpr std::size_t kBlockBytes = 64;

  Sha256() noexcept { reset(); }

  void reset() noexcept;
  void update(const void* data, std::size_t size) noexcept;
  void update(std::string_view data) noexcept { update(data.data(), data.size()); }
  void update_byte(std::uint8_t byte) noexcept { update(&byte, 1); }
  void update_u32(std::uint32_t value) noexcept;
  void update_u64(std::uint64_t value) noexcept;

  /// Finalizes and returns the digest. The object must be reset() before reuse.
  std::array<std::uint8_t, kDigestBytes> finish() noexcept;

 private:
  void compress(const std::uint8_t* block) noexcept;

  std::array<std::uint32_t, 8> state_{};
  std::array<std::uint8_t, kBlockBytes> buffer_{};
  std::size_t buffered_ = 0;
  std::uint64_t total_bytes_ = 0;
  bool finalized_ = false;
};

/// A 32-byte integrity digest with a fixed lowercase-hex rendering.
class Digest {
 public:
  static constexpr std::size_t kBytes = Sha256::kDigestBytes;

  Digest() noexcept = default;
  explicit Digest(std::array<std::uint8_t, kBytes> bytes) noexcept : bytes_(bytes) {}

  /// Parses exactly 64 lowercase hex characters.
  static Result<Digest> parse_hex(std::string_view hex);

  const std::array<std::uint8_t, kBytes>& bytes() const noexcept { return bytes_; }

  /// 64 lowercase hex characters.
  std::string to_hex() const;

  bool is_zero() const noexcept;

  friend bool operator==(const Digest&, const Digest&) noexcept = default;
  friend std::strong_ordering operator<=>(const Digest&, const Digest&) noexcept = default;

 private:
  std::array<std::uint8_t, kBytes> bytes_{};
};

/// Digest of a whole byte range.
Digest digest_bytes(std::string_view bytes);

std::string to_hex(std::string_view bytes);

}  // namespace dccp::cooling_failure_manager

#endif  // DCCP_COOLING_FAILURE_MANAGER_DIGEST_HPP
