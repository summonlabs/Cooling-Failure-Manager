// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Foundation proof obligations: the error registry, the strict text codec, the
// canonical number parsers, SHA-256 against the FIPS 180-4 vectors and against
// an independently written implementation, the identifier grammar, the decision
// clock arithmetic and the enumeration token registry.

#include "test_framework.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <iterator>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "dccp/cooling_failure_manager/digest.hpp"
#include "dccp/cooling_failure_manager/enums.hpp"
#include "dccp/cooling_failure_manager/limits.hpp"
#include "dccp/cooling_failure_manager/result.hpp"
#include "dccp/cooling_failure_manager/strong_id.hpp"
#include "dccp/cooling_failure_manager/text.hpp"
#include "dccp/cooling_failure_manager/version.hpp"

namespace {

using namespace dccp::cooling_failure_manager;

constexpr char kQuote = '"';
constexpr char kBackslash = '\\';

/// Builds a byte string from explicit byte values, so pathological inputs are
/// written as data instead of as escape sequences that are easy to misread.
std::string bytes(std::initializer_list<unsigned> values) {
  std::string out;
  out.reserve(values.size());
  for (const unsigned value : values) {
    out.push_back(static_cast<char>(value & 0xFFu));
  }
  return out;
}

std::string quoted(std::string_view body) {
  std::string out;
  out.reserve(body.size() + 2);
  out.push_back(kQuote);
  out.append(body);
  out.push_back(kQuote);
  return out;
}

std::string backslash(char marker) { return std::string(1, kBackslash) + marker; }

std::string hex_of(const std::array<std::uint8_t, 32>& value) {
  static const char kDigits[] = "0123456789abcdef";
  std::string out;
  out.reserve(64);
  for (const std::uint8_t byte : value) {
    out.push_back(kDigits[(byte >> 4) & 0x0Fu]);
    out.push_back(kDigits[byte & 0x0Fu]);
  }
  return out;
}

// ---------------------------------------------------------------------------
// A second, independently written SHA-256 used only by the tests.
//
// It differs from the library on purpose: it builds the whole padded message in
// one buffer instead of streaming through a 64-byte window, it renders the
// digest in a separate pass and it keeps the working variables in an array.
// The independent padding path is what makes the boundary lengths below a real
// cross-check rather than a restatement of the library.
// ---------------------------------------------------------------------------

std::uint32_t rotate_right(std::uint32_t value, unsigned count) {
  return (value >> count) | (value << (32u - count));
}

std::array<std::uint8_t, 32> reference_sha256(std::string_view message) {
  static constexpr std::uint32_t kRoundConstants[64] = {
      0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
      0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
      0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
      0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
      0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
      0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
      0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
      0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};
  static constexpr std::uint32_t kInitialState[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                                                     0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};

  std::vector<std::uint8_t> data(message.begin(), message.end());
  const std::uint64_t bit_length = static_cast<std::uint64_t>(message.size()) * 8u;
  data.push_back(0x80u);
  while (data.size() % 64u != 56u) {
    data.push_back(0x00u);
  }
  for (int shift = 56; shift >= 0; shift -= 8) {
    data.push_back(static_cast<std::uint8_t>((bit_length >> static_cast<unsigned>(shift)) & 0xFFu));
  }

  std::uint32_t state[8];
  for (std::size_t index = 0; index < 8; ++index) {
    state[index] = kInitialState[index];
  }

  for (std::size_t offset = 0; offset < data.size(); offset += 64u) {
    std::uint32_t schedule[64];
    for (std::size_t index = 0; index < 16; ++index) {
      schedule[index] = (static_cast<std::uint32_t>(data[offset + index * 4]) << 24) |
                        (static_cast<std::uint32_t>(data[offset + index * 4 + 1]) << 16) |
                        (static_cast<std::uint32_t>(data[offset + index * 4 + 2]) << 8) |
                        (static_cast<std::uint32_t>(data[offset + index * 4 + 3]));
    }
    for (std::size_t index = 16; index < 64; ++index) {
      const std::uint32_t s0 = rotate_right(schedule[index - 15], 7) ^
                               rotate_right(schedule[index - 15], 18) ^ (schedule[index - 15] >> 3);
      const std::uint32_t s1 = rotate_right(schedule[index - 2], 17) ^
                               rotate_right(schedule[index - 2], 19) ^ (schedule[index - 2] >> 10);
      schedule[index] = schedule[index - 16] + s0 + schedule[index - 7] + s1;
    }
    std::uint32_t working[8];
    for (std::size_t index = 0; index < 8; ++index) {
      working[index] = state[index];
    }
    for (std::size_t index = 0; index < 64; ++index) {
      const std::uint32_t choose = (working[4] & working[5]) ^ ((~working[4]) & working[6]);
      const std::uint32_t majority = (working[0] & working[1]) ^ (working[0] & working[2]) ^
                                     (working[1] & working[2]);
      const std::uint32_t sigma0 = rotate_right(working[0], 2) ^ rotate_right(working[0], 13) ^
                                   rotate_right(working[0], 22);
      const std::uint32_t sigma1 = rotate_right(working[4], 6) ^ rotate_right(working[4], 11) ^
                                   rotate_right(working[4], 25);
      const std::uint32_t temp1 = working[7] + sigma1 + choose + kRoundConstants[index] + schedule[index];
      const std::uint32_t temp2 = sigma0 + majority;
      working[7] = working[6];
      working[6] = working[5];
      working[5] = working[4];
      working[4] = working[3] + temp1;
      working[3] = working[2];
      working[2] = working[1];
      working[1] = working[0];
      working[0] = temp1 + temp2;
    }
    for (std::size_t index = 0; index < 8; ++index) {
      state[index] += working[index];
    }
  }

  std::array<std::uint8_t, 32> digest{};
  for (std::size_t word = 0; word < 8; ++word) {
    digest[word * 4] = static_cast<std::uint8_t>((state[word] >> 24) & 0xFFu);
    digest[word * 4 + 1] = static_cast<std::uint8_t>((state[word] >> 16) & 0xFFu);
    digest[word * 4 + 2] = static_cast<std::uint8_t>((state[word] >> 8) & 0xFFu);
    digest[word * 4 + 3] = static_cast<std::uint8_t>(state[word] & 0xFFu);
  }
  return digest;
}

/// A deterministic message body: byte i is (i * 37 + 11) mod 256.
std::string pattern_bytes(std::size_t length) {
  std::string out;
  out.reserve(length);
  for (std::size_t index = 0; index < length; ++index) {
    out.push_back(static_cast<char>(static_cast<unsigned char>((index * 37u + 11u) & 0xFFu)));
  }
  return out;
}

// ---------------------------------------------------------------------------
// SHA-256 and Digest
// ---------------------------------------------------------------------------

CT_TEST(test_sha256_standard_vectors) {
  CT_CHECK_EQ(digest_bytes("").to_hex(),
              std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
  CT_CHECK_EQ(digest_bytes("abc").to_hex(),
              std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));

  const std::string two_block("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
  CT_CHECK_EQ(two_block.size(), std::size_t{56});
  CT_CHECK_EQ(digest_bytes(two_block).to_hex(),
              std::string("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));

  // The same three messages through the independent implementation, so a
  // vector failure cannot be explained away by a shared helper.
  CT_CHECK_EQ(hex_of(reference_sha256("")),
              std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
  CT_CHECK_EQ(hex_of(reference_sha256("abc")),
              std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
  CT_CHECK_EQ(hex_of(reference_sha256(two_block)),
              std::string("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
}

CT_TEST(test_sha256_million_a) {
  const std::string message(1000000, 'a');
  const std::string expected("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
  CT_CHECK_EQ(digest_bytes(message).to_hex(), expected);
  CT_CHECK_EQ(hex_of(reference_sha256(message)), expected);

  Sha256 hasher;
  constexpr std::size_t kChunk = 4096;
  std::size_t offset = 0;
  while (offset < message.size()) {
    const std::size_t take = (message.size() - offset) < kChunk ? (message.size() - offset) : kChunk;
    hasher.update(std::string_view(message).substr(offset, take));
    offset += take;
  }
  CT_CHECK_EQ(Digest(hasher.finish()).to_hex(), expected);
}

CT_TEST(test_sha256_padding_boundaries) {
  // Lengths around both padding boundaries: 55/56 is the one-block boundary,
  // 119/120 the two-block one and 63/64/65 a block that is exactly full.
  const std::size_t lengths[] = {0,   1,   54,  55,  56,  57,  62,  63,  64,  65,  118, 119,
                                 120, 121, 127, 128, 129, 191, 192, 193, 247, 255, 256, 1000};
  for (const std::size_t length : lengths) {
    const std::string message = pattern_bytes(length);
    CT_CHECK_EQ(digest_bytes(message).to_hex(), hex_of(reference_sha256(message)));
  }
}

CT_TEST(test_sha256_incremental_matches_oneshot) {
  const std::size_t chunk_sizes[] = {1, 2, 3, 7, 13, 31, 63, 64, 65, 127, 128};
  const std::size_t lengths[] = {0, 1, 55, 56, 63, 64, 65, 130, 257};
  for (const std::size_t chunk : chunk_sizes) {
    for (const std::size_t length : lengths) {
      const std::string message = pattern_bytes(length);
      Sha256 hasher;
      std::size_t offset = 0;
      while (offset < message.size()) {
        const std::size_t take = (message.size() - offset) < chunk ? (message.size() - offset) : chunk;
        hasher.update(std::string_view(message).substr(offset, take));
        offset += take;
      }
      CT_CHECK_EQ(Digest(hasher.finish()).to_hex(), digest_bytes(message).to_hex());
    }
  }
}

CT_TEST(test_sha256_random_boundary_cross_check) {
  const std::uint64_t seed = ct_test::case_seed("test_sha256_random_boundary_cross_check");
  ct_test::report_note("seed=" + std::to_string(seed));
  ct_test::Rng rng(seed);
  for (int iteration = 0; iteration < 96; ++iteration) {
    const std::size_t length = static_cast<std::size_t>(rng.below(300));
    std::string message;
    message.reserve(length);
    for (std::size_t index = 0; index < length; ++index) {
      message.push_back(static_cast<char>(static_cast<unsigned char>(rng.below(256))));
    }
    CT_CHECK_MSG(digest_bytes(message).to_hex() == hex_of(reference_sha256(message)),
                 "iteration " + std::to_string(iteration) + " length " + std::to_string(length) +
                     " seed " + std::to_string(seed));
  }
}

CT_TEST(test_sha256_update_integer_endianness) {
  // update_u32/update_u64 are big-endian, which is the FIPS byte order: hashing
  // the integer must equal hashing its four or eight big-endian bytes.
  Sha256 word_hasher;
  word_hasher.update_u32(0x01020304u);
  CT_CHECK_EQ(Digest(word_hasher.finish()), digest_bytes(bytes({0x01, 0x02, 0x03, 0x04})));

  Sha256 long_hasher;
  long_hasher.update_u64(0x0102030405060708ull);
  CT_CHECK_EQ(Digest(long_hasher.finish()),
              digest_bytes(bytes({0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})));

  Sha256 byte_hasher;
  byte_hasher.update_byte(0xABu);
  CT_CHECK_EQ(Digest(byte_hasher.finish()), digest_bytes(bytes({0xAB})));
}

CT_TEST(test_sha256_seal_and_reset) {
  Sha256 hasher;
  hasher.update("abc");
  const std::array<std::uint8_t, 32> first = hasher.finish();
  // finish() is idempotent: sealing twice must not change the digest.
  CT_CHECK_EQ(hasher.finish(), first);
  CT_CHECK_EQ(Digest(first).to_hex(),
              std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));

  hasher.reset();
  hasher.update("abc");
  CT_CHECK_EQ(hasher.finish(), first);

  hasher.reset();
  hasher.update("ab");
  hasher.update("c");
  CT_CHECK_EQ(hasher.finish(), first);

  // An empty update never dereferences the pointer, so a null buffer with a
  // zero size is well defined and hashes the empty message.
  Sha256 empty_hasher;
  empty_hasher.update(nullptr, 0);
  CT_CHECK_EQ(Digest(empty_hasher.finish()).to_hex(),
              std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
}

CT_TEST(test_digest_hex_codec) {
  const Digest zero;
  CT_CHECK(zero.is_zero());
  CT_CHECK_EQ(zero.to_hex(),
              std::string("0000000000000000000000000000000000000000000000000000000000000000"));

  const Digest hashed = digest_bytes("abc");
  CT_CHECK(!hashed.is_zero());
  const std::string hex = hashed.to_hex();
  CT_CHECK_EQ(hex.size(), std::size_t{64});
  const auto parsed = Digest::parse_hex(hex);
  CT_REQUIRE(parsed.has_value());
  CT_CHECK_EQ(parsed.value(), hashed);
  CT_CHECK_EQ(parsed.value().to_hex(), hex);

  std::string all_bytes;
  for (unsigned value = 0; value < 256; ++value) {
    all_bytes.push_back(static_cast<char>(value));
  }
  CT_CHECK_EQ(to_hex(all_bytes).size(), all_bytes.size() * 2u);
  CT_CHECK_EQ(to_hex("").size(), std::size_t{0});
  CT_CHECK_EQ(to_hex(bytes({0x00, 0x0F, 0xF0, 0xFF})), std::string("000ff0ff"));
}

CT_TEST(test_digest_parse_hex_rejections) {
  const std::string valid("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
  CT_REQUIRE(Digest::parse_hex(valid).has_value());

  const std::string uppercase("0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef");
  const std::string too_short = valid.substr(0, 63);
  const std::string too_long = valid + "0";
  const std::string non_hex("0123456789abcdeg0123456789abcdef0123456789abcdef0123456789abcdef");
  const std::string spaced(" 123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
  const std::string empty;

  const std::string rejected[] = {uppercase, too_short, too_long, non_hex, spaced, empty};
  for (const std::string& text : rejected) {
    const auto result = Digest::parse_hex(text);
    CT_CHECK_MSG(!result.has_value(), "digest must reject: " + text);
    CT_CHECK_EQ(static_cast<int>(result.error().code()), static_cast<int>(ErrorCode::MalformedRecord));
  }
  const auto short_result = Digest::parse_hex(too_short);
  CT_REQUIRE(!short_result.has_value());
  CT_CHECK_MSG(!short_result.error().subject().empty(), "the rejected digest is named in the subject");
}

CT_TEST(test_digest_parse_hex_accepts_leading_zeros) {
  const auto parsed = Digest::parse_hex(std::string(64, '0'));
  CT_REQUIRE(parsed.has_value());
  CT_CHECK(parsed.value().is_zero());
}

// ---------------------------------------------------------------------------
// UTF-8, display text and external identity
// ---------------------------------------------------------------------------

CT_TEST(test_utf8_acceptance) {
  const std::string accepted[] = {
      std::string(),
      std::string("ASCII only"),
      bytes({0xC2, 0xA9}),                          // U+00A9
      bytes({0xC2, 0x80}),                          // U+0080, lowest two-byte value
      bytes({0xDF, 0xBF}),                          // U+07FF, highest two-byte value
      bytes({0xE0, 0xA0, 0x80}),                    // U+0800, lowest three-byte value
      bytes({0xED, 0x9F, 0xBF}),                    // U+D7FF, last before the surrogates
      bytes({0xEE, 0x80, 0x80}),                    // U+E000, first after the surrogates
      bytes({0xE2, 0x82, 0xAC}),                    // U+20AC
      bytes({0xEF, 0xBF, 0xBF}),                    // U+FFFF
      bytes({0xF0, 0x90, 0x80, 0x80}),              // U+10000, lowest four-byte value
      bytes({0xF4, 0x8F, 0xBF, 0xBF}),              // U+10FFFF, highest code point
      bytes({0xF0, 0x9F, 0x98, 0x80}),              // U+1F600
  };
  for (const std::string& text : accepted) {
    CT_CHECK_MSG(is_valid_utf8(text), "must accept valid UTF-8: " + to_hex(text));
  }
}

CT_TEST(test_utf8_rejections) {
  const std::string rejected[] = {
      bytes({0x80}),                                // lone continuation byte
      bytes({0xBF}),                                // lone continuation byte
      bytes({0x61, 0x80}),                          // continuation after ASCII
      bytes({0xC0, 0x80}),                          // overlong NUL
      bytes({0xC1, 0xBF}),                          // overlong
      bytes({0xC2}),                                // truncated two-byte sequence
      bytes({0xC2, 0x20}),                          // missing continuation byte
      bytes({0xE0, 0x80, 0x80}),                    // overlong
      bytes({0xE0, 0x9F, 0xBF}),                    // overlong, second byte below A0
      bytes({0xE2, 0x82}),                          // truncated three-byte sequence
      bytes({0xE2, 0x28, 0xA1}),                    // missing continuation byte
      bytes({0xED, 0xA0, 0x80}),                    // U+D800 surrogate
      bytes({0xED, 0xBF, 0xBF}),                    // U+DFFF surrogate
      bytes({0xF0, 0x80, 0x80, 0x80}),              // overlong
      bytes({0xF0, 0x8F, 0xBF, 0xBF}),              // overlong, second byte below 90
      bytes({0xF0, 0x9F, 0x98}),                    // truncated four-byte sequence
      bytes({0xF4, 0x90, 0x80, 0x80}),              // above U+10FFFF
      bytes({0xF5, 0x80, 0x80, 0x80}),              // five-byte lead
      bytes({0xF8, 0x80, 0x80, 0x80, 0x80}),        // five-byte sequence
      bytes({0xFC, 0x80, 0x80, 0x80, 0x80, 0x80}),  // six-byte sequence
      bytes({0xFE}),                                // never valid
      bytes({0xFF}),                                // never valid
      bytes({0x00}),                                // NUL
      bytes({0x61, 0x00, 0x62}),                    // embedded NUL
      bytes({0x61, 0xC2}),                          // truncated after a valid byte
  };
  for (const std::string& text : rejected) {
    CT_CHECK_MSG(!is_valid_utf8(text), "must reject malformed UTF-8: " + to_hex(text));
  }
}

CT_TEST(test_display_text_rules) {
  CT_CHECK(is_valid_display_text(std::string(), 0));
  CT_CHECK(is_valid_display_text("abc", 3));
  CT_CHECK(!is_valid_display_text("abcd", 3));
  CT_CHECK(is_valid_display_text(bytes({0xC2, 0xA9}), 2));
  CT_CHECK(is_valid_display_text(bytes({0xC2, 0xA0}), 2));   // U+00A0 is not a C1 control
  CT_CHECK(!is_valid_display_text(bytes({0x01}), 4));        // C0 control
  CT_CHECK(!is_valid_display_text(bytes({0x1F}), 4));        // C0 control
  CT_CHECK(!is_valid_display_text(bytes({0x7F}), 4));        // DEL
  CT_CHECK(!is_valid_display_text(bytes({0xC2, 0x80}), 4));  // U+0080, C1 control
  CT_CHECK(!is_valid_display_text(bytes({0xC2, 0x85}), 4));  // U+0085, C1 control
  CT_CHECK(!is_valid_display_text(bytes({0x00}), 4));        // NUL
  CT_CHECK(!is_valid_display_text(bytes({0xFF}), 4));        // malformed encoding
  CT_CHECK(!is_valid_display_text(std::string("line") + bytes({0x0A}) + "break", 32));
  CT_CHECK(!is_valid_display_text(std::string("tab") + bytes({0x09}), 32));
}

CT_TEST(test_external_identity_rules) {
  CT_CHECK(is_valid_external_identity("a", 1));
  CT_CHECK(is_valid_external_identity("cooling-topology/zone-3", limits::kMaxExternalIdentityBytes));
  CT_CHECK(is_valid_external_identity("abc", 3));
  CT_CHECK(!is_valid_external_identity("abc", 2));
  CT_CHECK(!is_valid_external_identity(std::string(), 8));
  CT_CHECK(!is_valid_external_identity("a", 0));
  CT_CHECK(!is_valid_external_identity(bytes({0x61, 0x00}), 8));
  CT_CHECK(!is_valid_external_identity(bytes({0xFF}), 8));
  CT_CHECK(!is_valid_external_identity(bytes({0xC0, 0x80}), 8));

  // Bytes are compared exactly: no case folding and no Unicode normalization,
  // so a reference can never silently resolve to a different object.
  const std::string composed = bytes({0xC3, 0xA9});          // U+00E9
  const std::string decomposed = bytes({0x65, 0xCC, 0x81});  // e + U+0301
  CT_CHECK(is_valid_external_identity(composed, 8));
  CT_CHECK(is_valid_external_identity(decomposed, 8));
  CT_CHECK(!external_identity_equal(composed, decomposed));
  CT_CHECK(!external_identity_equal("ABC", "abc"));
  CT_CHECK(external_identity_equal("ABC", "ABC"));
  CT_CHECK(external_identity_equal(std::string_view(), std::string_view()));
  CT_CHECK(!external_identity_equal("a", "a "));
}

// ---------------------------------------------------------------------------
// The escape codec
// ---------------------------------------------------------------------------

CT_TEST(test_escape_round_trip_pathological) {
  std::string all_bytes;
  for (unsigned value = 0; value < 256; ++value) {
    all_bytes.push_back(static_cast<char>(value));
  }
  const std::string quote_text = std::string(1, kQuote) + "quoted" + kQuote;
  const std::string slash_text = backslash('n') + backslash('x') + "4a";

  const std::string cases[] = {
      std::string(),
      std::string("plain ASCII text"),
      quote_text,
      slash_text,
      bytes({0x09, 0x0A, 0x0D}),
      bytes({0x00}),
      std::string("a") + bytes({0x00}) + "b",
      bytes({0x7F}),
      bytes({0x1F, 0x20, 0x7E, 0x7F}),
      bytes({0x80, 0xBF, 0xC0, 0xF5, 0xFF}),
      all_bytes,
  };
  for (const std::string& original : cases) {
    const std::string escaped = escape_text(original);
    CT_CHECK_MSG(escaped.size() >= 2, "escaping always yields a quoted string");
    CT_CHECK_EQ(escaped.front(), kQuote);
    CT_CHECK_EQ(escaped.back(), kQuote);
    for (const char character : escaped) {
      const auto byte = static_cast<unsigned char>(character);
      CT_CHECK_MSG(byte >= 0x20 && byte <= 0x7E,
                   "escape_text output must be printable ASCII only: " + to_hex(escaped));
    }
    const auto restored = unescape_text(escaped, original.size());
    CT_CHECK_MSG(restored.has_value(), "round trip must succeed for: " + to_hex(original));
    CT_REQUIRE(restored.has_value());
    CT_CHECK_EQ(restored.value(), original);
    // Escaping the restored bytes reproduces the identical rendering, which is
    // the canonical fixed point the durable format depends on.
    CT_CHECK_EQ(escape_text(restored.value()), escaped);
  }
}

CT_TEST(test_escape_rendering_is_canonical) {
  CT_CHECK_EQ(escape_text(std::string()), quoted(std::string()));
  CT_CHECK_EQ(escape_text("a"), quoted("a"));
  CT_CHECK_EQ(escape_text(std::string(1, kQuote)), quoted(backslash(kQuote)));
  CT_CHECK_EQ(escape_text(std::string(1, kBackslash)), quoted(backslash(kBackslash)));
  CT_CHECK_EQ(escape_text(bytes({0x09})), quoted(backslash('x') + "09"));
  CT_CHECK_EQ(escape_text(bytes({0x0A})), quoted(backslash('x') + "0a"));
  CT_CHECK_EQ(escape_text(bytes({0x0D})), quoted(backslash('x') + "0d"));
  CT_CHECK_EQ(escape_text(bytes({0x00})), quoted(backslash('x') + "00"));
  CT_CHECK_EQ(escape_text(bytes({0x7F})), quoted(backslash('x') + "7f"));
  CT_CHECK_EQ(escape_text(bytes({0xFF})), quoted(backslash('x') + "ff"));
  CT_CHECK_EQ(escape_text(bytes({0x1F})), quoted(backslash('x') + "1f"));
  CT_CHECK_EQ(escape_text(bytes({0x20})), quoted(" "));
  CT_CHECK_EQ(escape_text(bytes({0x7E})), quoted("~"));
  // A backslash is escaped as a doubled backslash, so a backslash followed by
  // a letter survives as data and is never read back as an escape.
  CT_CHECK_EQ(escape_text(backslash('n')), quoted(backslash(kBackslash) + "n"));
}

CT_TEST(test_unescape_bound_is_exact) {
  const std::string exact("abc");
  const std::string escaped = escape_text(exact);
  const auto accepted = unescape_text(escaped, 3);
  CT_REQUIRE(accepted.has_value());
  CT_CHECK_EQ(accepted.value(), exact);

  const auto rejected = unescape_text(escaped, 2);
  CT_REQUIRE(!rejected.has_value());
  CT_CHECK_EQ(static_cast<int>(rejected.error().code()), static_cast<int>(ErrorCode::TextTooLong));

  const auto empty = unescape_text(escape_text(std::string()), 0);
  CT_REQUIRE(empty.has_value());
  CT_CHECK_EQ(empty.value(), std::string());
}

namespace {

/// Shared by the strict-rejection table: the codec must fail with exactly the
/// documented code and never return a value.
void check_unescape_rejected(std::string_view escaped, std::size_t max_bytes, ErrorCode expected,
                             const char* why) {
  const auto result = unescape_text(escaped, max_bytes);
  CT_CHECK_MSG(!result.has_value(), std::string("unescape must reject ") + why);
  if (!result.has_value()) {
    CT_CHECK_EQ(static_cast<int>(result.error().code()), static_cast<int>(expected));
  }
}

}  // namespace

CT_TEST(test_unescape_strict_rejections) {
  constexpr std::size_t kBound = 64;
  check_unescape_rejected(std::string(), kBound, ErrorCode::TruncatedInput, "an empty input");
  check_unescape_rejected("abc", kBound, ErrorCode::MalformedRecord, "text without a leading quote");
  check_unescape_rejected(quoted("abc").substr(0, 4), kBound, ErrorCode::TruncatedInput,
                          "an unterminated string");
  check_unescape_rejected(std::string(1, kQuote), kBound, ErrorCode::TruncatedInput, "a lone quote");
  check_unescape_rejected(quoted(backslash('q')), kBound, ErrorCode::MalformedRecord, "an unknown escape");
  check_unescape_rejected(quoted(backslash('n')), kBound, ErrorCode::MalformedRecord,
                          "a non-canonical escape");
  check_unescape_rejected(quoted(backslash('t')), kBound, ErrorCode::MalformedRecord,
                          "a non-canonical escape");
  check_unescape_rejected(quoted(backslash('x')), kBound, ErrorCode::TruncatedInput,
                          "a truncated hex escape");
  check_unescape_rejected(quoted(backslash('x') + "4"), kBound, ErrorCode::TruncatedInput,
                          "a truncated hex escape");
  check_unescape_rejected(quoted(backslash('x') + "4g"), kBound, ErrorCode::MalformedRecord,
                          "a non-hex escape");
  check_unescape_rejected(quoted(backslash('x') + "4A"), kBound, ErrorCode::MalformedRecord,
                          "an uppercase hex escape");
  check_unescape_rejected(quoted(backslash('x') + " 4"), kBound, ErrorCode::MalformedRecord,
                          "a hex escape with a space");
  check_unescape_rejected(quoted(std::string(1, kBackslash)), kBound, ErrorCode::TruncatedInput,
                          "a trailing backslash");
  check_unescape_rejected(quoted(std::string("a") + bytes({0x09}) + "b"), kBound,
                          ErrorCode::MalformedRecord, "a raw tab");
  check_unescape_rejected(quoted(std::string("a") + bytes({0x0A}) + "b"), kBound,
                          ErrorCode::MalformedRecord, "a raw newline");
  check_unescape_rejected(quoted(bytes({0xFF})), kBound, ErrorCode::MalformedRecord, "a raw high byte");
  check_unescape_rejected(quoted(bytes({0x00})), kBound, ErrorCode::MalformedRecord, "a raw NUL");
  check_unescape_rejected(quoted("abc"), 2, ErrorCode::TextTooLong, "text above the bound");
  check_unescape_rejected(quoted(backslash('x') + "41414141"), 3, ErrorCode::TextTooLong,
                          "escaped text above the bound");

  // The accepted forms: the short escapes and the lowercase hex escape.
  const auto hexed = unescape_text(quoted(backslash('x') + "00" + backslash('x') + "ff"), kBound);
  CT_REQUIRE(hexed.has_value());
  CT_CHECK_EQ(hexed.value(), bytes({0x00, 0xFF}));
  const auto escaped_quote = unescape_text(quoted(backslash(kQuote)), kBound);
  CT_REQUIRE(escaped_quote.has_value());
  CT_CHECK_EQ(escaped_quote.value(), std::string(1, kQuote));
  const auto escaped_backslash = unescape_text(quoted(backslash(kBackslash)), kBound);
  CT_REQUIRE(escaped_backslash.has_value());
  CT_CHECK_EQ(escaped_backslash.value(), std::string(1, kBackslash));
  const auto plain = unescape_text(quoted("plain text"), kBound);
  CT_REQUIRE(plain.has_value());
  CT_CHECK_EQ(plain.value(), std::string("plain text"));
}

CT_TEST(test_random_byte_round_trip) {
  const std::uint64_t seed = ct_test::case_seed("test_random_byte_round_trip");
  ct_test::report_note("seed=" + std::to_string(seed));
  ct_test::Rng rng(seed);
  for (int iteration = 0; iteration < 200; ++iteration) {
    const std::size_t length = static_cast<std::size_t>(rng.below(300));
    std::string raw;
    raw.reserve(length);
    for (std::size_t index = 0; index < length; ++index) {
      raw.push_back(static_cast<char>(static_cast<unsigned char>(rng.below(256))));
    }
    const std::string escaped = escape_text(raw);
    const auto restored = unescape_text(escaped, raw.size());
    CT_CHECK_MSG(restored.has_value(), "iteration " + std::to_string(iteration) + " seed " +
                                           std::to_string(seed) + " input " + to_hex(raw));
    CT_REQUIRE(restored.has_value());
    CT_CHECK_EQ(restored.value(), raw);
    CT_CHECK_EQ(escape_text(restored.value()), escaped);
    const auto refused = unescape_text(escaped, raw.size() - (raw.empty() ? 0u : 1u));
    if (!raw.empty()) {
      CT_CHECK(!refused.has_value());
      CT_CHECK_EQ(static_cast<int>(refused.error().code()), static_cast<int>(ErrorCode::TextTooLong));
    }
  }
}

CT_TEST(test_ascii_helpers) {
  CT_CHECK_EQ(ascii_lower("AbC123"), std::string("abc123"));
  CT_CHECK_EQ(ascii_lower(std::string()), std::string());
  CT_CHECK_EQ(ascii_lower("already-lower"), std::string("already-lower"));
  CT_CHECK_EQ(ascii_lower(bytes({0xC3, 0x89})), bytes({0xC3, 0x89}));

  CT_CHECK(is_ascii_token("flow-meter"));
  CT_CHECK(is_ascii_token("A.b_c:d-e"));
  CT_CHECK(is_ascii_token("0"));
  CT_CHECK(!is_ascii_token(std::string()));
  CT_CHECK(!is_ascii_token("has space"));
  CT_CHECK(!is_ascii_token("has/slash"));
  CT_CHECK(!is_ascii_token("plus+"));
  CT_CHECK(!is_ascii_token(std::string("nul") + bytes({0x00})));
  CT_CHECK(!is_ascii_token(std::string("tab") + bytes({0x09})));
}

// ---------------------------------------------------------------------------
// Canonical numbers
// ---------------------------------------------------------------------------

namespace {

/// The outcome code of a Result, so a table can assert the exact code.
template <class T>
ErrorCode error_code_of(const Result<T>& result) {
  return result.has_value() ? ErrorCode::Ok : result.error().code();
}

}  // namespace

CT_TEST(test_parse_uint64_acceptance) {
  constexpr std::uint64_t kMax = UINT64_MAX;
  struct Case {
    std::string_view text;
    std::uint64_t expected;
  };
  const Case cases[] = {
      {"0", 0u},
      {"1", 1u},
      {"9", 9u},
      {"10", 10u},
      {"99", 99u},
      {"1000000000000000000", 1000000000000000000ull},
      {"18446744073709551614", 18446744073709551614ull},
      {"18446744073709551615", 18446744073709551615ull},
  };
  for (const Case& item : cases) {
    const auto result = parse_uint64(item.text, kMax);
    CT_CHECK_MSG(result.has_value(), "must parse: " + std::string(item.text));
    CT_REQUIRE(result.has_value());
    CT_CHECK_EQ(result.value(), item.expected);
  }
  // The caller's bound is inclusive and exact.
  const auto at_bound = parse_uint64("7", 7);
  CT_REQUIRE(at_bound.has_value());
  CT_CHECK_EQ(at_bound.value(), std::uint64_t{7});
}

CT_TEST(test_parse_uint64_rejections) {
  constexpr std::uint64_t kMax = UINT64_MAX;
  struct Case {
    std::string_view text;
    ErrorCode expected;
  };
  const Case cases[] = {
      {"", ErrorCode::MalformedNumber},
      {"+1", ErrorCode::MalformedNumber},
      {"-1", ErrorCode::MalformedNumber},
      {"-0", ErrorCode::MalformedNumber},
      {"00", ErrorCode::MalformedNumber},
      {"01", ErrorCode::MalformedNumber},
      {" 1", ErrorCode::MalformedNumber},
      {"1 ", ErrorCode::MalformedNumber},
      {"0x10", ErrorCode::MalformedNumber},
      {"1_000", ErrorCode::MalformedNumber},
      {"1,000", ErrorCode::MalformedNumber},
      {"1.0", ErrorCode::MalformedNumber},
      {"abc", ErrorCode::MalformedNumber},
      {"99999999999999999999", ErrorCode::LimitExceeded},
      {"18446744073709551616", ErrorCode::LimitExceeded},
  };
  for (const Case& item : cases) {
    CT_CHECK_EQ(static_cast<int>(error_code_of(parse_uint64(item.text, kMax))),
                static_cast<int>(item.expected));
  }
  // Beyond the magnitude, and whitespace that is not an ASCII space.
  const std::string trailing_newline = std::string("1") + bytes({0x0A});
  const std::string trailing_nul = std::string("1") + bytes({0x00});
  const std::string non_ascii_digits = bytes({0xD9, 0xA1});  // Arabic-Indic one
  CT_CHECK_EQ(static_cast<int>(error_code_of(parse_uint64(trailing_newline, kMax))),
              static_cast<int>(ErrorCode::MalformedNumber));
  CT_CHECK_EQ(static_cast<int>(error_code_of(parse_uint64(trailing_nul, kMax))),
              static_cast<int>(ErrorCode::MalformedNumber));
  CT_CHECK_EQ(static_cast<int>(error_code_of(parse_uint64(non_ascii_digits, kMax))),
              static_cast<int>(ErrorCode::MalformedNumber));

  // A value above the caller's maximum is a bound violation.
  CT_CHECK_EQ(static_cast<int>(error_code_of(parse_uint64("8", 7))),
              static_cast<int>(ErrorCode::LimitExceeded));
  const auto over = parse_uint64("12345678901234567890", 1000);
  CT_REQUIRE(!over.has_value());
  CT_CHECK_EQ(static_cast<int>(over.error().code()), static_cast<int>(ErrorCode::LimitExceeded));
  CT_CHECK_EQ(over.error().subject(), std::string("12345678901234567890"));
}

CT_TEST(test_parse_int64_acceptance) {
  constexpr std::int64_t kMin = INT64_MIN;
  constexpr std::int64_t kMax = INT64_MAX;
  struct Case {
    std::string_view text;
    std::int64_t expected;
  };
  const Case cases[] = {
      {"0", 0},
      {"1", 1},
      {"-1", -1},
      {"-9", -9},
      {"10", 10},
      {"-10", -10},
      {"9223372036854775807", 9223372036854775807ll},
      {"-9223372036854775807", -9223372036854775807ll},
      {"-9223372036854775808", INT64_MIN},
  };
  for (const Case& item : cases) {
    const auto result = parse_int64(item.text, kMin, kMax);
    CT_CHECK_MSG(result.has_value(), "must parse: " + std::string(item.text));
    CT_REQUIRE(result.has_value());
    CT_CHECK_EQ(result.value(), item.expected);
  }
  // INT64_MIN is reachable only because the magnitude is checked before the
  // negation; the equality above is the proof that no unchecked negation ran.
  const auto minimum = parse_int64("-9223372036854775808", kMin, kMax);
  CT_REQUIRE(minimum.has_value());
  CT_CHECK_EQ(minimum.value(), INT64_MIN);
}

CT_TEST(test_parse_int64_rejections) {
  constexpr std::int64_t kMin = INT64_MIN;
  constexpr std::int64_t kMax = INT64_MAX;
  struct Case {
    std::string_view text;
    ErrorCode expected;
  };
  const Case cases[] = {
      {"", ErrorCode::MalformedNumber},
      {"-", ErrorCode::MalformedNumber},
      {"+1", ErrorCode::MalformedNumber},
      {"--1", ErrorCode::MalformedNumber},
      {"-+1", ErrorCode::MalformedNumber},
      {"-0", ErrorCode::MalformedNumber},
      {"00", ErrorCode::MalformedNumber},
      {"01", ErrorCode::MalformedNumber},
      {"-01", ErrorCode::MalformedNumber},
      {" 1", ErrorCode::MalformedNumber},
      {"1 ", ErrorCode::MalformedNumber},
      {"1.0", ErrorCode::MalformedNumber},
      {"-", ErrorCode::MalformedNumber},
      {"9223372036854775808", ErrorCode::LimitExceeded},
      {"-9223372036854775809", ErrorCode::LimitExceeded},
      {"18446744073709551616", ErrorCode::LimitExceeded},
  };
  for (const Case& item : cases) {
    CT_CHECK_EQ(static_cast<int>(error_code_of(parse_int64(item.text, kMin, kMax))),
                static_cast<int>(item.expected));
  }
  const std::string trailing_tab = std::string("-1") + bytes({0x09});
  CT_CHECK_EQ(static_cast<int>(error_code_of(parse_int64(trailing_tab, kMin, kMax))),
              static_cast<int>(ErrorCode::MalformedNumber));
}

CT_TEST(test_parse_int64_range_bounds) {
  // The caller's range is inclusive at both ends and is checked after the
  // magnitude bound, so a representable value outside the range is a bound
  // violation rather than a shape violation.
  const auto minimum = parse_int64("-4", -4, 0);
  CT_REQUIRE(minimum.has_value());
  CT_CHECK_EQ(minimum.value(), std::int64_t{-4});
  const auto maximum = parse_int64("4", 0, 4);
  CT_REQUIRE(maximum.has_value());
  CT_CHECK_EQ(maximum.value(), std::int64_t{4});
  CT_CHECK_EQ(static_cast<int>(error_code_of(parse_int64("5", 0, 4))),
              static_cast<int>(ErrorCode::LimitExceeded));
  CT_CHECK_EQ(static_cast<int>(error_code_of(parse_int64("-5", -4, 0))),
              static_cast<int>(ErrorCode::LimitExceeded));
  CT_CHECK_EQ(static_cast<int>(error_code_of(parse_int64("-1", 0, 4))),
              static_cast<int>(ErrorCode::LimitExceeded));
}

CT_TEST(test_to_decimal_and_canonical_forms) {
  CT_CHECK_EQ(to_decimal(std::uint64_t{0}), std::string("0"));
  CT_CHECK_EQ(to_decimal(std::uint64_t{1}), std::string("1"));
  CT_CHECK_EQ(to_decimal(std::uint64_t{10}), std::string("10"));
  CT_CHECK_EQ(to_decimal(UINT64_MAX), std::string("18446744073709551615"));
  CT_CHECK_EQ(to_decimal(std::int64_t{0}), std::string("0"));
  CT_CHECK_EQ(to_decimal(std::int64_t{-1}), std::string("-1"));
  CT_CHECK_EQ(to_decimal(INT64_MAX), std::string("9223372036854775807"));
  CT_CHECK_EQ(to_decimal(INT64_MIN), std::string("-9223372036854775808"));

  // Every rendering round-trips through the parser.
  const std::uint64_t unsigned_values[] = {0u, 1u, 9u, 10u, 999999999999999999ull, UINT64_MAX};
  for (const std::uint64_t value : unsigned_values) {
    const std::string text = to_decimal(value);
    CT_CHECK(is_canonical_uint(text));
    const auto parsed = parse_uint64(text, UINT64_MAX);
    CT_REQUIRE(parsed.has_value());
    CT_CHECK_EQ(parsed.value(), value);
  }
  const std::int64_t signed_values[] = {0,  1,  -1,  9,   -9,  10,  -10,
                                        INT64_MAX, INT64_MIN, INT64_MAX - 1, INT64_MIN + 1};
  for (const std::int64_t value : signed_values) {
    const std::string text = to_decimal(value);
    CT_CHECK(is_canonical_int(text));
    const auto parsed = parse_int64(text, INT64_MIN, INT64_MAX);
    CT_REQUIRE(parsed.has_value());
    CT_CHECK_EQ(parsed.value(), value);
  }

  const char* const canonical_uint[] = {"0", "1", "10", "18446744073709551615"};
  for (const char* text : canonical_uint) {
    CT_CHECK_MSG(is_canonical_uint(text), std::string("must be canonical: ") + text);
  }
  const char* const non_canonical_uint[] = {"",     "00",   "01",   "+1",  "-1",   " 1",
                                            "1 ",   "1a",   "0x1",  "1.0", "1_0",  "18446744073709551616"};
  for (const char* text : non_canonical_uint) {
    CT_CHECK_MSG(!is_canonical_uint(text), std::string("must not be canonical: ") + text);
  }

  const char* const canonical_int[] = {"0", "1", "-1", "9223372036854775807",
                                       "-9223372036854775808"};
  for (const char* text : canonical_int) {
    CT_CHECK_MSG(is_canonical_int(text), std::string("must be canonical: ") + text);
  }
  const char* const non_canonical_int[] = {"",    "-0",   "+1",  "--1", "01",   "-01",  " 1",
                                           "1 ",  "1a",   "9223372036854775808",
                                           "-9223372036854775809"};
  for (const char* text : non_canonical_int) {
    CT_CHECK_MSG(!is_canonical_int(text), std::string("must not be canonical: ") + text);
  }
}

// ---------------------------------------------------------------------------
// Record splitting
// ---------------------------------------------------------------------------

CT_TEST(test_split_fields_acceptance) {
  const std::string tab = bytes({0x09});
  const std::string line = std::string("head") + tab + "middle" + tab + "tail";
  const auto fields = split_fields(line, tab.front());
  CT_REQUIRE(fields.has_value());
  CT_CHECK_EQ(fields.value().size(), std::size_t{3});
  CT_REQUIRE(fields.value().size() == 3);
  CT_CHECK_EQ(fields.value()[0], std::string_view("head"));
  CT_CHECK_EQ(fields.value()[1], std::string_view("middle"));
  CT_CHECK_EQ(fields.value()[2], std::string_view("tail"));
  // The fields are views into the input, not copies.
  CT_CHECK_EQ(fields.value()[0].data(), line.data());
  CT_CHECK_EQ(fields.value()[2].data(), line.data() + 12);

  const auto single = split_fields("only", tab.front());
  CT_REQUIRE(single.has_value());
  CT_CHECK_EQ(single.value().size(), std::size_t{1});
  CT_CHECK_EQ(single.value()[0], std::string_view("only"));

  const auto spaces = split_fields("a b c", ' ');
  CT_REQUIRE(spaces.has_value());
  CT_CHECK_EQ(spaces.value().size(), std::size_t{3});

  const auto whole = split_fields("a b", tab.front());
  CT_REQUIRE(whole.has_value());
  CT_CHECK_EQ(whole.value().size(), std::size_t{1});

  // A single-byte separator splits the same way as any other byte.
  const auto split_on_letter = split_fields("bab", 'a');
  CT_REQUIRE(split_on_letter.has_value());
  CT_CHECK_EQ(split_on_letter.value().size(), std::size_t{2});
  CT_CHECK_EQ(split_on_letter.value()[0], std::string_view("b"));
  CT_CHECK_EQ(split_on_letter.value()[1], std::string_view("b"));
}

CT_TEST(test_split_fields_rejections) {
  const std::string tab = bytes({0x09});
  CT_CHECK_EQ(static_cast<int>(error_code_of(split_fields(std::string(), tab.front()))),
              static_cast<int>(ErrorCode::EmptyInput));
  CT_CHECK_EQ(static_cast<int>(error_code_of(split_fields(tab + "a", tab.front()))),
              static_cast<int>(ErrorCode::MalformedRecord));
  CT_CHECK_EQ(static_cast<int>(error_code_of(split_fields(std::string("a") + tab, tab.front()))),
              static_cast<int>(ErrorCode::MalformedRecord));
  CT_CHECK_EQ(static_cast<int>(error_code_of(split_fields(std::string("a") + tab + tab + "b", tab.front()))),
              static_cast<int>(ErrorCode::MalformedRecord));
  CT_CHECK_EQ(static_cast<int>(error_code_of(split_fields(tab, tab.front()))),
              static_cast<int>(ErrorCode::MalformedRecord));
  CT_CHECK_EQ(
      static_cast<int>(error_code_of(split_fields(std::string("a") + bytes({0x00}) + "b", tab.front()))),
      static_cast<int>(ErrorCode::MalformedRecord));
  // A NUL separator could never occur in validated record text, so asking for
  // one is a caller defect rather than a malformed record.
  CT_CHECK_EQ(static_cast<int>(error_code_of(split_fields("a", static_cast<char>(0)))),
              static_cast<int>(ErrorCode::InvalidArgument));

  const auto trailing = split_fields(std::string("a") + tab, tab.front());
  CT_REQUIRE(!trailing.has_value());
  CT_CHECK(!trailing.error().subject().empty());
}

// ---------------------------------------------------------------------------
// Identifier grammar and the synthetic clock
// ---------------------------------------------------------------------------

CT_TEST(test_identifier_grammar_acceptance) {
  const std::string maximum_length(limits::kMaxIdentifierBytes, 'a');
  const std::string maximum_mixed = std::string("a") + std::string(126, '.') + "9";
  CT_CHECK_EQ(maximum_length.size(), limits::kMaxIdentifierBytes);
  CT_CHECK_EQ(maximum_mixed.size(), limits::kMaxIdentifierBytes);

  const std::string accepted[] = {"a",   "0",   "Z",   "a.b",     "a_b",  "a:b",     "a-b",
                                  "A1",  "x9.y-8:z_7", maximum_length, maximum_mixed};
  for (const std::string& text : accepted) {
    CT_CHECK_MSG(is_valid_identifier_syntax(text), "must accept identifier: " + text);
  }
  CT_CHECK(!identifier_syntax_help().empty());
  CT_CHECK(identifier_syntax_help().find("128") != std::string_view::npos);
}

CT_TEST(test_identifier_grammar_rejections) {
  const std::string too_long(limits::kMaxIdentifierBytes + 1, 'a');
  const std::string non_ascii = bytes({0xC3, 0xA9});
  const std::string with_backslash = std::string("a") + std::string(1, kBackslash) + "b";
  const std::string with_nul = std::string("a") + bytes({0x00}) + "b";
  const std::string with_tab = std::string("a") + bytes({0x09}) + "b";
  const std::string rejected[] = {
      std::string(), "-a",        "a-",  ".a",  "a.",  "_a",  "a_",   ":a",  "a:",  "a b",
      " a",          "a ",        "a/b", "a+b", "a@b", "a#b", "a?b",  "a*b", "a|b", "a=b",
      "a,b",         "a;b",       "a!b", "a(b)", "a)b", too_long, non_ascii, with_backslash,
      with_nul,      with_tab};
  for (const std::string& text : rejected) {
    CT_CHECK_MSG(!is_valid_identifier_syntax(text), "must reject identifier: " + to_hex(text));
  }
}

CT_TEST(test_strong_id_parse_and_order) {
  const auto scope = ScopeId::parse("plant-1.loop-2");
  CT_REQUIRE(scope.has_value());
  CT_REQUIRE(scope.has_value());
  const auto scope_text = scope.value().value();
  CT_CHECK_EQ(scope_text, std::string_view("plant-1.loop-2"));
  CT_CHECK_EQ(scope.value().str(), std::string("plant-1.loop-2"));
  CT_CHECK(!scope.value().empty());
  CT_CHECK(ScopeId().empty());

  const auto empty = ScopeId::parse(std::string());
  CT_REQUIRE(!empty.has_value());
  CT_CHECK_EQ(static_cast<int>(empty.error().code()), static_cast<int>(ErrorCode::MalformedIdentifier));

  // A rejected identifier names the offending text in the subject.
  const auto dash_leading = ScopeId::parse("-leading-dash");
  CT_REQUIRE(!dash_leading.has_value());
  CT_CHECK_EQ(static_cast<int>(dash_leading.error().code()),
              static_cast<int>(ErrorCode::MalformedIdentifier));
  CT_CHECK_EQ(dash_leading.error().subject(), std::string("-leading-dash"));

  const std::string invalid(limits::kMaxIdentifierBytes + 1, 'x');
  const auto too_long = FailureId::parse(invalid);
  CT_REQUIRE(!too_long.has_value());
  CT_CHECK_EQ(static_cast<int>(too_long.error().code()), static_cast<int>(ErrorCode::MalformedIdentifier));

  const auto first = ScopeId::parse("a");
  const auto second = ScopeId::parse("b");
  CT_REQUIRE(first.has_value());
  CT_REQUIRE(second.has_value());
  CT_CHECK(first.value() == first.value());
  CT_CHECK(first.value() != second.value());
  CT_CHECK(first.value() < second.value());
  CT_CHECK(second.value() > first.value());
  CT_REQUIRE(first.has_value());
  const auto first_text = first.value().value();
  CT_CHECK_EQ(first_text, std::string_view("a"));
}

CT_TEST(test_decision_clock_parse) {
  const auto absent = DecisionClock::parse(-1);
  CT_REQUIRE(absent.has_value());
  CT_CHECK(!absent.value().present());
  CT_CHECK_EQ(absent.value().milliseconds(), std::int64_t{-1});

  const auto zero = DecisionClock::parse(0);
  CT_REQUIRE(zero.has_value());
  CT_CHECK(zero.value().present());

  const auto maximum = DecisionClock::parse(limits::kMaxTimestampMilliseconds);
  CT_REQUIRE(maximum.has_value());
  CT_CHECK_EQ(maximum.value().milliseconds(), limits::kMaxTimestampMilliseconds);

  const auto below = DecisionClock::parse(-2);
  CT_REQUIRE(!below.has_value());
  CT_CHECK_EQ(static_cast<int>(below.error().code()), static_cast<int>(ErrorCode::TimestampOutOfRange));
  const auto above = DecisionClock::parse(limits::kMaxTimestampMilliseconds + 1);
  CT_REQUIRE(!above.has_value());
  CT_CHECK_EQ(static_cast<int>(above.error().code()), static_cast<int>(ErrorCode::TimestampOutOfRange));
  const auto minimum = DecisionClock::parse(INT64_MIN);
  CT_REQUIRE(!minimum.has_value());
  CT_CHECK_EQ(static_cast<int>(minimum.error().code()), static_cast<int>(ErrorCode::TimestampOutOfRange));
  const auto maximum64 = DecisionClock::parse(INT64_MAX);
  CT_REQUIRE(!maximum64.has_value());
  CT_CHECK_EQ(static_cast<int>(maximum64.error().code()),
              static_cast<int>(ErrorCode::TimestampOutOfRange));
}

CT_TEST(test_decision_clock_since) {
  const auto now = DecisionClock::parse(1000);
  const auto earlier = DecisionClock::parse(400);
  CT_REQUIRE(now.has_value());
  CT_REQUIRE(earlier.has_value());

  const auto elapsed = now.value().since(earlier.value());
  CT_REQUIRE(elapsed.has_value());
  CT_CHECK_EQ(elapsed.value(), std::int64_t{600});

  const auto same = now.value().since(now.value());
  CT_REQUIRE(same.has_value());
  CT_CHECK_EQ(same.value(), std::int64_t{0});

  // A reference clock in the future is reported, never clamped to zero.
  const auto negative = earlier.value().since(now.value());
  CT_REQUIRE(!negative.has_value());
  CT_CHECK_EQ(static_cast<int>(negative.error().code()),
              static_cast<int>(ErrorCode::TimestampOutOfRange));

  const auto absent = DecisionClock::parse(-1);
  CT_REQUIRE(absent.has_value());
  const auto absent_elapsed = absent.value().since(absent.value());
  CT_REQUIRE(absent_elapsed.has_value());
  CT_CHECK_EQ(absent_elapsed.value(), std::int64_t{0});

  // Subtraction overflow is a bound violation, not an enormous interval.
  const auto positive_overflow = DecisionClock(INT64_MAX).since(DecisionClock(-1));
  CT_REQUIRE(!positive_overflow.has_value());
  CT_CHECK_EQ(static_cast<int>(positive_overflow.error().code()),
              static_cast<int>(ErrorCode::LimitExceeded));
  const auto negative_overflow = DecisionClock(INT64_MIN).since(DecisionClock(1));
  CT_REQUIRE(!negative_overflow.has_value());
  CT_CHECK_EQ(static_cast<int>(negative_overflow.error().code()),
              static_cast<int>(ErrorCode::LimitExceeded));
  const auto largest = DecisionClock(INT64_MAX).since(DecisionClock(0));
  CT_REQUIRE(largest.has_value());
  CT_CHECK_EQ(largest.value(), INT64_MAX);
  const auto most_negative = DecisionClock(0).since(DecisionClock(INT64_MIN));
  CT_CHECK(!most_negative.has_value());
  CT_CHECK_EQ(static_cast<int>(most_negative.error().code()),
              static_cast<int>(ErrorCode::LimitExceeded));
}

CT_TEST(test_duration_milliseconds_parse) {
  const auto zero = DurationMilliseconds::parse(0);
  CT_REQUIRE(zero.has_value());
  CT_CHECK(zero.value().zero());
  CT_CHECK_EQ(zero.value().milliseconds(), std::int64_t{0});

  const auto maximum = DurationMilliseconds::parse(limits::kMaxWindowMilliseconds);
  CT_REQUIRE(maximum.has_value());
  CT_CHECK_EQ(maximum.value().milliseconds(), limits::kMaxWindowMilliseconds);

  const auto negative = DurationMilliseconds::parse(-1);
  CT_REQUIRE(!negative.has_value());
  CT_CHECK_EQ(static_cast<int>(negative.error().code()), static_cast<int>(ErrorCode::QuantityOutOfRange));
  const auto above = DurationMilliseconds::parse(limits::kMaxWindowMilliseconds + 1);
  CT_REQUIRE(!above.has_value());
  CT_CHECK_EQ(static_cast<int>(above.error().code()), static_cast<int>(ErrorCode::QuantityOutOfRange));
  const auto minimum = DurationMilliseconds::parse(INT64_MIN);
  CT_REQUIRE(!minimum.has_value());
  CT_CHECK_EQ(static_cast<int>(minimum.error().code()), static_cast<int>(ErrorCode::QuantityOutOfRange));
  const auto maximum64 = DurationMilliseconds::parse(INT64_MAX);
  CT_REQUIRE(!maximum64.has_value());
  CT_CHECK_EQ(static_cast<int>(maximum64.error().code()),
              static_cast<int>(ErrorCode::QuantityOutOfRange));
}

// ---------------------------------------------------------------------------
// Enumeration tokens, order tables and policy predicates
// ---------------------------------------------------------------------------

namespace {

/// Round-trips every enumerator of one enumeration and proves the strict
/// rejection of an unknown token. Called once per enumeration, so the whole
/// registry is covered rather than a sample.
template <class Enum, class ToToken, class FromToken>
void check_enum_tokens(const char* label, unsigned count, ToToken to_token_of,
                       FromToken from_token_of) {
  std::vector<std::string> seen;
  for (unsigned index = 0; index < count; ++index) {
    const Enum value = static_cast<Enum>(index);
    const std::string token(to_token_of(value));
    CT_CHECK_MSG(!token.empty(), label);
    CT_CHECK_MSG(token != "invalid", std::string(label) + ": an enumerator needs a real token");
    for (const std::string& other : seen) {
      CT_CHECK_MSG(other != token, std::string(label) + ": token " + token + " is used twice");
    }
    seen.push_back(token);
    const auto parsed = from_token_of(token);
    CT_CHECK_MSG(parsed.has_value(), std::string(label) + ": token " + token + " must round-trip");
    CT_REQUIRE(parsed.has_value());
    CT_CHECK_EQ(static_cast<int>(parsed.value()), static_cast<int>(index));
  }
  CT_CHECK_EQ(seen.size(), static_cast<std::size_t>(count));

  // An unknown token is rejected with UnknownEnumToken, and the token is named
  // in both the message and the subject. It is never mapped to a default.
  const std::string unknown = "definitely-not-a-canonical-token";
  const auto missing = from_token_of(unknown);
  CT_CHECK_MSG(!missing.has_value(), label);
  CT_CHECK_EQ(static_cast<int>(missing.error().code()), static_cast<int>(ErrorCode::UnknownEnumToken));
  CT_CHECK_EQ(missing.error().subject(), unknown);
  CT_CHECK_MSG(missing.error().message().find(unknown) != std::string::npos,
               std::string(label) + ": the rejected token is named in the message");

  // A value that is not an enumerator has no token, and the sentinel it renders
  // to is not a token of this enumeration either.
  const std::string invalid(to_token_of(static_cast<Enum>(count + 7)));
  CT_CHECK_EQ(invalid, std::string("invalid"));
  CT_CHECK(!from_token_of(invalid).has_value());
  CT_CHECK_EQ(static_cast<int>(from_token_of(invalid).error().code()),
              static_cast<int>(ErrorCode::UnknownEnumToken));
}

}  // namespace

CT_TEST(test_enum_token_round_trip) {
  check_enum_tokens<Availability>("availability", 2, [](Availability value) { return to_token(value); },
                                  [](std::string_view token) { return availability_from_token(token); });
  check_enum_tokens<ObservationQuality>(
      "observation-quality", 4, [](ObservationQuality value) { return to_token(value); },
      [](std::string_view token) { return observation_quality_from_token(token); });
  check_enum_tokens<Freshness>("freshness", 4, [](Freshness value) { return to_token(value); },
                               [](std::string_view token) { return freshness_from_token(token); });
  check_enum_tokens<ConfirmationState>(
      "confirmation-state", 6, [](ConfirmationState value) { return to_token(value); },
      [](std::string_view token) { return confirmation_state_from_token(token); });
  check_enum_tokens<FailureClass>("failure-class", 15, [](FailureClass value) { return to_token(value); },
                                  [](std::string_view token) { return failure_class_from_token(token); });
  check_enum_tokens<Severity>("severity", 5, [](Severity value) { return to_token(value); },
                              [](std::string_view token) { return severity_from_token(token); });
  check_enum_tokens<Urgency>("urgency", 4, [](Urgency value) { return to_token(value); },
                             [](std::string_view token) { return urgency_from_token(token); });
  check_enum_tokens<TimeToImpact>("time-to-impact", 6, [](TimeToImpact value) { return to_token(value); },
                                  [](std::string_view token) { return time_to_impact_from_token(token); });
  check_enum_tokens<ObservationChannel>(
      "observation-channel", 17, [](ObservationChannel value) { return to_token(value); },
      [](std::string_view token) { return observation_channel_from_token(token); });
  check_enum_tokens<LeakState>("leak-state", 5, [](LeakState value) { return to_token(value); },
                               [](std::string_view token) { return leak_state_from_token(token); });
  check_enum_tokens<EvidenceStatus>(
      "evidence-status", 8, [](EvidenceStatus value) { return to_token(value); },
      [](std::string_view token) { return evidence_status_from_token(token); });
  check_enum_tokens<ResponseAction>(
      "response-action", 14, [](ResponseAction value) { return to_token(value); },
      [](std::string_view token) { return response_action_from_token(token); });
  check_enum_tokens<EffectClass>("effect-class", 8, [](EffectClass value) { return to_token(value); },
                                 [](std::string_view token) { return effect_class_from_token(token); });
  check_enum_tokens<PlanLifecycle>(
      "plan-lifecycle", 8, [](PlanLifecycle value) { return to_token(value); },
      [](std::string_view token) { return plan_lifecycle_from_token(token); });
  check_enum_tokens<AttemptState>("attempt-state", 10, [](AttemptState value) { return to_token(value); },
                                  [](std::string_view token) { return attempt_state_from_token(token); });
  check_enum_tokens<RecoveryDecision>(
      "recovery-decision", 4, [](RecoveryDecision value) { return to_token(value); },
      [](std::string_view token) { return recovery_decision_from_token(token); });
  check_enum_tokens<RecoveryGate>("recovery-gate", 12, [](RecoveryGate value) { return to_token(value); },
                                  [](std::string_view token) { return recovery_gate_from_token(token); });
  check_enum_tokens<RestrictionKind>(
      "restriction-kind", 7, [](RestrictionKind value) { return to_token(value); },
      [](std::string_view token) { return restriction_kind_from_token(token); });
  check_enum_tokens<ScopeKind>("scope-kind", 11, [](ScopeKind value) { return to_token(value); },
                               [](std::string_view token) { return scope_kind_from_token(token); });
  check_enum_tokens<DependencyKind>(
      "dependency-kind", 6, [](DependencyKind value) { return to_token(value); },
      [](std::string_view token) { return dependency_kind_from_token(token); });
  check_enum_tokens<BindingStatus>(
      "binding-status", 4, [](BindingStatus value) { return to_token(value); },
      [](std::string_view token) { return binding_status_from_token(token); });
}

CT_TEST(test_enum_token_spellings) {
  // Spot checks that pin the exact durable spelling of representative tokens,
  // so a rename is caught even when it stays internally consistent.
  CT_CHECK_EQ(std::string(to_token(FailureClass::PumpFailure)), std::string("pump-failure"));
  CT_CHECK_EQ(std::string(to_token(FailureClass::CrahCracFailure)), std::string("crah-crac-failure"));
  CT_CHECK_EQ(std::string(to_token(ObservationChannel::ThermalCapacityMeter)),
              std::string("thermal-capacity-meter"));
  CT_CHECK_EQ(std::string(to_token(TimeToImpact::TensOfMinutes)), std::string("tens-of-minutes"));
  CT_CHECK_EQ(std::string(to_token(EvidenceStatus::Indeterminate)), std::string("indeterminate"));
  CT_CHECK_EQ(std::string(to_token(Availability::Indeterminate)), std::string("indeterminate"));
  CT_CHECK_EQ(std::string(to_token(AttemptState::EffectObserved)), std::string("effect-observed"));
  CT_CHECK_EQ(std::string(to_token(BindingStatus::Mismatched)), std::string("mismatched"));
  CT_CHECK_EQ(std::string(to_token(RestrictionKind::NoCapacityCommitment)),
              std::string("no-capacity-commitment"));
  CT_CHECK_EQ(std::string(to_token(RecoveryGate::ConfirmedClassesCleared)),
              std::string("confirmed-classes-cleared"));
  CT_CHECK_EQ(std::string(to_token(ScopeKind::AirHandlerGroup)), std::string("air-handler-group"));
  CT_CHECK_EQ(std::string(to_token(DependencyKind::SharesPowerTrain)),
              std::string("shares-power-train"));
  CT_CHECK_EQ(std::string(to_token(LeakState::LeakUnknown)), std::string("leak-unknown"));
  CT_CHECK_EQ(std::string(to_token(RecoveryDecision::NotRequested)), std::string("not-requested"));

  // Tokens are per-enumeration, so the same spelling may mean a different thing
  // in two enumerations without ambiguity.
  const auto availability = availability_from_token("indeterminate");
  const auto evidence = evidence_status_from_token("indeterminate");
  CT_REQUIRE(availability.has_value());
  CT_REQUIRE(evidence.has_value());
  CT_CHECK_EQ(static_cast<int>(availability.value()), static_cast<int>(Availability::Indeterminate));
  CT_CHECK_EQ(static_cast<int>(evidence.value()), static_cast<int>(EvidenceStatus::Indeterminate));
}

CT_TEST(test_enum_unknown_token_is_named_and_bounded) {
  // A long unknown token is bounded in the error value instead of being copied
  // whole, and the message still names it.
  const std::string long_token(4096, 'x');
  const auto result = failure_class_from_token(long_token);
  CT_REQUIRE(!result.has_value());
  CT_CHECK_EQ(static_cast<int>(result.error().code()), static_cast<int>(ErrorCode::UnknownEnumToken));
  CT_CHECK_EQ(result.error().subject().size(), limits::kMaxTokenBytes);
  CT_CHECK(!result.error().message().empty());

  // An uppercase or spaced spelling is not a token: decoding never folds case.
  CT_CHECK(!failure_class_from_token("Pump-Failure").has_value());
  CT_CHECK(!failure_class_from_token("pump_failure").has_value());
  CT_CHECK(!failure_class_from_token(" pump-failure").has_value());
  CT_CHECK(!failure_class_from_token("pump-failure ").has_value());
  CT_CHECK(!failure_class_from_token(std::string()).has_value());
  CT_CHECK_EQ(static_cast<int>(failure_class_from_token("Pump-Failure").error().code()),
              static_cast<int>(ErrorCode::UnknownEnumToken));
}

CT_TEST(test_order_tables) {
  CT_CHECK_EQ(failure_class_count(), std::size_t{15});
  CT_CHECK_EQ(observation_channel_count(), std::size_t{17});
  CT_CHECK_EQ(response_action_count(), std::size_t{14});
  CT_CHECK_EQ(recovery_gate_count(), std::size_t{12});
  CT_CHECK_EQ(restriction_kind_count(), std::size_t{7});

  const FailureClass* classes = failure_class_order();
  for (std::size_t index = 0; index < failure_class_count(); ++index) {
    CT_CHECK_EQ(static_cast<int>(classes[index]), static_cast<int>(index));
  }
  const ObservationChannel* channels = observation_channel_order();
  for (std::size_t index = 0; index < observation_channel_count(); ++index) {
    CT_CHECK_EQ(static_cast<int>(channels[index]), static_cast<int>(index));
  }
  const ResponseAction* actions = response_action_order();
  for (std::size_t index = 0; index < response_action_count(); ++index) {
    CT_CHECK_EQ(static_cast<int>(actions[index]), static_cast<int>(index));
  }
  const RecoveryGate* gates = recovery_gate_order();
  for (std::size_t index = 0; index < recovery_gate_count(); ++index) {
    CT_CHECK_EQ(static_cast<int>(gates[index]), static_cast<int>(index));
  }
  const RestrictionKind* restrictions = restriction_kind_order();
  for (std::size_t index = 0; index < restriction_kind_count(); ++index) {
    CT_CHECK_EQ(static_cast<int>(restrictions[index]), static_cast<int>(index));
  }
}

CT_TEST(test_failure_class_is_total_loss_predicate) {
  // Order: PlantLoss, PumpFailure, LoopDegradation, LoopLoss, ChillerFailure,
  // CduFailure, ValveFlowFailure, PressureFailure, CrahCracFailure, AirflowLoss,
  // ContainmentBreach, Leak, ThermalCapacityLoss, SharedSourceFailure,
  // ThermalRunaway.
  //
  // The truth set is narrow on purpose. This predicate decides which confirmed
  // upstream failures are attributed to the scopes that depend on them, so only a
  // loss of the WHOLE cooling function of a scope qualifies: the plant, the loop,
  // the CDU, the shared source or thermal control itself. A single failed chiller
  // unit inside a live plant, a single failed air-handling unit, a failed pump
  // set, a valve or pressure fault, a containment breach, a leak and a capacity
  // shortfall are all degradations of a scope that is still functioning, and
  // attributing any of them downstream would report a loss that did not happen.
  const bool expected[] = {true,  false, false, true,  false, true,  false, false,
                           false, false, false, false, false, true,  true};
  CT_CHECK_EQ(std::size(expected), failure_class_count());
  for (std::size_t index = 0; index < failure_class_count(); ++index) {
    const auto value = static_cast<FailureClass>(index);
    CT_CHECK_EQ(failure_class_is_total_loss(value), expected[index]);
  }
}

CT_TEST(test_severity_and_urgency_predicates) {
  const Severity severities[] = {Severity::None, Severity::Degraded, Severity::Impaired, Severity::Critical,
                                 Severity::Total};
  for (const Severity value : severities) {
    for (const Severity floor : severities) {
      const bool expected = static_cast<unsigned>(value) >= static_cast<unsigned>(floor);
      CT_CHECK_EQ(severity_at_least(value, floor), expected);
    }
  }
  const Urgency urgencies[] = {Urgency::Routine, Urgency::Elevated, Urgency::Imminent, Urgency::Immediate};
  for (const Urgency value : urgencies) {
    for (const Urgency floor : urgencies) {
      const bool expected = static_cast<unsigned>(value) >= static_cast<unsigned>(floor);
      CT_CHECK_EQ(urgency_at_least(value, floor), expected);
    }
  }
  CT_CHECK(severity_at_least(Severity::Total, Severity::Critical));
  CT_CHECK(!severity_at_least(Severity::Degraded, Severity::Critical));
  CT_CHECK(urgency_at_least(Urgency::Immediate, Urgency::Immediate));
  CT_CHECK(!urgency_at_least(Urgency::Routine, Urgency::Elevated));
}

CT_TEST(test_leak_evidence_and_binding_predicates) {
  for (unsigned index = 0; index < 5; ++index) {
    const auto value = static_cast<LeakState>(index);
    CT_CHECK_EQ(leak_state_is_clear(value), value == LeakState::LeakNone);
  }
  for (unsigned index = 0; index < 8; ++index) {
    const auto value = static_cast<EvidenceStatus>(index);
    CT_CHECK_EQ(evidence_status_is_usable(value), value == EvidenceStatus::Current);
  }
  for (unsigned index = 0; index < 4; ++index) {
    const auto value = static_cast<BindingStatus>(index);
    CT_CHECK_EQ(binding_status_is_current(value), value == BindingStatus::Current);
  }
  CT_CHECK(leak_state_is_clear(LeakState::LeakNone));
  CT_CHECK(!leak_state_is_clear(LeakState::LeakUnknown));
  CT_CHECK(evidence_status_is_usable(EvidenceStatus::Current));
  CT_CHECK(!evidence_status_is_usable(EvidenceStatus::Indeterminate));
  CT_CHECK(binding_status_is_current(BindingStatus::Current));
  CT_CHECK(!binding_status_is_current(BindingStatus::Stale));
}

CT_TEST(test_response_action_predicates) {
  // Order: ObserveOnly, VerifyEvidence, IsolateScope, FailoverCoolingSource,
  // StartStandbyPump, StartStandbyChiller, OpenBypassValve, CloseIsolationValve,
  // RaiseFanSpeed, ReduceThermalLoad, ThrottleWorkload, EvacuateScope,
  // EmergencyShutdown, ManualIntervention.
  const bool load_reduction[] = {false, false, false, false, false, false, false,
                                 false, false, true,  true,  true,  true,  false};
  const bool protective[] = {false, false, true,  false, false, false, false,
                             true,  false, true,  true,  true,  true,  true};
  CT_CHECK_EQ(std::size(load_reduction), response_action_count());
  CT_CHECK_EQ(std::size(protective), response_action_count());
  for (std::size_t index = 0; index < response_action_count(); ++index) {
    const auto value = static_cast<ResponseAction>(index);
    CT_CHECK_EQ(response_action_is_load_reduction(value), load_reduction[index]);
    CT_CHECK_EQ(response_action_is_protective(value), protective[index]);
  }
  // A load-reducing action is protective: it bounds harm when cooling cannot be
  // restored. The converse is deliberately false (isolation restores nothing).
  CT_CHECK(response_action_is_protective(ResponseAction::IsolateScope));
  CT_CHECK(!response_action_is_load_reduction(ResponseAction::IsolateScope));
  CT_CHECK(!response_action_is_protective(ResponseAction::ObserveOnly));
}

CT_TEST(test_attempt_state_predicates) {
  // Order: Planned, Solicited, Acknowledged, Refused, Failed, EffectObserved,
  // Verified, Refuted, Unresolved, Withdrawn.
  const bool terminal[] = {false, false, false, true,  true,  false,
                           true,  true,  false, true};
  CT_CHECK_EQ(std::size(terminal), std::size_t{10});
  for (std::size_t index = 0; index < 10; ++index) {
    const auto value = static_cast<AttemptState>(index);
    CT_CHECK_EQ(attempt_state_is_terminal(value), terminal[index]);
    CT_CHECK_EQ(attempt_state_is_unresolved(value), value == AttemptState::Unresolved);
  }
  // Unresolved is precisely the state that still needs an explicit decision, so
  // it is never terminal. EffectObserved is not terminal either: the effect
  // still has to be verified or refuted.
  CT_CHECK(!attempt_state_is_terminal(AttemptState::Unresolved));
  CT_CHECK(!attempt_state_is_terminal(AttemptState::EffectObserved));
  CT_CHECK(attempt_state_is_unresolved(AttemptState::Unresolved));
}

// ---------------------------------------------------------------------------
// The error registry
// ---------------------------------------------------------------------------

CT_TEST(test_error_code_registry) {
  const int last = static_cast<int>(ErrorCode::InternalError);
  std::vector<std::string> names;
  for (int value = 0; value <= 0xFFFF; ++value) {
    const std::string_view name = error_code_name(static_cast<ErrorCode>(value));
    if (name == "UnknownErrorCode") {
      continue;
    }
    CT_CHECK_MSG(!name.empty(), "an error name must be non-empty");
    CT_CHECK_MSG(value <= last, "a code outside the enumeration must not resolve to a name");
    const std::string text(name);
    for (const std::string& other : names) {
      CT_CHECK_MSG(other != text, "duplicate error name: " + text);
    }
    names.push_back(text);
  }
  // Every enumerator from Ok to the last declared code resolves to a name.
  CT_CHECK_EQ(names.size(), static_cast<std::size_t>(last + 1));
  for (int value = 0; value <= last; ++value) {
    CT_CHECK_MSG(error_code_name(static_cast<ErrorCode>(value)) != "UnknownErrorCode",
                 "every enumerator needs a name");
  }
  CT_CHECK_EQ(error_code_name(ErrorCode::Ok), std::string_view("Ok"));
  CT_CHECK_EQ(error_code_name(ErrorCode::MalformedRecord), std::string_view("MalformedRecord"));
  CT_CHECK_EQ(error_code_name(ErrorCode::TimestampOutOfRange), std::string_view("TimestampOutOfRange"));
  CT_CHECK_EQ(error_code_name(ErrorCode::StaleWriterIncarnation),
              std::string_view("StaleWriterIncarnation"));
  CT_CHECK_EQ(error_code_name(ErrorCode::PathUnsafeName), std::string_view("PathUnsafeName"));
  CT_CHECK_EQ(error_code_name(ErrorCode::InternalError), std::string_view("InternalError"));
  // A value outside the enumeration has a stable non-enumerator name.
  CT_CHECK_EQ(error_code_name(static_cast<ErrorCode>(0xFFFF)), std::string_view("UnknownErrorCode"));
  CT_CHECK_EQ(error_code_name(static_cast<ErrorCode>(last + 1)), std::string_view("UnknownErrorCode"));
}

CT_TEST(test_error_category_mapping) {
  CT_CHECK_EQ(static_cast<int>(error_category(ErrorCode::Ok)), static_cast<int>(ErrorCategory::Ok));
  const int last = static_cast<int>(ErrorCode::InternalError);
  for (int value = 1; value <= last; ++value) {
    CT_CHECK_MSG(error_category(static_cast<ErrorCode>(value)) != ErrorCategory::Ok,
                 "a non-Ok code must never be classified Ok");
  }
  CT_CHECK_EQ(static_cast<int>(error_category(ErrorCode::InvalidArgument)),
              static_cast<int>(ErrorCategory::Argument));
  // LimitExceeded is reported for a rejected input magnitude, so it is an
  // argument rejection rather than a limit of its own.
  CT_CHECK_EQ(static_cast<int>(error_category(ErrorCode::LimitExceeded)),
              static_cast<int>(ErrorCategory::Argument));
  CT_CHECK_EQ(static_cast<int>(error_category(ErrorCode::EvidenceStale)),
              static_cast<int>(ErrorCategory::Evidence));
  CT_CHECK_EQ(static_cast<int>(error_category(ErrorCode::ObservationOutOfOrder)),
              static_cast<int>(ErrorCategory::Evidence));
  CT_CHECK_EQ(static_cast<int>(error_category(ErrorCode::ScopeCycle)),
              static_cast<int>(ErrorCategory::Structure));
  CT_CHECK_EQ(static_cast<int>(error_category(ErrorCode::SharedSourceUnknown)),
              static_cast<int>(ErrorCategory::Structure));
  CT_CHECK_EQ(static_cast<int>(error_category(ErrorCode::StaleDecision)),
              static_cast<int>(ErrorCategory::Authority));
  CT_CHECK_EQ(static_cast<int>(error_category(ErrorCode::PathTraversal)),
              static_cast<int>(ErrorCategory::Persistence));
  CT_CHECK_EQ(static_cast<int>(error_category(ErrorCode::HeadCorrupt)),
              static_cast<int>(ErrorCategory::Persistence));
  CT_CHECK_EQ(static_cast<int>(error_category(ErrorCode::StoreLocked)),
              static_cast<int>(ErrorCategory::Lifecycle));
  CT_CHECK_EQ(static_cast<int>(error_category(ErrorCode::IdempotencyEvicted)),
              static_cast<int>(ErrorCategory::Lifecycle));
  CT_CHECK_EQ(static_cast<int>(error_category(ErrorCode::InternalError)),
              static_cast<int>(ErrorCategory::Internal));
  // A value outside the enumeration is a library defect, not Ok.
  CT_CHECK_EQ(static_cast<int>(error_category(static_cast<ErrorCode>(0xFFFF))),
              static_cast<int>(ErrorCategory::Internal));

  std::vector<std::string> category_names;
  for (int value = 0; value <= 8; ++value) {
    const std::string name(error_category_name(static_cast<ErrorCategory>(value)));
    CT_CHECK_MSG(!name.empty(), "a category name must be non-empty");
    for (const std::string& other : category_names) {
      CT_CHECK_MSG(other != name, "duplicate category name: " + name);
    }
    category_names.push_back(name);
  }
  CT_CHECK_EQ(category_names.size(), std::size_t{9});
  CT_CHECK_EQ(error_category_name(ErrorCategory::Ok), std::string_view("OK"));
  CT_CHECK_EQ(error_category_name(ErrorCategory::Evidence), std::string_view("EVIDENCE"));
  // An unknown category value still names itself instead of crashing.
  CT_CHECK(!error_category_name(static_cast<ErrorCategory>(200)).empty());
}

CT_TEST(test_error_to_string) {
  const Error plain(ErrorCode::MalformedRecord, "field is not canonical");
  CT_CHECK_EQ(plain.to_string(), std::string("MalformedRecord: field is not canonical"));
  CT_CHECK(plain.ok() == false);
  CT_CHECK_EQ(plain.message(), std::string("field is not canonical"));

  Error annotated(ErrorCode::UnknownEnumToken, "unknown token");
  annotated.with_subject("bogus").with_detail("first").with_detail("second");
  CT_CHECK_EQ(annotated.to_string(),
              std::string("UnknownEnumToken: unknown token [subject=bogus] [detail=first] "
                          "[detail=second]"));
  CT_CHECK_EQ(annotated.subject(), std::string("bogus"));
  CT_CHECK_EQ(annotated.details().size(), std::size_t{2});
  CT_CHECK_EQ(annotated.details()[0], std::string("first"));
  CT_CHECK_EQ(annotated.details()[1], std::string("second"));
  CT_CHECK_EQ(static_cast<int>(annotated.category()), static_cast<int>(ErrorCategory::Argument));

  // An empty subject is omitted rather than rendered as an empty clause.
  Error empty_subject(ErrorCode::InternalError, "defect");
  empty_subject.with_subject(std::string());
  CT_CHECK_EQ(empty_subject.to_string(), std::string("InternalError: defect"));

  CT_CHECK(Error(ErrorCode::Ok, std::string()).ok());
  CT_CHECK_EQ(std::string(error_code_name(ErrorCode::Ok)), std::string("Ok"));
}

CT_TEST(test_result_semantics) {
  const Result<int> value(7);
  CT_REQUIRE(value.has_value());
  CT_CHECK_EQ(value.value(), 7);
  CT_CHECK_EQ(*value, 7);

  const Result<int> failure(Error(ErrorCode::InvalidArgument, "nope"));
  CT_CHECK(!failure.has_value());
  CT_CHECK_EQ(static_cast<int>(failure.error().code()), static_cast<int>(ErrorCode::InvalidArgument));

  // A Result built from an Ok error carries no value, and the defect is
  // reported rather than silently becoming a success.
  const Result<void> normalized(Error(ErrorCode::Ok, std::string("no error")));
  CT_CHECK(!normalized.has_value());
  CT_CHECK_EQ(static_cast<int>(normalized.error().code()), static_cast<int>(ErrorCode::InternalError));

  CT_CHECK(ok().has_value());
  const Result<void> success = Result<void>::success();
  CT_CHECK(success.has_value());
  CT_CHECK(success.error().ok());
}

CT_TEST(test_result_value_throws_only_on_programmer_error) {
  // The header documents that value() throws std::logic_error only when a
  // failed Result is dereferenced; every expected failure travels as an Error.
  const Result<int> failure(Error(ErrorCode::MissingField, "absent"));
  bool threw = false;
  try {
    (void)failure.value();
  } catch (const std::logic_error& error) {
    threw = true;
    CT_CHECK_MSG(std::string(error.what()).find("MissingField") != std::string::npos,
                 "the diagnostic names the failing code");
  }
  CT_CHECK_MSG(threw, "dereferencing a failed Result is a programmer error");
  const Result<int> value(3);
  CT_CHECK_EQ(value.value(), 3);
}

// ---------------------------------------------------------------------------
// Version agreement and determinism
// ---------------------------------------------------------------------------

CT_TEST(test_version_agreement) {
  CT_CHECK_EQ(std::string(version_string()), std::string("1.0.1"));
  CT_CHECK_EQ(std::string(component_id()), std::string("dccp-cooling-failure-manager/1.0.1"));
  CT_CHECK(!systems_boundary().empty());
  CT_CHECK_EQ(std::string(version_string()),
              std::to_string(kVersionMajor) + "." + std::to_string(kVersionMinor) + "." +
                  std::to_string(kVersionPatch));
#ifdef COOLING_FAILURE_MANAGER_CMAKE_VERSION
  // The compile definition is supplied by the test support target, so the CMake
  // project version and the compiled-in version cannot drift apart silently.
  CT_CHECK_EQ(std::string(version_string()), std::string(COOLING_FAILURE_MANAGER_CMAKE_VERSION));
#else
  ct_test::report_note(
      "COOLING_FAILURE_MANAGER_CMAKE_VERSION is not defined; the CMake cross-check did not run");
#endif
}

CT_TEST(test_deterministic_rendering) {
  const std::string sample = bytes({0x00, 0x41, 0x7F, 0xFF, 0x0A});
  const std::string first_escape = escape_text(sample);
  const std::string first_hex = digest_bytes(sample).to_hex();
  Error first_error(ErrorCode::MalformedRecord, "message");
  first_error.with_subject("subject").with_detail("detail");
  const std::string first_text = first_error.to_string();
  CT_CHECK_EQ(std::string(to_token(FailureClass::ThermalRunaway)), std::string("thermal-runaway"));
  for (int repetition = 0; repetition < 8; ++repetition) {
    CT_CHECK_EQ(escape_text(sample), first_escape);
    CT_CHECK_EQ(digest_bytes(sample).to_hex(), first_hex);
    Error next(ErrorCode::MalformedRecord, "message");
    next.with_subject("subject").with_detail("detail");
    CT_CHECK_EQ(next.to_string(), first_text);
    CT_CHECK_EQ(to_decimal(INT64_MIN), std::string("-9223372036854775808"));
    CT_CHECK_EQ(to_decimal(UINT64_MAX), std::string("18446744073709551615"));
    CT_CHECK_EQ(std::string(to_token(EvidenceStatus::OutOfOrder)), std::string("out-of-order"));
  }
}

}  // namespace
