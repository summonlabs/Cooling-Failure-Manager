// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Minimal test framework. No timing logic, no timeouts, no test-order
// dependence: every test runs to completion and reports its own failures.

#ifndef COOLING_FAILURE_MANAGER_TEST_FRAMEWORK_HPP
#define COOLING_FAILURE_MANAGER_TEST_FRAMEWORK_HPP

#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace ct_test {

/// Thrown by CT_REQUIRE to abandon the current test without abandoning the run.
struct TestAborted {
  std::string reason;
};

struct TestCase {
  std::string name;
  std::string file;
  int line = 0;
  std::function<void()> body;
};

std::vector<TestCase>& registry();

struct Registrar {
  Registrar(std::string name, std::string file, int line, std::function<void()> body);
};

/// Current failure recorder. Every check reports through it.
void report_failure(const std::string& file, int line, const std::string& expression,
                    const std::string& detail);
void report_note(const std::string& text);

/// Seed of the current run and a per-case derived seed, so a randomized case is
/// reproducible from the run seed and the case name alone.
/// Installs the seed of this run before any test executes.
void set_run_seed(std::uint64_t seed);

std::uint64_t run_seed();
std::uint64_t case_seed(const std::string& name);

/// Deterministic pseudo-random generator (splitmix64). Never seeded from a
/// clock or from the environment.
class Rng {
 public:
  explicit Rng(std::uint64_t seed) : state_(seed) {}
  std::uint64_t next() noexcept;
  std::uint32_t below(std::uint32_t bound) noexcept;
  bool chance(std::uint32_t numerator, std::uint32_t denominator) noexcept;

 private:
  std::uint64_t state_;
};

/// Renders a value for a failure message. Overloaded for the types the suite
/// compares; anything else falls back to a placeholder.
std::string describe(bool value);
std::string describe(int value);
std::string describe(long long value);
std::string describe(unsigned value);
std::string describe(unsigned long long value);
std::string describe(const std::string& value);
std::string describe(std::string_view value);
std::string describe(const char* value);

template <class T>
std::string describe(const T&) {
  return "<value>";
}

int run_all(const std::string& filter);

}  // namespace ct_test

#define CT_TEST(test_name)                                                              \
  static void test_name();                                                              \
  static ::ct_test::Registrar test_name##_registrar(#test_name, __FILE__, __LINE__,     \
                                                    &test_name);                        \
  static void test_name()

#define CT_CHECK(expression)                                                            \
  do {                                                                                  \
    const bool ct_ok_ = static_cast<bool>(expression);                                  \
    if (!ct_ok_) {                                                                      \
      ::ct_test::report_failure(__FILE__, __LINE__, #expression, "");                   \
    }                                                                                   \
  } while (false)

#define CT_CHECK_MSG(expression, message)                                               \
  do {                                                                                  \
    const bool ct_ok_ = static_cast<bool>(expression);                                  \
    if (!ct_ok_) {                                                                      \
      ::ct_test::report_failure(__FILE__, __LINE__, #expression, (message));            \
    }                                                                                   \
  } while (false)

// The operands are held by value rather than by reference. An operand is often a
// value read out of a temporary Result, and binding that by reference would leave
// the reference pointing into storage that the temporary's destruction has already
// ended. Holding the value is also exactly what the check means.
#define CT_CHECK_EQ(lhs, rhs)                                                           \
  do {                                                                                  \
    const auto ct_lhs_ = (lhs);                                                         \
    const auto ct_rhs_ = (rhs);                                                         \
    const bool ct_ok_ = static_cast<bool>(ct_lhs_ == ct_rhs_);                           \
    if (!ct_ok_) {                                                                      \
      ::ct_test::report_failure(__FILE__, __LINE__, #lhs " == " #rhs,                   \
                                ::ct_test::describe(ct_lhs_) + " != " +                 \
                                    ::ct_test::describe(ct_rhs_));                      \
    }                                                                                   \
  } while (false)

#define CT_REQUIRE(expression)                                                          \
  do {                                                                                  \
    const bool ct_ok_ = static_cast<bool>(expression);                                  \
    if (!ct_ok_) {                                                                      \
      ::ct_test::report_failure(__FILE__, __LINE__, #expression, "required");           \
      throw ::ct_test::TestAborted{#expression};                                        \
    }                                                                                   \
  } while (false)

#endif  // COOLING_FAILURE_MANAGER_TEST_FRAMEWORK_HPP
