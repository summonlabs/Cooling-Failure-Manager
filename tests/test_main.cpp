// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "test_framework.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <string>
#include <string_view>
#include <vector>

namespace ct_test {
namespace {

std::uint64_t g_seed = 0;
int g_failures = 0;
int g_checks = 0;
std::string g_current;

std::string hex64(std::uint64_t value) {
  static const char* digits = "0123456789abcdef";
  std::string out(16, '0');
  for (int index = 15; index >= 0; --index) {
    out[static_cast<std::size_t>(index)] = digits[value & 0xFu];
    value >>= 4;
  }
  return out;
}

}  // namespace

std::vector<TestCase>& registry() {
  static std::vector<TestCase> cases;
  return cases;
}

Registrar::Registrar(std::string name, std::string file, int line, std::function<void()> body) {
  registry().push_back(TestCase{std::move(name), std::move(file), line, std::move(body)});
}

void report_failure(const std::string& file, int line, const std::string& expression,
                    const std::string& detail) {
  ++g_failures;
  std::printf("FAIL %s\n  %s:%d\n  %s%s%s\n", g_current.c_str(), file.c_str(), line, expression.c_str(),
              detail.empty() ? "" : " -> ", detail.c_str());
  std::fflush(stdout);
}

void report_note(const std::string& text) {
  std::printf("NOTE %s: %s\n", g_current.c_str(), text.c_str());
  std::fflush(stdout);
}

void set_run_seed(std::uint64_t seed) { g_seed = seed; }

std::uint64_t run_seed() { return g_seed; }

std::uint64_t case_seed(const std::string& name) {
  std::uint64_t value = g_seed ^ 0x9E3779B97F4A7C15ull;
  for (const char byte : name) {
    value ^= static_cast<unsigned char>(byte);
    value *= 0x100000001B3ull;
  }
  value ^= value >> 29;
  value *= 0xBF58476D1CE4E5B9ull;
  value ^= value >> 32;
  return value;
}

std::uint64_t Rng::next() noexcept {
  state_ += 0x9E3779B97F4A7C15ull;
  std::uint64_t value = state_;
  value = (value ^ (value >> 30)) * 0xBF58476D1CE4E5B9ull;
  value = (value ^ (value >> 27)) * 0x94D049BB133111EBull;
  return value ^ (value >> 31);
}

std::uint32_t Rng::below(std::uint32_t bound) noexcept {
  if (bound == 0) {
    return 0;
  }
  return static_cast<std::uint32_t>(next() % bound);
}

bool Rng::chance(std::uint32_t numerator, std::uint32_t denominator) noexcept {
  if (denominator == 0) {
    return false;
  }
  return below(denominator) < numerator;
}

std::string describe(bool value) { return value ? "true" : "false"; }
std::string describe(int value) { return std::to_string(value); }
std::string describe(long long value) { return std::to_string(value); }
std::string describe(unsigned value) { return std::to_string(value); }
std::string describe(unsigned long long value) { return std::to_string(value); }
std::string describe(const std::string& value) { return "\"" + value + "\""; }
std::string describe(std::string_view value) { return "\"" + std::string(value) + "\""; }
std::string describe(const char* value) { return std::string("\"") + value + "\""; }

int run_all(const std::string& filter) {
  int executed = 0;
  for (TestCase& test : registry()) {
    if (!filter.empty() && test.name.find(filter) == std::string::npos) {
      continue;
    }
    ++executed;
    g_current = test.name;
    const int before = g_failures;
    try {
      test.body();
    } catch (const TestAborted& aborted) {
      std::printf("ABORT %s: %s\n", test.name.c_str(), aborted.reason.c_str());
    } catch (const std::exception& error) {
      report_failure(test.file, test.line, "no unexpected exception",
                     std::string("std::exception: ") + error.what());
    } catch (...) {
      report_failure(test.file, test.line, "no unexpected exception", "unknown exception");
    }
    ++g_checks;
    std::printf("%-6s %s\n", g_failures == before ? "ok" : "FAILED", test.name.c_str());
    std::fflush(stdout);
  }
  std::printf("\n%d test(s) executed, %d failing check(s), seed=%s\n", executed, g_failures,
              hex64(g_seed).c_str());
  std::fflush(stdout);
  return g_failures == 0 ? 0 : 1;
}

}  // namespace ct_test

int main(int argc, char** argv) {
  std::string filter;
  std::uint64_t seed = 0x5DEECE66Dull;
  bool list = false;
  for (int index = 1; index < argc; ++index) {
    const std::string_view argument(argv[index]);
    if (argument == "--list") {
      list = true;
    } else if (argument.rfind("--filter=", 0) == 0) {
      filter = std::string(argument.substr(9));
    } else if (argument.rfind("--seed=", 0) == 0) {
      seed = std::strtoull(std::string(argument.substr(7)).c_str(), nullptr, 10);
    } else {
      std::printf("usage: %s [--filter=<substring>] [--seed=<n>] [--list]\n", argv[0]);
      return 2;
    }
  }
  if (list) {
    for (const ct_test::TestCase& test : ct_test::registry()) {
      std::printf("%s\n", test.name.c_str());
    }
    return 0;
  }
  ct_test::set_run_seed(seed);
  return ct_test::run_all(filter);
}
