#pragma once

#include <broker/data.hh>
#include <broker/error.hh>

#include <zeek/OpaqueVal.h>
#include <zeek/file_analysis/analyzer/hash/Hash.h>
#include <zeek/file_analysis/analyzer/hash/events.bif.h>

namespace plugin::Zeek_MoreHashes::detail {

class MMH3Val : public zeek::HashVal {
public:
  explicit MMH3Val(uint32_t seed = 0) : HashVal(mmh3_type), mmh3_h1{seed} {}

  bool DoInit() override { return true; }

  bool DoFeed(const void *data, size_t size) override;

  // MMH3 returns uint32_t, but Zeek's API and the file_hash() event assume
  // strings so we just format an unsigned integer to a string.
  zeek::StringValPtr DoGet() override;

  uint32_t Result();

  broker::expected<broker::data> DoSerialize() const override;

  bool DoUnserialize(const broker::data &data) override;

  const char *OpaqueName() const override { return "MMH3Val"; }

  static zeek::OpaqueTypePtr mmh3_type;

private:
  uint32_t mmh3_h1;
  uint32_t mmh3_carry = 0;
  uint32_t mmh3_total_len = 0;
};

class MMH3 : public zeek::file_analysis::detail::Hash {
public:
  static zeek::file_analysis::Analyzer *
  Instantiate(zeek::RecordValPtr arg_args,
              zeek::file_analysis::File *arg_file) {
    return new MMH3(arg_args, arg_file);
  }

  // Return value of mmh3_seed if it exists in AnalyzerArgs, else 0.
  static int seed_from_args(zeek::RecordValPtr args) {
    if (mmh3_seed_field_offset < 0)
      return 0;

    return static_cast<int>(
        args->GetFieldOrDefault(mmh3_seed_field_offset)->AsCount());
  }

  static void InitPostScript();

private:
  MMH3(zeek::RecordValPtr arg_args, zeek::file_analysis::File *arg_file)
      : zeek::file_analysis::detail::Hash(
            arg_args, arg_file,
            new detail::MMH3Val(MMH3::seed_from_args(arg_args)),
            MMH3::kind_val) {}

  static zeek::StringValPtr kind_val;
  static int mmh3_seed_field_offset;
};

} // namespace plugin::Zeek_MoreHashes::detail
