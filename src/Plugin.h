
#pragma once

#include <broker/data.hh>
#include <broker/error.hh>

#include <zeek/OpaqueVal.h>
#include <zeek/plugin/Plugin.h>

#include "config.h"

namespace plugin::Zeek_MoreHashes {

class Plugin : public zeek::plugin::Plugin {
protected:
  zeek::plugin::Configuration Configure() override;
  void InitPostScript() override;
};

extern Plugin plugin;

namespace detail {

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

} // namespace detail

} // namespace plugin::Zeek_MoreHashes
