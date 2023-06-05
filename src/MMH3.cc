#include "MMH3.h"

#include "3rdparty/PMurHash.h"
#include "Plugin.h"

#include <zeek/ID.h>

using namespace plugin::Zeek_MoreHashes;

bool detail::MMH3Val::DoFeed(const void *data, size_t size) {
  mmh3_total_len += size;
  PMurHash32_Process(&mmh3_h1, &mmh3_carry, data, static_cast<int>(size));
  return true;
}

zeek::StringValPtr detail::MMH3Val::DoGet() {
  return zeek::make_intrusive<zeek::StringVal>(zeek::util::fmt("%u", Result()));
}

uint32_t detail::MMH3Val::Result() {
  return PMurHash32_Result(mmh3_h1, mmh3_carry, mmh3_total_len);
}

broker::expected<broker::data> detail::MMH3Val::DoSerialize() const {
  if (!IsValid())
    return {broker::vector{false}};

  broker::vector d = {true, mmh3_h1, mmh3_carry, mmh3_total_len};
  return {std::move(d)};
}

// This is a totally untested best-effort implementation. It's a
// bit of a burden adding this to a HashVal.
bool detail::MMH3Val::DoUnserialize(const broker::data &data) {
  auto *d = broker::get_if<broker::vector>(data);
  if (!d)
    return false;

  const auto &dv = *d;

  if (dv.size() < 1)
    return false;

  auto *valid = broker::get_if<broker::boolean>(dv[0]);
  if (!valid)
    return false;

  if (!*valid)
    return true; // while the content is invalid, unserializing was
                 // successful.

  if (dv.size() < 4)
    return false;

  auto *d_mmh3_h1 = broker::get_if<broker::count>(dv[1]);
  auto *d_mmh3_carry = broker::get_if<broker::count>(dv[2]);
  auto *d_mmh3_total_len = broker::get_if<broker::count>(dv[3]);

  if (!d_mmh3_h1 || !d_mmh3_carry || !d_mmh3_total_len)
    return false;

  mmh3_h1 = static_cast<uint32_t>(*d_mmh3_h1);
  mmh3_carry = static_cast<uint32_t>(*d_mmh3_carry);
  mmh3_total_len = static_cast<uint32_t>(*d_mmh3_total_len);

  return true;
}

zeek::OpaqueTypePtr detail::MMH3Val::mmh3_type;

void detail::MMH3::InitPostScript() {
  // Find the offset of "mmh3_seed" within AnalyzerArgs (optional).
  auto analyzer_args_type =
      zeek::id::find_type<zeek::RecordType>("Files::AnalyzerArgs");
  detail::MMH3::mmh3_seed_field_offset =
      analyzer_args_type->FieldOffset("mmh3_seed");
  detail::MMH3::kind_val = zeek::make_intrusive<zeek::StringVal>("MMH3");
  detail::MMH3Val::mmh3_type = zeek::make_intrusive<zeek::OpaqueType>("mmh3");
}

// MMH3 32bit hash
class MMH3 : public zeek::file_analysis::detail::Hash {
public:
  static zeek::file_analysis::Analyzer *
  Instantiate(zeek::RecordValPtr arg_args,
              zeek::file_analysis::File *arg_file) {
    return new MMH3(arg_args, arg_file);
  }

  static zeek::StringValPtr kind_val;
  static int mmh3_seed_field_offset;

  // Return value of mmh3_seed if it exists in AnalyzerArgs, else 0.
  static int seed_from_args(zeek::RecordValPtr args) {
    if (mmh3_seed_field_offset < 0)
      return 0;

    return static_cast<int>(
        args->GetFieldOrDefault(mmh3_seed_field_offset)->AsCount());
  }

private:
  MMH3(zeek::RecordValPtr arg_args, zeek::file_analysis::File *arg_file)
      : zeek::file_analysis::detail::Hash(
            arg_args, arg_file,
            new detail::MMH3Val(MMH3::seed_from_args(arg_args)),
            MMH3::kind_val) {}
};

zeek::StringValPtr detail::MMH3::kind_val;
int detail::MMH3::mmh3_seed_field_offset = -1;
