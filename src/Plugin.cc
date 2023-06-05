#include "Plugin.h"

#include "MMH3.h"

#include <zeek/file_analysis/Component.h>

namespace plugin::Zeek_MoreHashes {
Plugin plugin;
}

using namespace plugin::Zeek_MoreHashes;

zeek::plugin::Configuration Plugin::Configure() {
  zeek::plugin::Configuration config;
  config.name = "Zeek::MoreHashes";
  config.description = "More analyzers and built-in functions for hashing.";
  config.version.major = MOREHASHES_VERSION_MAJOR;
  config.version.minor = MOREHASHES_VERSION_MINOR;
  config.version.patch = MOREHASHES_VERSION_PATCH;

  AddComponent(
      new zeek::file_analysis::Component("MMH3", detail::MMH3::Instantiate));

  return config;
}

void Plugin::InitPostScript() { detail::MMH3::InitPostScript(); }
