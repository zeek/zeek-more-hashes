
#include "Plugin.h"

namespace plugin { namespace Zeek_MoreFileHashes { Plugin plugin; } }

using namespace plugin::Zeek_MoreFileHashes;

zeek::plugin::Configuration Plugin::Configure()
	{
	zeek::plugin::Configuration config;
	config.name = "Zeek::MoreFileHashes";
	config.description = "<Insert description>";
	config.version.major = MOREFILEHASHES_VERSION_MAJOR;
	config.version.minor = MOREFILEHASHES_VERSION_MINOR;
	config.version.patch = MOREFILEHASHES_VERSION_PATCH;
	return config;
	}
