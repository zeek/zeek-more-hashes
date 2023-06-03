
#pragma once

#include <zeek/plugin/Plugin.h>

#include "config.h"

namespace plugin {
namespace Zeek_MoreFileHashes {

class Plugin : public zeek::plugin::Plugin
{
protected:
	// Overridden from zeek::plugin::Plugin.
	zeek::plugin::Configuration Configure() override;
};

extern Plugin plugin;

}
}
