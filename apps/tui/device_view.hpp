#pragma once

#include <heyaki/node.hpp>

#include <iosfwd>
#include <vector>

namespace heyaki::tui {

void render_device_view(
    std::ostream& output,
    const std::vector<EndpointDirectoryEntrySnapshot>& endpoints,
    const std::vector<NodePeerSessionSnapshot>& sessions);

}  // namespace heyaki::tui
