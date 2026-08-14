#include <heyaki/protocol.hpp>

#include <algorithm>

namespace heyaki {
namespace {

Result<NegotiatedProtocol> negotiation_error(const char* detail) {
  return Result<NegotiatedProtocol>::failure(Error{ErrorCode::protocol, "negotiation", detail});
}

}  // namespace

Result<NegotiatedProtocol> negotiate_protocol(const ProtocolHello& local,
                                              const ProtocolHello& remote) {
  if (!local.supported.contains(local.required) || !remote.supported.contains(remote.required)) {
    return negotiation_error("invalid_required_capabilities");
  }
  if (local.version.major != remote.version.major) {
    return negotiation_error("incompatible_major_version");
  }
  if (!local.supported.contains(remote.required) || !remote.supported.contains(local.required)) {
    return negotiation_error("required_capability_unavailable");
  }

  return Result<NegotiatedProtocol>::success(
      {.version = {.major = local.version.major,
                   .minor = std::min(local.version.minor, remote.version.minor)},
       .capabilities = {.bits = local.supported.bits & remote.supported.bits}});
}

}  // namespace heyaki
