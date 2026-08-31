#include "fuzz_targets.hpp"

#include <heyaki/operation.hpp>
#include <heyaki/lan_protocol.hpp>
#include <heyaki/protocol.hpp>
#include <heyaki/session_protocol.hpp>
#include <heyaki/signaling_protocol.hpp>
#include <heyaki/frame_stream.hpp>
#include <heyaki/event.hpp>
#include <heyaki/file.hpp>
#include <heyaki/message.hpp>
#include <heyaki/rpc.hpp>
#include <heyaki/pairing_protocol.hpp>
#include <heyaki/trust_grant.hpp>
#include <heyaki/wire.hpp>

#include "heyaki/common/v1/common.pb.h"
#include "heyaki/discovery/v1/discovery.pb.h"
#include "heyaki/enrollment/v1/enrollment.pb.h"
#include "heyaki/event/v1/event.pb.h"
#include "heyaki/file/v1/file.pb.h"
#include "heyaki/message/v1/message.pb.h"
#include "heyaki/pairing/v1/pairing.pb.h"
#include "heyaki/relay/v1/relay_control.pb.h"
#include "heyaki/rpc/v1/rpc.pb.h"
#include "heyaki/session/v1/session.pb.h"
#include "heyaki/shell/v1/shell.pb.h"
#include "heyaki/signaling/v1/signaling.pb.h"
#include "heyaki/signaling/v1/lan.pb.h"
#include "heyaki/stream/v1/stream.pb.h"

#include <algorithm>
#include <cstdlib>
#include <limits>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace heyaki::fuzz {
namespace {

template <typename Message>
void parse_protobuf(std::span<const std::byte> input) {
  Message message;
  if (!message.ParseFromArray(input.data(), static_cast<int>(input.size()))) {
    return;
  }

  const auto encoded = message.SerializeAsString();
  Message reparsed;
  if (!reparsed.ParseFromString(encoded)) {
    std::abort();
  }
  Message third_parse;
  if (!third_parse.ParseFromString(reparsed.SerializeAsString())) {
    std::abort();
  }
}

enum class ProtocolDomain : std::uint8_t {
  enrollment,
  signaling,
  session_pairing,
  message,
  rpc,
  event,
  stream,
  file,
  shell,
  count,
};

std::uint8_t advance_protocol_state(ProtocolDomain domain, std::uint8_t state,
                                    std::uint8_t event) noexcept {
  switch (domain) {
    case ProtocolDomain::enrollment:
      if (event == 0U && state == 0U) {
        return 1U;
      }
      if (event == 1U && state == 1U) {
        return 2U;
      }
      if (event == 2U && state == 2U) {
        return 3U;
      }
      if (event == 3U && state < 3U) {
        return 4U;
      }
      return state;
    case ProtocolDomain::signaling:
      if (event == 0U && state == 0U) {
        return 1U;
      }
      if (event == 1U && state == 1U) {
        return 2U;
      }
      if (event == 2U && (state == 2U || state == 3U)) {
        return 3U;
      }
      if (event == 3U && state < 4U) {
        return 4U;
      }
      if (event == 4U && state < 4U) {
        return 5U;
      }
      return state;
    case ProtocolDomain::session_pairing:
      if (event == 0U && state == 0U) {
        return 1U;
      }
      if (event == 1U && state <= 1U) {
        return 2U;
      }
      if (event == 2U && state <= 1U) {
        return 3U;
      }
      if (event == 3U && state == 2U) {
        return 3U;
      }
      if (event == 4U && state == 3U) {
        return 4U;
      }
      if (event == 5U && state < 5U) {
        return 6U;
      }
      if (event == 6U && state < 5U) {
        return 5U;
      }
      if (event == 7U && state == 1U) {
        return 6U;
      }
      return state;
    case ProtocolDomain::message:
      if (event == 0U && state == 0U) {
        return 1U;
      }
      if (event == 2U && state == 1U) {
        return 2U;
      }
      return state;
    case ProtocolDomain::rpc:
      if (event == 0U && state == 0U) {
        return 1U;
      }
      if (event == 3U && state == 1U) {
        return 2U;
      }
      if (event == 4U && state == 1U) {
        return 3U;
      }
      if (event == 5U && state == 1U) {
        return 4U;
      }
      if (event == 6U && state == 1U) {
        return 5U;
      }
      return state;
    case ProtocolDomain::event:
      if (event == 0U && state == 0U) {
        return 1U;
      }
      if (event == 2U && state == 1U) {
        return 2U;
      }
      if (event == 3U && state == 1U) {
        return 3U;
      }
      return state;
    case ProtocolDomain::stream:
      if (event == 0U && state == 0U) {
        return 1U;
      }
      if (event == 2U && state == 1U) {
        return 2U;
      }
      if ((event == 3U || event == 5U) && (state == 1U || state == 2U)) {
        return 3U;
      }
      if (event == 4U && state == 2U) {
        return 4U;
      }
      return state;
    case ProtocolDomain::file:
      if (event == 0U && state == 0U) {
        return 1U;
      }
      if (event == 1U && state == 1U) {
        return 2U;
      }
      if (event == 2U && state == 1U) {
        return 6U;
      }
      if (event == 4U && state == 2U) {
        return 3U;
      }
      if (event == 5U && state == 3U) {
        return 4U;
      }
      if (event == 6U && (state == 2U || state == 3U)) {
        return 5U;
      }
      return state;
    case ProtocolDomain::shell:
      if (event == 0U && state == 0U) {
        return 1U;
      }
      if (event == 1U && state == 1U) {
        return 2U;
      }
      if (event == 3U && state == 2U) {
        return 3U;
      }
      if (event == 4U && (state == 2U || state == 3U)) {
        return 4U;
      }
      if ((event == 5U && state < 4U) || (event == 6U && state == 3U)) {
        return 5U;
      }
      return state;
    case ProtocolDomain::count:
      return state;
  }
  return state;
}

std::uint8_t maximum_state(ProtocolDomain domain) noexcept {
  switch (domain) {
    case ProtocolDomain::enrollment:
      return 4U;
    case ProtocolDomain::signaling:
      return 5U;
    case ProtocolDomain::session_pairing:
      return 6U;
    case ProtocolDomain::message:
      return 2U;
    case ProtocolDomain::rpc:
      return 5U;
    case ProtocolDomain::event:
      return 3U;
    case ProtocolDomain::stream:
      return 4U;
    case ProtocolDomain::file:
      return 6U;
    case ProtocolDomain::shell:
      return 5U;
    case ProtocolDomain::count:
      return 0U;
  }
  return 0U;
}

bool is_terminal_state(ProtocolDomain domain, std::uint8_t state) noexcept {
  switch (domain) {
    case ProtocolDomain::enrollment:
      return state >= 3U;
    case ProtocolDomain::signaling:
      return state >= 4U;
    case ProtocolDomain::session_pairing:
      return state >= 5U;
    case ProtocolDomain::message:
      return state == 2U;
    case ProtocolDomain::rpc:
      return state >= 2U;
    case ProtocolDomain::event:
      return state >= 2U;
    case ProtocolDomain::stream:
      return state >= 3U;
    case ProtocolDomain::file:
      return state >= 4U;
    case ProtocolDomain::shell:
      return state >= 4U;
    case ProtocolDomain::count:
      return true;
  }
  return true;
}

void operation_lifecycle(std::span<const std::byte> input) {
  OperationStatus current{};
  for (const auto raw : input) {
    const auto byte = std::to_integer<unsigned int>(raw);
    if (current.state != OperationState::pending) {
      if ((byte & 0x80U) == 0U) {
        const auto repeated = transition_operation(current, OperationState::success);
        const bool same_terminal_state = current.state == OperationState::success;
        if (static_cast<bool>(repeated) != same_terminal_state ||
            current.state == OperationState::pending) {
          std::abort();
        }
        continue;
      }
      const auto next_epoch = current.epoch.next();
      if (!next_epoch.has_value()) {
        return;
      }
      current = OperationStatus{.id = current.id,
                                .epoch = *next_epoch,
                                .state = OperationState::pending,
                                .error = std::nullopt};
    }

    const auto next = static_cast<OperationState>((byte % 4U) + 1U);
    std::optional<Error> error;
    if (next == OperationState::error) {
      error = Error{ErrorCode::remote_error, "fuzz", "remote_error"};
    }
    const auto transitioned = transition_operation(current, next, std::move(error));
    if (!transitioned || transitioned.value_if()->state == OperationState::pending ||
        transitioned.value_if()->epoch != current.epoch) {
      std::abort();
    }
    current = *transitioned.value_if();
  }
}

}  // namespace

void frame_parser(std::span<const std::byte> input) {
  const auto parsed = parse_frame(input);
  if (parsed.status != FrameParseStatus::parsed) {
    return;
  }
  if (!parsed.frame.has_value() || parsed.consumed == 0U || parsed.consumed > input.size()) {
    std::abort();
  }

  const auto& view = *parsed.frame;
  Frame owning{.type = view.type,
               .flags = view.flags,
               .channel_id = view.channel_id,
               .message_id = view.message_id,
               .payload = {view.payload.begin(), view.payload.end()}};
  const auto encoded = encode_frame(owning);
  if (!encoded || encoded.value_if()->size() != parsed.consumed ||
      !std::equal(encoded.value_if()->begin(), encoded.value_if()->end(), input.begin())) {
    std::abort();
  }
}

// M5: the incremental decoder must accept exactly what the one-shot parser
// accepts, delivered at arbitrary chunk boundaries, and never crash.
void frame_stream_decoder(std::span<const std::byte> input) {
  FrameStreamDecoder decoder;
  if (!decoder.append(input)) return;
  while (true) {
    auto step = decoder.next_view();
    if (step.status == FrameStreamStatus::invalid) return;
    if (step.status == FrameStreamStatus::need_more) return;
    if (!decoder.consume_view()) return;
  }
}

void pairing_request_parser(std::span<const std::byte> input) {
  const auto parsed = parse_pairing_request(input);
  if (!parsed) return;
  const auto encoded = encode_pairing_request(*parsed.value_if());
  if (!encoded) std::abort();
  const auto reparsed = parse_pairing_request(*encoded.value_if());
  if (!reparsed) std::abort();
}

void trust_grant_parser(std::span<const std::byte> input) {
  const auto parsed = parse_signed_trust_grant(input);
  if (!parsed) return;
  const auto encoded = encode_signed_trust_grant(*parsed.value_if());
  if (!encoded) std::abort();
}

void lan_datagram_parser(std::span<const std::byte> input) {
  const auto parsed = parse_lan_datagram(input);
  if (parsed.status != LanDatagramParseStatus::parsed) {
    return;
  }
  if (!parsed.datagram.has_value()) {
    std::abort();
  }
  const auto encoded = encode_lan_datagram(parsed.datagram->type, parsed.datagram->payload);
  if (!encoded || encoded.value_if()->size() != input.size() ||
      !std::equal(encoded.value_if()->begin(), encoded.value_if()->end(), input.begin())) {
    std::abort();
  }
}

void lan_hello_parser(std::span<const std::byte> input) {
  const auto parsed = parse_lan_hello(input);
  if (!parsed) {
    return;
  }
  const auto encoded = encode_lan_hello(*parsed.value_if());
  if (!encoded || encoded.value_if()->size() != input.size() ||
      !std::equal(encoded.value_if()->begin(), encoded.value_if()->end(),
                  input.begin())) {
    std::abort();
  }
}

void lan_presence_parser(std::span<const std::byte> input) {
  const auto parsed = parse_lan_presence(input);
  if (!parsed) {
    return;
  }
  const auto encoded = encode_lan_presence(*parsed.value_if());
  if (!encoded || encoded.value_if()->size() != input.size() ||
      !std::equal(encoded.value_if()->begin(), encoded.value_if()->end(), input.begin())) {
    std::abort();
  }
}

void signed_offer_parser(std::span<const std::byte> input) {
  const auto parsed = parse_signed_offer(input);
  if (!parsed) {
    return;
  }
  const auto encoded = encode_signed_offer(*parsed.value_if());
  if (!encoded || encoded.value_if()->size() != input.size() ||
      !std::equal(encoded.value_if()->begin(), encoded.value_if()->end(),
                  input.begin())) {
    std::abort();
  }
}

void signed_answer_parser(std::span<const std::byte> input) {
  const auto parsed = parse_signed_answer(input);
  if (!parsed) {
    return;
  }
  const auto encoded = encode_signed_answer(*parsed.value_if());
  if (!encoded || encoded.value_if()->size() != input.size() ||
      !std::equal(encoded.value_if()->begin(), encoded.value_if()->end(),
                  input.begin())) {
    std::abort();
  }
}

void signed_candidate_parser(std::span<const std::byte> input) {
  const auto parsed = parse_signed_candidate(input);
  if (!parsed) {
    return;
  }
  const auto encoded = encode_signed_candidate(*parsed.value_if());
  if (!encoded || encoded.value_if()->size() != input.size() ||
      !std::equal(encoded.value_if()->begin(), encoded.value_if()->end(),
                  input.begin())) {
    std::abort();
  }
}

void signed_session_hello_parser(std::span<const std::byte> input) {
  const auto parsed = parse_signed_session_hello(input);
  if (!parsed) {
    return;
  }
  const auto encoded = encode_signed_session_hello(*parsed.value_if());
  if (!encoded || encoded.value_if()->size() != input.size() ||
      !std::equal(encoded.value_if()->begin(), encoded.value_if()->end(),
                  input.begin())) {
    std::abort();
  }
}

void lan_signaling_frame_parser(std::span<const std::byte> input) {
  const auto parsed = parse_lan_signaling_frame(input);
  if (!parsed) {
    return;
  }
  const auto encoded = encode_lan_signaling_frame(*parsed.value_if());
  if (!encoded || encoded.value_if()->size() != input.size() ||
      !std::equal(encoded.value_if()->begin(), encoded.value_if()->end(),
                  input.begin())) {
    std::abort();
  }
}

void m6_service_payload_parser(std::span<const std::byte> input) {
  // M6 message/RPC payload parsers: every accepted body must re-encode and
  // re-parse successfully (round-trip property).
  const auto envelope = parse_message_envelope(input);
  if (envelope) {
    const auto encoded = encode_message_envelope(*envelope.value_if());
    if (!encoded) std::abort();
    if (!parse_message_envelope(*encoded.value_if())) std::abort();
  }
  const auto ack = parse_message_ack(input);
  if (ack) {
    const auto encoded = encode_message_ack(*ack.value_if());
    if (!encoded) std::abort();
    if (!parse_message_ack(*encoded.value_if())) std::abort();
  }
  const auto request = parse_rpc_request(input);
  if (request) {
    const auto encoded = encode_rpc_request(*request.value_if());
    if (!encoded) std::abort();
    if (!parse_rpc_request(*encoded.value_if())) std::abort();
  }
  const auto response = parse_rpc_response(input);
  if (response) {
    const auto encoded = encode_rpc_response(*response.value_if());
    if (!encoded) std::abort();
    if (!parse_rpc_response(*encoded.value_if())) std::abort();
  }
  const auto cancel = parse_rpc_cancel(input);
  if (cancel) {
    const auto encoded = encode_rpc_cancel(*cancel.value_if());
    if (!encoded) std::abort();
    if (!parse_rpc_cancel(*encoded.value_if())) std::abort();
  }
}

void m7_service_payload_parser(std::span<const std::byte> input) {
  // M7 event/file payload parsers: every accepted body must re-encode and
  // re-parse successfully (round-trip property), including the raw 60-byte
  // FileChunk header layout.
  const auto subscribe = parse_event_subscribe(input);
  if (subscribe) {
    const auto encoded = encode_event_subscribe(*subscribe.value_if());
    if (!encoded) std::abort();
    if (!parse_event_subscribe(*encoded.value_if())) std::abort();
  }
  const auto item = parse_event_item(input);
  if (item) {
    const auto encoded = encode_event_item(*item.value_if());
    if (!encoded) std::abort();
    if (!parse_event_item(*encoded.value_if())) std::abort();
  }
  const auto unsubscribe = parse_event_unsubscribe(input);
  if (unsubscribe) {
    const auto encoded = encode_event_unsubscribe(*unsubscribe.value_if());
    if (!encoded) std::abort();
    if (!parse_event_unsubscribe(*encoded.value_if())) std::abort();
  }
  const auto manifest = parse_file_manifest(input);
  if (manifest) {
    const auto encoded = encode_file_manifest(*manifest.value_if());
    if (!encoded) std::abort();
    if (!parse_file_manifest(*encoded.value_if())) std::abort();
  }
  const auto accept = parse_file_accept(input);
  if (accept) {
    const auto encoded = encode_file_accept(*accept.value_if());
    if (!encoded) std::abort();
    if (!parse_file_accept(*encoded.value_if())) std::abort();
  }
  const auto reject = parse_file_reject(input);
  if (reject) {
    const auto encoded = encode_file_reject(*reject.value_if());
    if (!encoded) std::abort();
    if (!parse_file_reject(*encoded.value_if())) std::abort();
  }
  const auto complete = parse_file_complete(input);
  if (complete) {
    const auto encoded = encode_file_complete(*complete.value_if());
    if (!encoded) std::abort();
    if (!parse_file_complete(*encoded.value_if())) std::abort();
  }
  const auto pull = parse_file_pull_request(input);
  if (pull) {
    const auto encoded = encode_file_pull_request(*pull.value_if());
    if (!encoded) std::abort();
    if (!parse_file_pull_request(*encoded.value_if())) std::abort();
  }
  const auto chunk = parse_file_chunk(input);
  if (chunk) {
    // The data span aliases the input; the header must round-trip.
    const auto encoded = encode_file_chunk(chunk.value_if()->header, chunk.value_if()->data);
    if (encoded.size() != input.size()) std::abort();
    if (!parse_file_chunk(encoded)) std::abort();
  }
}

void protobuf_schema_parser(std::span<const std::byte> input) {
  if (input.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
    return;
  }
  parse_protobuf<protocol::common::v1::ProtocolVersion>(input);
  parse_protobuf<protocol::common::v1::CapabilityAdvertisement>(input);
  parse_protobuf<protocol::common::v1::DeviceEndpoint>(input);
  parse_protobuf<protocol::common::v1::Signature>(input);
  parse_protobuf<protocol::common::v1::RelativeDeadline>(input);
  parse_protobuf<protocol::discovery::v1::LanPresence>(input);
  parse_protobuf<protocol::enrollment::v1::EnrollmentChallenge>(input);
  parse_protobuf<protocol::enrollment::v1::EnrollmentRequest>(input);
  parse_protobuf<protocol::enrollment::v1::EnrollmentResult>(input);
  parse_protobuf<protocol::enrollment::v1::ControlError>(input);
  parse_protobuf<protocol::enrollment::v1::EnrollmentRecord>(input);
  parse_protobuf<protocol::enrollment::v1::EndpointRecord>(input);
  parse_protobuf<protocol::enrollment::v1::ServiceManifest>(input);
  parse_protobuf<protocol::relay::v1::LoginResult>(input);
  parse_protobuf<protocol::relay::v1::HeartbeatRequest>(input);
  parse_protobuf<protocol::relay::v1::HeartbeatAck>(input);
  parse_protobuf<protocol::relay::v1::EndpointPublish>(input);
  parse_protobuf<protocol::relay::v1::EndpointPublishAck>(input);
  parse_protobuf<protocol::relay::v1::EndpointQuery>(input);
  parse_protobuf<protocol::relay::v1::EndpointPublication>(input);
  parse_protobuf<protocol::relay::v1::EndpointQueryResult>(input);
  parse_protobuf<protocol::signaling::v1::SignalBinding>(input);
  parse_protobuf<protocol::signaling::v1::SignedOffer>(input);
  parse_protobuf<protocol::signaling::v1::SignedAnswer>(input);
  parse_protobuf<protocol::signaling::v1::SignedCandidate>(input);
  parse_protobuf<protocol::signaling::v1::LanHello>(input);
  parse_protobuf<protocol::session::v1::SessionHello>(input);
  parse_protobuf<protocol::session::v1::SessionClose>(input);
  parse_protobuf<protocol::pairing::v1::PairingRequest>(input);
  parse_protobuf<protocol::pairing::v1::TrustGrant>(input);
  parse_protobuf<protocol::pairing::v1::PairingResult>(input);
  parse_protobuf<protocol::message::v1::MessageEnvelope>(input);
  parse_protobuf<protocol::message::v1::MessageAck>(input);
  parse_protobuf<protocol::rpc::v1::RpcRequest>(input);
  parse_protobuf<protocol::rpc::v1::RpcResponse>(input);
  parse_protobuf<protocol::rpc::v1::RpcCancel>(input);
  parse_protobuf<protocol::event::v1::EventSubscribe>(input);
  parse_protobuf<protocol::event::v1::EventItem>(input);
  parse_protobuf<protocol::event::v1::EventUnsubscribe>(input);
  parse_protobuf<protocol::stream::v1::StreamOpen>(input);
  parse_protobuf<protocol::stream::v1::WindowUpdate>(input);
  parse_protobuf<protocol::stream::v1::StreamFinish>(input);
  parse_protobuf<protocol::stream::v1::StreamReset>(input);
  parse_protobuf<protocol::file::v1::FileManifest>(input);
  parse_protobuf<protocol::file::v1::FileAccept>(input);
  parse_protobuf<protocol::file::v1::FileReject>(input);
  parse_protobuf<protocol::file::v1::FileComplete>(input);
  parse_protobuf<protocol::shell::v1::ShellOpen>(input);
  parse_protobuf<protocol::shell::v1::ShellResize>(input);
  parse_protobuf<protocol::shell::v1::ShellSignal>(input);
  parse_protobuf<protocol::shell::v1::ShellExit>(input);
  parse_protobuf<protocol::shell::v1::ShellEof>(input);
  parse_protobuf<protocol::shell::v1::ShellError>(input);
  parse_protobuf<protocol::shell::v1::ShellClose>(input);
}

void protocol_state_machines(std::span<const std::byte> input) {
  operation_lifecycle(input);
  if (input.empty()) {
    return;
  }

  const auto domain = static_cast<ProtocolDomain>(
      std::to_integer<std::uint8_t>(input.front()) %
      static_cast<std::uint8_t>(ProtocolDomain::count));
  std::uint8_t state = 0U;
  bool terminal = false;
  for (const auto raw : input.subspan(1U)) {
    const auto next = advance_protocol_state(
        domain, state, std::to_integer<std::uint8_t>(raw) % 8U);
    if (next > maximum_state(domain) || (terminal && next != state)) {
      std::abort();
    }
    state = next;
    terminal = is_terminal_state(domain, state);
  }
}

}  // namespace heyaki::fuzz
