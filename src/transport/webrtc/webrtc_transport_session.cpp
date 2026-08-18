#include "webrtc_transport_session.hpp"

#include <heyaki/signaling_protocol.hpp>

#include <executor/comm.hpp>

#include <rtc/candidate.hpp>
#include <rtc/configuration.hpp>
#include <rtc/datachannel.hpp>
#include <rtc/description.hpp>
#include <rtc/peerconnection.hpp>

#include <algorithm>
#include <atomic>
#include <limits>
#include <map>
#include <string>
#include <utility>
#include <variant>

namespace heyaki::transport::webrtc {
namespace {

Error transport_error(ErrorCode code, const char* detail) {
  return Error{code, "webrtc_transport", detail};
}

executor::comm::ChannelOptions callback_options(std::size_t capacity) {
  executor::comm::ChannelOptions options;
  options.capacity = capacity;
  options.drop_policy = executor::comm::DropPolicy::RejectNewest;
  options.name = "heyaki-webrtc-callbacks";
  return options;
}

bool valid_config(const WebRtcTransportConfig& config) noexcept {
  if (config.callback_capacity == 0U || config.channel_capacity == 0U ||
      config.channel_message_capacity == 0U || config.maximum_message_bytes == 0U ||
      config.buffered_amount_low_water >= config.buffered_amount_high_water ||
      config.buffered_amount_high_water > config.maximum_message_bytes * 64U) {
    return false;
  }
  if ((!config.candidates.allow_ipv4_host && !config.candidates.allow_ipv6_host &&
       !config.candidates.allow_server_reflexive && !config.candidates.allow_turn_udp &&
       !config.candidates.allow_turn_tcp && !config.candidates.allow_turn_tls) ||
      ((config.candidates.allow_turn_tcp || config.candidates.allow_turn_tls) &&
       !config.tcp_turn_backend_verified)) {
    return false;
  }
  return std::all_of(config.ice_servers.begin(), config.ice_servers.end(),
                     [](const IceServerConfig& server) {
                       if (server.hostname.empty() || server.port == 0U) {
                         return false;
                       }
                       return server.kind == IceServerKind::stun ||
                              (!server.username.empty() && !server.credential.empty());
                     });
}

std::string label_for(ChannelKind kind) {
  switch (kind) {
    case ChannelKind::control:
      return "heyaki.control.v1";
    case ChannelKind::pairing:
      return "heyaki.pairing.v1";
    case ChannelKind::message:
      return "heyaki.message.v1";
    case ChannelKind::rpc:
      return "heyaki.rpc.v1";
    case ChannelKind::event:
      return "heyaki.event.v1";
    case ChannelKind::file:
      return "heyaki.file.v1";
    case ChannelKind::shell:
      return "heyaki.shell.v1";
  }
  return "heyaki.unknown.v1";
}

std::optional<ChannelKind> kind_for(std::string_view label) {
  for (const auto kind : {ChannelKind::control, ChannelKind::pairing,
                          ChannelKind::message, ChannelKind::rpc, ChannelKind::event,
                          ChannelKind::file, ChannelKind::shell}) {
    if (label_for(kind) == label) {
      return kind;
    }
  }
  return std::nullopt;
}

rtc::Configuration rtc_config(const WebRtcTransportConfig& config) {
  rtc::Configuration output;
  output.maxMessageSize = config.maximum_message_bytes;
  output.iceTransportPolicy = config.candidates.relay_only
                                  ? rtc::TransportPolicy::Relay
                                  : rtc::TransportPolicy::All;
  output.enableIceTcp = config.tcp_turn_backend_verified &&
                        (config.candidates.allow_turn_tcp ||
                         config.candidates.allow_turn_tls);
  for (const auto& server : config.ice_servers) {
    switch (server.kind) {
      case IceServerKind::stun:
        output.iceServers.emplace_back(server.hostname, server.port);
        break;
      case IceServerKind::turn_udp:
        output.iceServers.emplace_back(server.hostname, server.port, server.username,
                                       server.credential,
                                       rtc::IceServer::RelayType::TurnUdp);
        break;
      case IceServerKind::turn_tcp:
        output.iceServers.emplace_back(server.hostname, server.port, server.username,
                                       server.credential,
                                       rtc::IceServer::RelayType::TurnTcp);
        break;
      case IceServerKind::turn_tls:
        output.iceServers.emplace_back(server.hostname, server.port, server.username,
                                       server.credential,
                                       rtc::IceServer::RelayType::TurnTls);
        break;
    }
  }
  return output;
}

bool candidate_allowed(const rtc::Candidate& candidate,
                       const CandidatePolicy& policy) noexcept {
  switch (candidate.type()) {
    case rtc::Candidate::Type::Host:
      return candidate.family() == rtc::Candidate::Family::Ipv6
                 ? policy.allow_ipv6_host
                 : policy.allow_ipv4_host;
    case rtc::Candidate::Type::ServerReflexive:
    case rtc::Candidate::Type::PeerReflexive:
      return policy.allow_server_reflexive;
    case rtc::Candidate::Type::Relayed:
      return candidate.transportType() == rtc::Candidate::TransportType::Udp
                 ? policy.allow_turn_udp
                 : (policy.allow_turn_tcp || policy.allow_turn_tls);
    case rtc::Candidate::Type::Unknown:
      return false;
  }
  return false;
}

}  // namespace

class WebRtcTransportSession::Impl
    : public std::enable_shared_from_this<WebRtcTransportSession::Impl> {
 public:
  class Channel final : public TransportChannel,
                        public std::enable_shared_from_this<Channel> {
   public:
    Channel(std::weak_ptr<Impl> owner, ChannelKind kind, ChannelOptions options,
            std::shared_ptr<rtc::DataChannel> channel)
        : owner_(std::move(owner)), kind_(kind), options_(std::move(options)),
          channel_(std::move(channel)) {}

    ChannelKind kind() const noexcept override { return kind_; }
    const ChannelOptions& options() const noexcept override { return options_; }

    Result<void> send(std::span<const std::byte> payload) override {
      auto owner = owner_.lock();
      if (!owner || closed_.load(std::memory_order_acquire)) {
        return Result<void>::failure(transport_error(ErrorCode::cancelled,
                                                     "channel_closed"));
      }
      if (payload.empty() || payload.size() > options_.max_message_bytes ||
          payload.size() > channel_->maxMessageSize()) {
        ++owner->messages_rejected_;
        return Result<void>::failure(transport_error(ErrorCode::protocol,
                                                     "message_size_invalid"));
      }
      const auto buffered = channel_->bufferedAmount();
      if (buffered == 0U) {
        queued_messages_.store(0U, std::memory_order_release);
      }
      const auto byte_limit =
          std::min(options_.send_queue_bytes, owner->config_.buffered_amount_high_water);
      const auto queued_messages = queued_messages_.load(std::memory_order_relaxed);
      if (buffered > byte_limit || payload.size() > byte_limit - buffered ||
          queued_messages >= owner->config_.channel_message_capacity) {
        ++owner->sends_would_block_;
        return Result<void>::failure(transport_error(ErrorCode::would_block,
                                                     "channel_high_water"));
      }
      try {
        const auto* bytes = reinterpret_cast<const rtc::byte*>(payload.data());
        (void)channel_->send(bytes, payload.size());
      } catch (...) {
        return Result<void>::failure(transport_error(ErrorCode::transport,
                                                     "channel_send_failed"));
      }
      queued_messages_.fetch_add(1U, std::memory_order_relaxed);
      return Result<void>::success();
    }

    std::size_t buffered_amount() const noexcept override {
      try {
        return channel_->bufferedAmount();
      } catch (...) {
        return 0U;
      }
    }

    void close(CloseReason /*reason*/) override {
      if (!closed_.exchange(true, std::memory_order_acq_rel)) {
        channel_->resetCallbacks();
        channel_->close();
      }
    }

    void buffered_low() noexcept {
      queued_messages_.store(0U, std::memory_order_release);
    }

    std::shared_ptr<rtc::DataChannel> rtc_channel() const { return channel_; }

   private:
    std::weak_ptr<Impl> owner_;
    ChannelKind kind_;
    ChannelOptions options_;
    std::shared_ptr<rtc::DataChannel> channel_;
    std::atomic<std::size_t> queued_messages_{0U};
    std::atomic<bool> closed_{false};
  };

  struct LocalDescriptionEvent {
    std::vector<std::byte> sdp;
    std::string type;
  };
  struct LocalCandidateEvent {
    std::vector<std::byte> candidate;
  };
  struct PeerStateEvent {
    rtc::PeerConnection::State state;
  };
  struct IceStateEvent {
    rtc::PeerConnection::IceState state;
  };
  struct GatheringEvent {
    rtc::PeerConnection::GatheringState state;
  };
  struct IncomingChannelEvent {
    std::shared_ptr<rtc::DataChannel> channel;
  };
  struct OpenEvent {
    std::shared_ptr<Channel> channel;
  };
  struct MessageEvent {
    std::shared_ptr<Channel> channel;
    std::vector<std::byte> payload;
  };
  struct ChannelErrorEvent {
    std::shared_ptr<Channel> channel;
    std::string detail;
  };
  struct ChannelClosedEvent {
    std::shared_ptr<Channel> channel;
  };
  struct BufferedLowEvent {
    std::shared_ptr<Channel> channel;
  };
  using Event = std::variant<LocalDescriptionEvent, LocalCandidateEvent, PeerStateEvent,
                             IceStateEvent, GatheringEvent, IncomingChannelEvent,
                             OpenEvent, MessageEvent, ChannelErrorEvent,
                             ChannelClosedEvent, BufferedLowEvent>;

  Impl(WebRtcTransportConfig config, RuntimeDispatcher dispatcher,
       WebRtcSignalingHandler signaling)
      : config_(std::move(config)), dispatcher_(std::move(dispatcher)),
        signaling_(std::move(signaling)), events_(callback_options(config_.callback_capacity)),
        snapshots_(TransportSessionSnapshot{}, "heyaki-webrtc-snapshot") {
    path_.signaling_path = config_.signaling_path;
  }

  Result<void> initialize() {
    try {
      peer_ = std::make_shared<rtc::PeerConnection>(rtc_config(config_));
    } catch (...) {
      return Result<void>::failure(transport_error(ErrorCode::configuration,
                                                   "peer_connection_create_failed"));
    }
    auto weak = weak_from_this();
    peer_->onLocalDescription([weak](rtc::Description description) {
      if (auto self = weak.lock()) {
        const auto text = description.generateSdp();
        self->enqueue(LocalDescriptionEvent{
            std::vector<std::byte>{reinterpret_cast<const std::byte*>(text.data()),
                                   reinterpret_cast<const std::byte*>(text.data()) +
                                       text.size()},
            description.typeString()});
      }
    });
    peer_->onLocalCandidate([weak](rtc::Candidate candidate) {
      if (auto self = weak.lock(); self && candidate_allowed(candidate, self->config_.candidates)) {
        const auto text = candidate.candidate();
        self->enqueue(LocalCandidateEvent{
            std::vector<std::byte>{reinterpret_cast<const std::byte*>(text.data()),
                                   reinterpret_cast<const std::byte*>(text.data()) +
                                       text.size()}});
      }
    });
    peer_->onStateChange([weak](rtc::PeerConnection::State state) {
      if (auto self = weak.lock()) self->enqueue(PeerStateEvent{state});
    });
    peer_->onIceStateChange([weak](rtc::PeerConnection::IceState state) {
      if (auto self = weak.lock()) self->enqueue(IceStateEvent{state});
    });
    peer_->onGatheringStateChange([weak](rtc::PeerConnection::GatheringState state) {
      if (auto self = weak.lock()) self->enqueue(GatheringEvent{state});
    });
    peer_->onDataChannel([weak](std::shared_ptr<rtc::DataChannel> channel) {
      if (auto self = weak.lock()) self->enqueue(IncomingChannelEvent{std::move(channel)});
    });
    update_snapshot(TransportState::new_session);
    return Result<void>::success();
  }

  void enqueue(Event event) noexcept {
    if (closed_.load(std::memory_order_acquire)) return;
    if (!events_.try_send(std::move(event))) {
      ++callbacks_rejected_;
      callback_overflowed_.store(true, std::memory_order_release);
      return;
    }
    ++callbacks_enqueued_;
    schedule_drain();
  }

  void schedule_drain() noexcept {
    bool expected = false;
    if (!drain_scheduled_.compare_exchange_strong(expected, true,
                                                   std::memory_order_acq_rel)) {
      return;
    }
    auto weak = weak_from_this();
    auto dispatched = dispatcher_("webrtc-callback-drain", [weak] {
      if (auto self = weak.lock()) return self->drain();
      return Result<void>::success();
    });
    if (!dispatched) {
      drain_scheduled_.store(false, std::memory_order_release);
      ++callback_dispatch_rejected_;
      callback_overflowed_.store(true, std::memory_order_release);
    }
  }

  Result<void> drain() {
    Event event;
    while (events_.try_receive(event)) {
      ++callbacks_dispatched_;
      std::visit([this](auto& item) { handle(item); }, event);
    }
    drain_scheduled_.store(false, std::memory_order_release);
    if (!events_.is_drained()) schedule_drain();
    if (callback_overflowed_.exchange(false, std::memory_order_acq_rel)) {
      fail(transport_error(ErrorCode::resource_exhausted,
                           "callback_delivery_rejected"));
      return Result<void>::failure(transport_error(ErrorCode::resource_exhausted,
                                                   "callback_delivery_rejected"));
    }
    return Result<void>::success();
  }

  void handle(LocalDescriptionEvent& event) {
    if (signaling_.on_local_description) {
      signaling_.on_local_description(std::move(event.sdp), std::move(event.type));
    }
  }
  void handle(LocalCandidateEvent& event) {
    if (signaling_.on_local_candidate) {
      signaling_.on_local_candidate(std::move(event.candidate));
    }
  }
  void handle(PeerStateEvent& event) {
    switch (event.state) {
      case rtc::PeerConnection::State::New:
        update_snapshot(TransportState::new_session);
        break;
      case rtc::PeerConnection::State::Connecting:
        update_snapshot(TransportState::checking);
        break;
      case rtc::PeerConnection::State::Connected:
        update_selected_path();
        update_snapshot(TransportState::connected);
        break;
      case rtc::PeerConnection::State::Disconnected:
      case rtc::PeerConnection::State::Failed:
        fail(transport_error(ErrorCode::transport, "peer_connection_failed"));
        break;
      case rtc::PeerConnection::State::Closed:
        update_snapshot(TransportState::closed);
        break;
    }
  }
  void handle(IceStateEvent& event) {
    if (event.state == rtc::PeerConnection::IceState::Checking) {
      update_snapshot(TransportState::checking);
    } else if (event.state == rtc::PeerConnection::IceState::Failed ||
               event.state == rtc::PeerConnection::IceState::Disconnected) {
      fail(transport_error(ErrorCode::nat_traversal, "ice_failed"));
    }
  }
  void handle(GatheringEvent& event) {
    if (event.state == rtc::PeerConnection::GatheringState::InProgress) {
      update_snapshot(TransportState::gathering);
    }
  }
  void handle(IncomingChannelEvent& event) {
    const auto kind = kind_for(event.channel->label());
    if (!kind || channels_.size() >= config_.channel_capacity) {
      ++channels_rejected_;
      event.channel->close();
      return;
    }
    ChannelOptions options;
    options.reliability = event.channel->reliability().maxPacketLifeTime ||
                                  event.channel->reliability().maxRetransmits
                              ? Reliability::unreliable
                              : Reliability::reliable;
    options.ordering = event.channel->reliability().unordered ? Ordering::unordered
                                                               : Ordering::ordered;
    options.max_message_bytes =
        std::min(config_.maximum_message_bytes, event.channel->maxMessageSize());
    attach_channel(*kind, std::move(options), std::move(event.channel));
  }
  void handle(OpenEvent& event) {
    ++channels_opened_;
    const auto pending = pending_opens_.find(event.channel->kind());
    if (pending != pending_opens_.end()) {
      auto completion = std::move(pending->second);
      pending_opens_.erase(pending);
      completion(Result<TransportChannel*>::success(event.channel.get()));
    }
  }
  void handle(MessageEvent& event) {
    if (message_handler_) message_handler_(*event.channel, std::move(event.payload));
  }
  void handle(ChannelErrorEvent& event) {
    fail_pending_open(event.channel->kind(), ErrorCode::transport,
                      "channel_open_failed");
    fail(Error{ErrorCode::transport, "webrtc_data_channel", event.detail});
  }
  void handle(ChannelClosedEvent& event) {
    fail_pending_open(event.channel->kind(), ErrorCode::cancelled,
                      "channel_closed_before_open");
    event.channel->buffered_low();
  }
  void handle(BufferedLowEvent& event) {
    event.channel->buffered_low();
    update_snapshot(snapshot().state);
  }

  std::shared_ptr<Channel> attach_channel(ChannelKind kind, ChannelOptions options,
                                          std::shared_ptr<rtc::DataChannel> rtc_channel) {
    auto channel = std::make_shared<Channel>(weak_from_this(), kind, std::move(options),
                                             std::move(rtc_channel));
    auto weak = weak_from_this();
    std::weak_ptr<Channel> weak_channel = channel;
    const auto low_water = std::min(config_.buffered_amount_low_water,
                                    channel->options().send_queue_bytes / 2U);
    channel->rtc_channel()->setBufferedAmountLowThreshold(low_water);
    channel->rtc_channel()->onOpen([weak, weak_channel] {
      if (auto self = weak.lock(); self) {
        if (auto current = weak_channel.lock()) self->enqueue(OpenEvent{std::move(current)});
      }
    });
    channel->rtc_channel()->onMessage([weak, weak_channel](rtc::binary data) {
      if (auto self = weak.lock(); self) {
        if (auto current = weak_channel.lock()) {
          std::vector<std::byte> payload(data.size());
          std::transform(data.begin(), data.end(), payload.begin(),
                         [](rtc::byte value) { return static_cast<std::byte>(value); });
          if (payload.size() > current->options().max_message_bytes) {
            ++self->messages_rejected_;
            current->close(CloseReason::protocol_error);
            return;
          }
          self->enqueue(MessageEvent{std::move(current), std::move(payload)});
        }
      }
    }, [weak, weak_channel](std::string) {
      if (auto self = weak.lock(); self) {
        if (auto current = weak_channel.lock()) {
          self->enqueue(ChannelErrorEvent{std::move(current), "text_message_rejected"});
        }
      }
    });
    channel->rtc_channel()->onError([weak, weak_channel](std::string detail) {
      if (auto self = weak.lock(); self) {
        if (auto current = weak_channel.lock()) {
          self->enqueue(ChannelErrorEvent{std::move(current), std::move(detail)});
        }
      }
    });
    channel->rtc_channel()->onClosed([weak, weak_channel] {
      if (auto self = weak.lock(); self) {
        if (auto current = weak_channel.lock()) {
          self->enqueue(ChannelClosedEvent{std::move(current)});
        }
      }
    });
    channel->rtc_channel()->onBufferedAmountLow([weak, weak_channel] {
      if (auto self = weak.lock(); self) {
        if (auto current = weak_channel.lock()) {
          self->enqueue(BufferedLowEvent{std::move(current)});
        }
      }
    });
    channels_.emplace(kind, channel);
    return channel;
  }

  void update_selected_path() {
    rtc::Candidate local;
    rtc::Candidate remote;
    if (!peer_->getSelectedCandidatePair(&local, &remote)) return;
    path_.selected_candidate = local.candidate();
    if (path_.selected_candidate.size() > 512U) path_.selected_candidate.resize(512U);
    if (local.type() == rtc::Candidate::Type::Relayed) {
      if (local.transportType() == rtc::Candidate::TransportType::Udp) {
        path_.data_path = DataPathKind::turn_udp;
      } else if (config_.candidates.allow_turn_tls &&
                 !config_.candidates.allow_turn_tcp) {
        path_.data_path = DataPathKind::turn_tls;
      } else {
        path_.data_path = DataPathKind::turn_tcp;
      }
    } else if (local.type() == rtc::Candidate::Type::ServerReflexive ||
               local.type() == rtc::Candidate::Type::PeerReflexive) {
      path_.data_path = DataPathKind::direct_srflx;
    } else {
      path_.data_path = DataPathKind::direct_host;
    }
    path_.rtt = peer_->rtt().value_or(std::chrono::milliseconds{});
  }

  TransportSessionSnapshot snapshot() const noexcept { return snapshots_.load().value; }

  void update_snapshot(TransportState state, std::optional<Error> error = std::nullopt) {
    TransportSessionSnapshot next;
    next.state = state;
    next.path = path_;
    next.error = std::move(error);
    for (const auto& [kind, channel] : channels_) {
      (void)kind;
      next.buffered_amount += channel->buffered_amount();
    }
    snapshots_.publish(next);
    if (state_handler_) state_handler_(next);
  }

  void fail(Error error) {
    update_snapshot(TransportState::failed, error);
    if (peer_) peer_->close();
  }

  void fail_pending_open(ChannelKind kind, ErrorCode code, const char* detail) {
    const auto pending = pending_opens_.find(kind);
    if (pending == pending_opens_.end()) {
      return;
    }
    auto completion = std::move(pending->second);
    pending_opens_.erase(pending);
    completion(Result<TransportChannel*>::failure(transport_error(code, detail)));
  }

  void open_channel(ChannelKind kind, ChannelOptions options,
                    OpenCompletion completion) {
    if (channels_.contains(kind) || channels_.size() >= config_.channel_capacity ||
        options.send_queue_bytes == 0U || options.max_message_bytes == 0U ||
        options.max_message_bytes > config_.maximum_message_bytes) {
      ++channels_rejected_;
      completion(Result<TransportChannel*>::failure(
          transport_error(ErrorCode::resource_exhausted,
                          "channel_admission_rejected")));
      return;
    }
    try {
      rtc::DataChannelInit init;
      init.reliability.unordered = options.ordering == Ordering::unordered;
      if (options.reliability == Reliability::unreliable) {
        init.reliability.maxRetransmits = 0U;
      }
      pending_opens_.emplace(kind, std::move(completion));
      auto rtc_channel = peer_->createDataChannel(label_for(kind), std::move(init));
      (void)attach_channel(kind, std::move(options), std::move(rtc_channel));
    } catch (...) {
      ++channels_rejected_;
      fail_pending_open(kind, ErrorCode::transport, "channel_create_failed");
    }
  }

  WebRtcTransportConfig config_;
  RuntimeDispatcher dispatcher_;
  WebRtcSignalingHandler signaling_;
  std::shared_ptr<rtc::PeerConnection> peer_;
  executor::comm::MpscChannel<Event> events_;
  executor::comm::DoubleBuffer<TransportSessionSnapshot> snapshots_;
  std::map<ChannelKind, std::shared_ptr<Channel>> channels_;
  std::map<ChannelKind, OpenCompletion> pending_opens_;
  MessageHandler message_handler_;
  StateHandler state_handler_;
  PathInfo path_;
  std::atomic<bool> drain_scheduled_{false};
  std::atomic<bool> callback_overflowed_{false};
  std::atomic<bool> closed_{false};
  std::atomic<std::uint64_t> callbacks_enqueued_{0U};
  std::atomic<std::uint64_t> callbacks_dispatched_{0U};
  std::atomic<std::uint64_t> callbacks_rejected_{0U};
  std::atomic<std::uint64_t> callback_dispatch_rejected_{0U};
  std::atomic<std::uint64_t> messages_rejected_{0U};
  std::atomic<std::uint64_t> sends_would_block_{0U};
  std::atomic<std::uint64_t> channels_opened_{0U};
  std::atomic<std::uint64_t> channels_rejected_{0U};
  std::atomic<std::uint64_t> ice_restarts_{0U};
};

Result<std::shared_ptr<WebRtcTransportSession>> WebRtcTransportSession::create(
    WebRtcTransportConfig config, RuntimeDispatcher dispatcher,
    WebRtcSignalingHandler signaling) {
  if (!valid_config(config) || !dispatcher) {
    return Result<std::shared_ptr<WebRtcTransportSession>>::failure(
        transport_error(ErrorCode::configuration, "transport_config_invalid"));
  }
  auto impl = std::make_shared<Impl>(std::move(config), std::move(dispatcher),
                                     std::move(signaling));
  auto initialized = impl->initialize();
  if (!initialized) {
    return Result<std::shared_ptr<WebRtcTransportSession>>::failure(
        *initialized.error_if());
  }
  return Result<std::shared_ptr<WebRtcTransportSession>>::success(
      std::shared_ptr<WebRtcTransportSession>{new WebRtcTransportSession{std::move(impl)}});
}

WebRtcTransportSession::WebRtcTransportSession(std::shared_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}

WebRtcTransportSession::~WebRtcTransportSession() { close(CloseReason::local_shutdown); }

Result<void> WebRtcTransportSession::start() {
  if (!impl_ || impl_->closed_.load(std::memory_order_acquire)) {
    return Result<void>::failure(transport_error(ErrorCode::cancelled,
                                                 "transport_closed"));
  }
  try {
    if (impl_->config_.offerer) {
      impl_->peer_->setLocalDescription(rtc::Description::Type::Offer);
    }
    return Result<void>::success();
  } catch (...) {
    return Result<void>::failure(transport_error(ErrorCode::transport,
                                                 "transport_start_failed"));
  }
}

Result<void> WebRtcTransportSession::set_remote_description(
    std::span<const std::byte> sdp, std::string_view type) {
  if (!impl_ || sdp.empty() || sdp.size() > max_signaling_object_bytes ||
      (type != "offer" && type != "answer")) {
    return Result<void>::failure(transport_error(ErrorCode::protocol,
                                                 "remote_description_invalid"));
  }
  try {
    const std::string text{reinterpret_cast<const char*>(sdp.data()), sdp.size()};
    impl_->peer_->setRemoteDescription(rtc::Description{text, std::string{type}});
    return Result<void>::success();
  } catch (...) {
    return Result<void>::failure(transport_error(ErrorCode::transport,
                                                 "remote_description_rejected"));
  }
}

Result<void> WebRtcTransportSession::add_remote_candidate(
    std::span<const std::byte> candidate) {
  if (!impl_ || candidate.empty() || candidate.size() > 4096U) {
    return Result<void>::failure(transport_error(ErrorCode::protocol,
                                                 "remote_candidate_invalid"));
  }
  try {
    const std::string text{reinterpret_cast<const char*>(candidate.data()), candidate.size()};
    rtc::Candidate parsed{text};
    if (!candidate_allowed(parsed, impl_->config_.candidates)) {
      return Result<void>::failure(transport_error(ErrorCode::permission,
                                                   "candidate_policy_rejected"));
    }
    impl_->peer_->addRemoteCandidate(std::move(parsed));
    return Result<void>::success();
  } catch (...) {
    return Result<void>::failure(transport_error(ErrorCode::protocol,
                                                 "remote_candidate_rejected"));
  }
}

Result<void> WebRtcTransportSession::restart_ice() {
  if (!impl_ || impl_->closed_.load(std::memory_order_acquire)) {
    return Result<void>::failure(transport_error(ErrorCode::cancelled,
                                                 "transport_closed"));
  }
  try {
    ++impl_->ice_restarts_;
    impl_->peer_->setLocalDescription(impl_->config_.offerer
                                          ? rtc::Description::Type::Offer
                                          : rtc::Description::Type::Answer,
                                      rtc::LocalDescriptionInit{});
    return Result<void>::success();
  } catch (...) {
    return Result<void>::failure(transport_error(ErrorCode::transport,
                                                 "ice_restart_failed"));
  }
}

WebRtcTransportDiagnostics WebRtcTransportSession::diagnostics() const noexcept {
  if (!impl_) return {};
  const auto stats = impl_->events_.stats();
  return WebRtcTransportDiagnostics{
      .callbacks_enqueued = impl_->callbacks_enqueued_.load(std::memory_order_relaxed),
      .callbacks_dispatched = impl_->callbacks_dispatched_.load(std::memory_order_relaxed),
      .callbacks_rejected = impl_->callbacks_rejected_.load(std::memory_order_relaxed),
      .callback_dispatch_rejected =
          impl_->callback_dispatch_rejected_.load(std::memory_order_relaxed),
      .messages_rejected = impl_->messages_rejected_.load(std::memory_order_relaxed),
      .sends_would_block = impl_->sends_would_block_.load(std::memory_order_relaxed),
      .channels_opened = impl_->channels_opened_.load(std::memory_order_relaxed),
      .channels_rejected = impl_->channels_rejected_.load(std::memory_order_relaxed),
      .ice_restarts = impl_->ice_restarts_.load(std::memory_order_relaxed),
      .callback_depth = stats.current_depth,
      .callback_peak_depth = stats.peak_depth};
}

void WebRtcTransportSession::async_open_channel(ChannelKind kind, ChannelOptions options,
                                                OpenCompletion completion) {
  if (!impl_ || !completion) return;
  auto weak = std::weak_ptr<Impl>{impl_};
  auto rejected_completion = completion;
  auto dispatched = impl_->dispatcher_(
      "webrtc-open-channel",
      [weak, kind, options = std::move(options),
       completion = std::move(completion)]() mutable {
        if (auto self = weak.lock()) {
          self->open_channel(kind, std::move(options), std::move(completion));
        } else {
          completion(Result<TransportChannel*>::failure(
              transport_error(ErrorCode::cancelled, "transport_closed")));
        }
        return Result<void>::success();
      });
  if (!dispatched) {
    rejected_completion(Result<TransportChannel*>::failure(
        transport_error(ErrorCode::resource_exhausted,
                        "channel_dispatch_rejected")));
  }
}

void WebRtcTransportSession::set_message_handler(MessageHandler handler) {
  if (impl_) impl_->message_handler_ = std::move(handler);
}

void WebRtcTransportSession::set_state_handler(StateHandler handler) {
  if (impl_) impl_->state_handler_ = std::move(handler);
}

TransportSessionSnapshot WebRtcTransportSession::snapshot() const noexcept {
  return impl_ ? impl_->snapshot() : TransportSessionSnapshot{};
}

void WebRtcTransportSession::close(CloseReason /*reason*/) {
  if (!impl_ || impl_->closed_.exchange(true, std::memory_order_acq_rel)) return;
  impl_->events_.close();
  while (!impl_->pending_opens_.empty()) {
    impl_->fail_pending_open(impl_->pending_opens_.begin()->first,
                             ErrorCode::cancelled, "transport_closed");
  }
  for (auto& [kind, channel] : impl_->channels_) {
    (void)kind;
    channel->close(CloseReason::local_shutdown);
  }
  impl_->channels_.clear();
  if (impl_->peer_) {
    impl_->peer_->resetCallbacks();
    impl_->peer_->close();
  }
  impl_->update_snapshot(TransportState::closed);
}

}  // namespace heyaki::transport::webrtc
