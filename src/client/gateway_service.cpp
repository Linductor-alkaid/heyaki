#include "gateway_service.hpp"

#include <heyaki/gateway.hpp>

#include <boost/asio/buffer.hpp>
#include <boost/asio/error.hpp>
#include <boost/system/error_code.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <functional>
#include <utility>

namespace heyaki {
namespace {

// One in-flight chunk per direction (design 6: bounded by construction).
constexpr std::size_t gateway_pump_chunk_bytes = 16U * 1024U;
constexpr std::size_t max_gateway_resolved_addresses = 16U;

Error gateway_service_error(ErrorCode code, const char* detail) {
  return {code, "gateway", detail};
}

boost::asio::ip::address asio_address(const GatewayIp& address) noexcept {
  if (address.v4) {
    std::array<unsigned char, 4U> v4{};
    for (std::size_t index = 0U; index < 4U; ++index) {
      v4[index] = std::to_integer<unsigned char>(address.bytes[index]);
    }
    return boost::asio::ip::make_address_v4(v4);
  }
  std::array<unsigned char, 16U> v6{};
  for (std::size_t index = 0U; index < 16U; ++index) {
    v6[index] = std::to_integer<unsigned char>(address.bytes[index]);
  }
  return boost::asio::ip::make_address_v6(v6);
}

GatewayIp gateway_ip_from_asio(const boost::asio::ip::address& address) noexcept {
  GatewayIp ip;
  if (address.is_v4()) {
    ip.v4 = true;
    const auto bytes = address.to_v4().to_bytes();
    for (std::size_t index = 0U; index < 4U; ++index) {
      ip.bytes[index] = static_cast<std::byte>(bytes[index]);
    }
  } else {
    ip.v4 = false;
    const auto bytes = address.to_v6().to_bytes();
    for (std::size_t index = 0U; index < 16U; ++index) {
      ip.bytes[index] = static_cast<std::byte>(bytes[index]);
    }
  }
  return ip;
}

// Io-strand write-all loop for one node-side chunk. The chain state keeps
// the running offset and a weak self-reference (a strong one would cycle:
// state owns `next`, `next` must not own state); the pending handler holds
// the only strong reference, so the whole chain is released on completion.
struct ChunkWriteState {
  std::function<void()> next;
  std::size_t offset{0};
};

void socket_write_all(
    const std::shared_ptr<boost::asio::ip::tcp::socket>& socket,
    const std::shared_ptr<std::vector<std::byte>>& buffer, std::size_t total,
    std::size_t offset, std::function<void()> on_done,
    std::function<void()> on_error) {
  auto state = std::make_shared<ChunkWriteState>();
  state->offset = offset;
  const std::weak_ptr<ChunkWriteState> weak_state = state;
  state->next = [socket, buffer, total, weak_state, on_done = std::move(on_done),
                 on_error = std::move(on_error)]() mutable {
    auto state = weak_state.lock();
    if (!state) return;
    if (state->offset >= total) {
      auto done = std::move(on_done);
      if (done) done();
      return;
    }
    socket->async_write_some(
        boost::asio::buffer(buffer->data() + state->offset, total - state->offset),
        [socket, buffer, total, state, on_done, on_error](
            const boost::system::error_code& error, std::size_t written) mutable {
          if (error) {
            auto failed = std::move(on_error);
            if (failed) failed();
            return;
          }
          state->offset += written;
          state->next();
        });
  };
  state->next();
}

}  // namespace

GatewayService::GatewayService(PeerSession& session, ByteStreamService& streams,
                               GatewayServiceConfig config,
                               boost::asio::any_io_executor io, NodePoster poster,
                               ScopeCheck scope_check,
                               std::function<std::uint64_t()> wall_clock)
    : session_(session),
      streams_(streams),
      config_(std::move(config)),
      io_strand_(boost::asio::make_strand(std::move(io))),
      poster_(std::move(poster)),
      scope_check_(std::move(scope_check)),
      wall_clock_(std::move(wall_clock)) {}

GatewayService::~GatewayService() { handle_session_closed(); }

Result<void> GatewayService::attach() {
  if (config_.profiles.empty()) {
    return Result<void>::failure(
        gateway_service_error(ErrorCode::configuration, "gateway_not_configured"));
  }
  auto weak = weak_from_this();
  streams_.set_gateway_inbound_handler(
      [weak](const std::shared_ptr<ByteStreamHandle>& stream,
             const GatewayConnect& connect) {
        if (auto self = weak.lock()) {
          self->handle_gateway_open(stream, connect);
        } else {
          // The service is gone: the stream cannot be served.
          stream->reset(gateway_refusal_status(GatewayRefusal::not_enabled));
        }
      });
  attached_ = true;
  return Result<void>::success();
}

void GatewayService::handle_session_closed() {
  for (auto& [id, tunnel] : tunnels_) {
    tunnel->finished = true;
    boost::asio::post(io_strand_, [tunnel] {
      if (tunnel->socket) {
        boost::system::error_code ignored;
        tunnel->socket->cancel();
        tunnel->socket->close(ignored);
      }
      if (tunnel->dial_timer) {
        boost::system::error_code ignored;
        tunnel->dial_timer->cancel();
      }
    });
  }
  tunnels_.clear();
  usage_.clear();
  stats_.tunnels_active = 0U;
}

void GatewayService::prune() {
  const auto current = now();
  for (auto it = tunnels_.begin(); it != tunnels_.end();) {
    const auto next = std::next(it);
    const auto& tunnel = it->second;
    const auto profile = tunnel->profile;
    if (profile != nullptr &&
        current - tunnel->opened_unix_ms >
            static_cast<std::uint64_t>(profile->stream_max_duration.count())) {
      ++stats_.duration_timeout_resets;
      close_tunnel(tunnel, StableStatus::deadline_exceeded, false);
      it = next;
      continue;
    }
    if (profile != nullptr && tunnel->socket_connected &&
        current - tunnel->last_activity_unix_ms >
            static_cast<std::uint64_t>(profile->stream_idle_timeout.count())) {
      ++stats_.idle_timeout_resets;
      close_tunnel(tunnel, StableStatus::deadline_exceeded, false);
      it = next;
      continue;
    }
    if (profile != nullptr) {
      auto usage = usage_.find(tunnel->profile_name);
      if (usage != usage_.end() && usage->second.bytes >= profile->max_profile_bytes) {
        ++stats_.byte_quota_resets;
        close_tunnel(tunnel, StableStatus::resource_exhausted, false);
        it = next;
        continue;
      }
    }
    it = next;
  }
  stats_.tunnels_active = tunnels_.size();
}

std::uint64_t GatewayService::now() const noexcept {
  return wall_clock_ ? wall_clock_() : 0U;
}

void GatewayService::handle_gateway_open(const std::shared_ptr<ByteStreamHandle>& stream,
                                         const GatewayConnect& connect) {
  ++stats_.opens_received;
  if (stream->state() == StreamState::reset || stream->state() == StreamState::closed) {
    return;
  }
  // Shared selection rule (M10-05): an unnamed request resolves only on a
  // single-profile configuration; a named miss is a policy refusal.
  const auto profile = resolve_gateway_profile(config_.profiles, connect.profile);
  if (profile == nullptr) {
    refuse_open(stream, nullptr,
                connect.profile.empty() ? GatewayRefusal::not_enabled
                                        : GatewayRefusal::policy_denied);
    return;
  }
  // Live scope gate (M10-03): every open re-checks gateway.provide:<profile>
  // against the session's authorized scopes — the pairing-time grant alone
  // never serves a stream.
  if (!scope_check_ || !scope_check_(gateway_provide_scope(profile->name))) {
    refuse_open(stream, nullptr, GatewayRefusal::scope_denied);
    return;
  }
  auto tunnel = std::make_shared<Tunnel>(stream->stream_id());
  tunnel->stream = stream;
  tunnel->profile = profile;
  tunnel->profile_name = profile->name;
  tunnel->opened_unix_ms = now();
  tunnel->last_activity_unix_ms = tunnel->opened_unix_ms;
  // Reserve the concurrency slot before any async work so parallel opens
  // cannot overshoot the caps (fail-closed admission, M10-05).
  tunnels_.emplace(tunnel->id, tunnel);
  usage_[profile->name].active += 1U;
  stats_.tunnels_active = tunnels_.size();

  const auto literal = parse_gateway_ip(connect.host);
  if (literal.has_value()) {
    continue_admission(
        tunnel, connect,
        Result<std::vector<GatewayIp>>::success(std::vector<GatewayIp>{*literal}));
    return;
  }
  // Hostname: resolution belongs to the serving side (design 4.3) and is
  // bounded by the profile's dial deadline (the connect phase gets its own
  // bounded budget, so the whole open stays bounded by 2x dial_deadline).
  const auto deadline_ms = profile->dial_deadline;
  auto weak = weak_from_this();
  auto strand = io_strand_;
  boost::asio::post(strand, [weak, strand, tunnel, connect, deadline_ms] {
    auto resolver = std::make_shared<boost::asio::ip::tcp::resolver>(strand);
    auto timer = std::make_shared<boost::asio::steady_timer>(strand);
    tunnel->dial_timer = timer;
    auto timed_out = std::make_shared<bool>(false);
    timer->expires_after(deadline_ms);
    timer->async_wait([resolver, timer, tunnel, timed_out](
                          const boost::system::error_code& error) {
      if (tunnel->finished || error) return;
      *timed_out = true;
      boost::system::error_code ignored;
      resolver->cancel();
      if (tunnel->socket) tunnel->socket->cancel();
    });
    resolver->async_resolve(
        std::string{connect.host}, std::to_string(connect.port),
        [weak, resolver, timer, tunnel, connect,
         timed_out](const boost::system::error_code& error,
                    boost::asio::ip::tcp::resolver::results_type results) {
          timer->cancel();
          auto poster = [weak](std::function<void()> task) {
            if (auto self = weak.lock()) {
              self->poster_(std::move(task));
            }
          };
          if (*timed_out) {
            poster([weak, tunnel] {
              if (auto self = weak.lock()) {
                self->on_dial_failed(tunnel, GatewayRefusal::dial_deadline);
              }
            });
            return;
          }
          if (tunnel->finished) return;
          if (error) {
            poster([weak, tunnel, connect] {
              if (auto self = weak.lock()) {
                self->continue_admission(
                    tunnel, connect,
                    Result<std::vector<GatewayIp>>::failure(gateway_service_error(
                        ErrorCode::transport, "gateway_resolve_failed")));
              }
            });
            return;
          }
          std::vector<GatewayIp> addresses;
          for (const auto& entry : results) {
            const GatewayIp candidate = gateway_ip_from_asio(entry.endpoint().address());
            const bool duplicate = std::any_of(
                addresses.begin(), addresses.end(),
                [&candidate](const GatewayIp& existing) { return existing == candidate; });
            if (!duplicate) {
              addresses.push_back(candidate);
              if (addresses.size() >= max_gateway_resolved_addresses) break;
            }
          }
          poster([weak, tunnel, connect, addresses = std::move(addresses)]() mutable {
            if (auto self = weak.lock()) {
              self->continue_admission(
                  tunnel, connect,
                  Result<std::vector<GatewayIp>>::success(std::move(addresses)));
            }
          });
        });
  });
}

void GatewayService::continue_admission(const std::shared_ptr<Tunnel>& tunnel,
                                        const GatewayConnect& connect,
                                        Result<std::vector<GatewayIp>> resolved) {
  if (tunnel->finished) return;
  if (!resolved) {
    // Resolution failure is a dial failure (coarse mapping): the peer
    // learns `unavailable`, never why.
    on_dial_failed(tunnel, GatewayRefusal::dial_failed);
    return;
  }
  GatewayAdmissionContext context;
  // The candidate reserved its own slot at registration; the engine's
  // contract counts ALREADY-active streams, so exclude this tunnel.
  context.streams_active_session = tunnels_.empty() ? 0U : tunnels_.size() - 1U;
  auto usage = usage_.find(tunnel->profile_name);
  if (usage != usage_.end()) {
    context.streams_active_profile =
        usage->second.active > 0U ? usage->second.active - 1U : 0U;
    context.profile_bytes_used = usage->second.bytes;
  }
  const auto admission =
      admit_gateway_connection(config_.profiles, connect, *resolved.value_if(), context);
  if (!admission.allowed) {
    refuse_open(tunnel->stream, tunnel, admission.refusal);
    return;
  }
  tunnel->dial_addresses = admission.dial_addresses;
  dispatch_dial(tunnel, connect);
}

void GatewayService::dispatch_dial(const std::shared_ptr<Tunnel>& tunnel,
                                   const GatewayConnect& connect) {
  const auto port = connect.port;
  const auto deadline_ms = tunnel->profile->dial_deadline;
  auto weak = weak_from_this();
  auto strand = io_strand_;
  boost::asio::post(strand, [weak, strand, tunnel, port, deadline_ms] {
    // Dial chain with a weak self-reference: the state owns `next`, the
    // pending connect handler owns the only strong state reference, so a
    // finished chain releases everything (no shared_ptr cycle).
    struct DialState {
      std::function<void()> next;
      std::size_t index{0};
      bool timed_out{false};
    };
    auto state = std::make_shared<DialState>();
    auto socket = std::make_shared<boost::asio::ip::tcp::socket>(strand);
    auto timer = std::make_shared<boost::asio::steady_timer>(strand);
    tunnel->dial_timer = timer;
    timer->expires_after(deadline_ms);
    timer->async_wait([socket, timer, tunnel, state](const boost::system::error_code& error) {
      if (tunnel->finished || error) return;
      state->timed_out = true;
      boost::system::error_code ignored;
      socket->cancel();
    });
    auto poster = [weak](std::function<void()> task) {
      if (auto self = weak.lock()) {
        self->poster_(std::move(task));
      }
    };
    const std::weak_ptr<DialState> weak_state = state;
    state->next = [weak, tunnel, port, socket, timer, weak_state,
                   poster]() mutable {
      auto state = weak_state.lock();
      if (!state) return;
      if (tunnel->finished) return;
      if (state->timed_out) {
        poster([weak, tunnel] {
          if (auto self = weak.lock()) {
            self->on_dial_failed(tunnel, GatewayRefusal::dial_deadline);
          }
        });
        return;
      }
      if (state->index >= tunnel->dial_addresses.size()) {
        // Every surviving address refused/failed: coarse `unavailable`.
        poster([weak, tunnel] {
          if (auto self = weak.lock()) {
            self->on_dial_failed(tunnel, GatewayRefusal::dial_failed);
          }
        });
        return;
      }
      const auto address = tunnel->dial_addresses[state->index];
      ++state->index;
      const auto endpoint = boost::asio::ip::tcp::endpoint(asio_address(address), port);
      socket->async_connect(endpoint,
                            [weak, socket, timer, tunnel, state,
                             poster](const boost::system::error_code& error) mutable {
                              if (tunnel->finished) return;
                              if (!error) {
                                boost::system::error_code ignored;
                                timer->cancel();
                                tunnel->socket = socket;
                                poster([weak, tunnel] {
                                  if (auto self = weak.lock()) {
                                    self->on_dial_succeeded(tunnel);
                                  }
                                });
                                return;
                              }
                              if (state->timed_out) {
                                poster([weak, tunnel] {
                                  if (auto self = weak.lock()) {
                                    self->on_dial_failed(
                                        tunnel, GatewayRefusal::dial_deadline);
                                  }
                                });
                                return;
                              }
                              state->next();
                            });
    };
    state->next();
  });
}

void GatewayService::on_dial_succeeded(const std::shared_ptr<Tunnel>& tunnel) {
  if (tunnel->finished) return;
  // Node-strand state: connected + fresh activity (idle sweeps must not
  // fire on tunnels that are merely mid-dial).
  tunnel->socket_connected = true;
  tunnel->last_activity_unix_ms = now();
  ++stats_.dials_succeeded;
  // Prelude first, before any tunnel byte (wire 6.3.1): 2 bytes, status 0.
  const auto prelude = encode_gateway_prelude(gateway_prelude_connected);
  tunnel->stream->async_write(
      std::span<const std::byte>{prelude.data(), prelude.size()},
      [weak = weak_from_this(), tunnel](StreamIoResult written) {
        if (auto self = weak.lock()) {
          self->on_prelude_written(tunnel, written);
        }
      });
}

void GatewayService::on_prelude_written(const std::shared_ptr<Tunnel>& tunnel,
                                        StreamIoResult written) {
  if (tunnel->finished) return;
  if (written.error.has_value() || written.bytes != gateway_prelude_bytes) {
    close_tunnel(tunnel, StableStatus::internal, false);
    return;
  }
  start_pumps(tunnel);
}

void GatewayService::start_pumps(const std::shared_ptr<Tunnel>& tunnel) {
  pump_tunnel_to_socket(tunnel);
  auto weak = weak_from_this();
  boost::asio::post(io_strand_, [weak, tunnel] {
    if (tunnel->finished || !tunnel->socket) return;
    auto buffer = std::make_shared<std::vector<std::byte>>(gateway_pump_chunk_bytes);
    tunnel->socket->async_read_some(
        boost::asio::buffer(buffer->data(), buffer->size()),
        [weak, tunnel, buffer](const boost::system::error_code& error,
                               std::size_t bytes) {
          if (auto self = weak.lock()) {
            self->poster_([weak, tunnel, buffer, error, bytes] {
              if (auto self = weak.lock()) {
                self->on_socket_read(tunnel, buffer, error, bytes);
              }
            });
          }
        });
  });
}

void GatewayService::pump_tunnel_to_socket(const std::shared_ptr<Tunnel>& tunnel) {
  if (tunnel->finished) return;
  auto buffer = std::make_shared<std::vector<std::byte>>(gateway_pump_chunk_bytes);
  tunnel->stream->async_read_some(
      std::span<std::byte>{buffer->data(), buffer->size()},
      [weak = weak_from_this(), tunnel, buffer](StreamIoResult read) {
        if (auto self = weak.lock()) {
          self->on_tunnel_read(tunnel, buffer, read);
        }
      });
}

void GatewayService::on_tunnel_read(const std::shared_ptr<Tunnel>& tunnel,
                                    const std::shared_ptr<std::vector<std::byte>>& buffer,
                                    StreamIoResult read) {
  if (tunnel->finished) return;
  if (read.error.has_value()) {
    // The tunnel stream failed or was reset: the socket has nothing more
    // to say. reset()/close are idempotent for the already-terminal case.
    close_tunnel(tunnel, StableStatus::cancelled, false);
    return;
  }
  if (read.bytes == 0U) {
    // Clean tunnel EOF: the initiator half-closed; propagate to the target.
    boost::asio::post(io_strand_, [tunnel] {
      if (tunnel->socket && tunnel->socket->is_open()) {
        boost::system::error_code ignored;
        tunnel->socket->shutdown(
            boost::asio::ip::tcp::socket::shutdown_send, ignored);
      }
    });
    return;
  }
  on_tunnel_bytes(tunnel, read.bytes, 0U);
  auto weak = weak_from_this();
  boost::asio::post(io_strand_, [weak, tunnel, buffer, total = read.bytes] {
    if (tunnel->finished || !tunnel->socket) return;
    socket_write_all(
        tunnel->socket, buffer, total, 0U,
        [weak, tunnel]() {
          if (auto self = weak.lock()) {
            self->poster_([weak, tunnel] {
              if (auto self = weak.lock()) {
                self->pump_tunnel_to_socket(tunnel);
              }
            });
          }
        },
        [weak, tunnel]() {
          if (auto self = weak.lock()) {
            self->poster_([weak, tunnel] {
              if (auto self = weak.lock()) {
                // Target-side failure mid-stream: coarse `unavailable`.
                self->close_tunnel(
                    tunnel, gateway_refusal_status(GatewayRefusal::dial_failed), false);
              }
            });
          }
        });
  });
}

void GatewayService::on_socket_read(const std::shared_ptr<Tunnel>& tunnel,
                                    const std::shared_ptr<std::vector<std::byte>>& buffer,
                                    boost::system::error_code error, std::size_t bytes) {
  if (tunnel->finished) return;
  if (error == boost::asio::error::eof) {
    // Target half-closed: propagate FIN toward the initiator and stop this
    // direction (the reverse direction keeps flowing until it EOFs/closes).
    (void)tunnel->stream->shutdown_write();
    return;
  }
  if (error) {
    close_tunnel(tunnel, gateway_refusal_status(GatewayRefusal::dial_failed), false);
    return;
  }
  if (bytes == 0U) {
    close_tunnel(tunnel, gateway_refusal_status(GatewayRefusal::dial_failed), false);
    return;
  }
  on_tunnel_bytes(tunnel, 0U, bytes);
  tunnel->stream->async_write(
      std::span<const std::byte>{buffer->data(), bytes},
      [weak = weak_from_this(), tunnel](StreamIoResult written) {
        if (auto self = weak.lock()) {
          self->on_socket_written(tunnel, written);
        }
      });
}

void GatewayService::on_socket_written(const std::shared_ptr<Tunnel>& tunnel,
                                       StreamIoResult written) {
  if (tunnel->finished) return;
  if (written.error.has_value() || written.bytes == 0U) {
    close_tunnel(tunnel, StableStatus::cancelled, false);
    return;
  }
  // Next socket read: chain continues on the io strand.
  auto weak = weak_from_this();
  boost::asio::post(io_strand_, [weak, tunnel] {
    if (tunnel->finished || !tunnel->socket) return;
    auto buffer = std::make_shared<std::vector<std::byte>>(gateway_pump_chunk_bytes);
    tunnel->socket->async_read_some(
        boost::asio::buffer(buffer->data(), buffer->size()),
        [weak, tunnel, buffer](const boost::system::error_code& error,
                               std::size_t bytes) {
          if (auto self = weak.lock()) {
            self->poster_([weak, tunnel, buffer, error, bytes] {
              if (auto self = weak.lock()) {
                self->on_socket_read(tunnel, buffer, error, bytes);
              }
            });
          }
        });
  });
}

void GatewayService::on_tunnel_bytes(const std::shared_ptr<Tunnel>& tunnel,
                                     std::uint64_t from_tunnel,
                                     std::uint64_t to_tunnel) {
  tunnel->bytes_from_tunnel += from_tunnel;
  tunnel->bytes_to_tunnel += to_tunnel;
  stats_.bytes_from_tunnel += from_tunnel;
  stats_.bytes_to_tunnel += to_tunnel;
  auto usage = usage_.find(tunnel->profile_name);
  if (usage != usage_.end()) {
    usage->second.bytes += from_tunnel + to_tunnel;
  }
  tunnel->last_activity_unix_ms = now();
}

void GatewayService::on_dial_failed(const std::shared_ptr<Tunnel>& tunnel,
                                    GatewayRefusal refusal) {
  ++stats_.dials_failed;
  refuse_open(tunnel->stream, tunnel, refusal);
}

void GatewayService::close_tunnel(std::shared_ptr<Tunnel> tunnel, StableStatus reason,
                                  bool clean) {
  // By value: callers may pass a map-slot reference (prune does), and the
  // erase below would leave that reference dangling.
  if (tunnel->finished) return;
  tunnel->finished = true;
  if (clean) {
    ++stats_.tunnels_closed_clean;
  }
  if (tunnel->stream && tunnel->stream->state() != StreamState::reset &&
      tunnel->stream->state() != StreamState::closed) {
    tunnel->stream->reset(reason);
  }
  boost::asio::post(io_strand_, [tunnel] {
    if (tunnel->socket) {
      boost::system::error_code ignored;
      tunnel->socket->cancel();
      tunnel->socket->close(ignored);
    }
    if (tunnel->dial_timer) {
      boost::system::error_code ignored;
      tunnel->dial_timer->cancel();
    }
  });
  tunnels_.erase(tunnel->id);
  auto usage = usage_.find(tunnel->profile_name);
  if (usage != usage_.end() && usage->second.active > 0U) {
    usage->second.active -= 1U;
  }
  stats_.tunnels_active = tunnels_.size();
}

void GatewayService::refuse_open(const std::shared_ptr<ByteStreamHandle>& stream,
                                 const std::shared_ptr<Tunnel>& tunnel,
                                 GatewayRefusal refusal) {
  ++stats_.refusals[static_cast<std::size_t>(refusal)];
  if (stream && stream->state() != StreamState::reset &&
      stream->state() != StreamState::closed) {
    stream->reset(gateway_refusal_status(refusal));
  }
  if (tunnel) {
    close_tunnel(tunnel, gateway_refusal_status(refusal), false);
  }
}

}  // namespace heyaki
