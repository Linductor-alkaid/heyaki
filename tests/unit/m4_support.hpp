#pragma once

// Round-1 M4 test doubles: a recording signaling route and an in-memory loopback transport
// pair exercising the internal TransportSession SPI. Test-only; no production code may
// include this header.

#include "signaling_coordinator.hpp"
#include "transport/transport_session.hpp"

#include <algorithm>
#include <cstddef>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace heyaki::test {

class FakeSignalingRoute : public SignalingRoute {
 public:
  explicit FakeSignalingRoute(SignalingRouteKind kind) : kind_(kind) {}

  // When set, every sent envelope is synchronously forwarded to the peer side.
  std::function<void(const SignalingEnvelope&)> sink;

  Result<void> send(const SignalingEnvelope& message) override {
    sent.push_back(message);
    if (sink) {
      sink(message);
    }
    return Result<void>::success();
  }

  [[nodiscard]] SignalingRouteKind kind() const noexcept override { return kind_; }

  [[nodiscard]] const std::vector<SignalingEnvelope>& sent_messages() const noexcept {
    return sent;
  }

  [[nodiscard]] std::optional<SignalingEnvelope> last_of(
      LanSignalingMessageKind kind) const noexcept {
    for (auto it = sent.rbegin(); it != sent.rend(); ++it) {
      if (it->kind == kind) {
        return *it;
      }
    }
    return std::nullopt;
  }

 private:
  SignalingRouteKind kind_;
  std::vector<SignalingEnvelope> sent;
};

class LoopbackSession;

class LoopbackChannel : public transport::TransportChannel {
 public:
  LoopbackChannel(transport::ChannelKind kind, transport::ChannelOptions options)
      : kind_(kind), options_(options) {}

  struct PendingMessage {
    transport::ChannelKind kind;
    std::vector<std::byte> payload;
    LoopbackChannel* sender;
  };

  [[nodiscard]] transport::ChannelKind kind() const noexcept override { return kind_; }
  [[nodiscard]] const transport::ChannelOptions& options() const noexcept override {
    return options_;
  }

  // Queues into the peer session's inbound queue; the byte budget is charged to this
  // (sending) channel until the peer pumps the message out.
  Result<void> send(std::span<const std::byte> payload) override {
    if (closed_) {
      return Result<void>::failure(Error{ErrorCode::transport, "loopback",
                                         "channel_closed"});
    }
    if (payload.size() > options_.max_message_bytes) {
      return Result<void>::failure(Error{ErrorCode::protocol, "loopback",
                                         "message_too_large"});
    }
    if (paused_ || pending_bytes_ + payload.size() > options_.send_queue_bytes) {
      paused_ = true;
      return Result<void>::failure(Error{ErrorCode::would_block, "loopback",
                                         "send_queue_full"});
    }
    pending_bytes_ += payload.size();
    if (pending_bytes_ >= options_.send_queue_bytes) paused_ = true;
    peer_inbound_->push_back(
        PendingMessage{kind_, std::vector<std::byte>{payload.begin(), payload.end()},
                       this});
    return Result<void>::success();
  }

  [[nodiscard]] std::size_t buffered_amount() const noexcept override {
    return pending_bytes_;
  }

  [[nodiscard]] bool writable() const noexcept override {
    return !closed_ && !paused_;
  }

  void set_writable_handler(WritableHandler handler) override {
    writable_handler_ = std::move(handler);
  }

  void close(transport::CloseReason reason) override {
    if (!closed_) {
      closed_ = true;
      close_reason_ = reason;
    }
  }

  [[nodiscard]] bool closed() const noexcept { return closed_; }
  [[nodiscard]] std::optional<transport::CloseReason> close_reason() const noexcept {
    return close_reason_;
  }

  void note_delivered(std::size_t bytes) {
    pending_bytes_ -= std::min(pending_bytes_, bytes);
    if (paused_ && pending_bytes_ <= options_.send_queue_bytes / 2U) {
      paused_ = false;
      if (writable_handler_) writable_handler_();
    }
  }
  void attach_peer_inbound(std::deque<PendingMessage>* inbound) { peer_inbound_ = inbound; }

 private:
  transport::ChannelKind kind_;
  transport::ChannelOptions options_;
  std::deque<PendingMessage>* peer_inbound_{nullptr};
  std::size_t pending_bytes_{};
  bool paused_{false};
  bool closed_{false};
  std::optional<transport::CloseReason> close_reason_;
  WritableHandler writable_handler_;
};

class LoopbackTransportPair;

class LoopbackSession : public transport::TransportSession {
 public:
  explicit LoopbackSession(LoopbackTransportPair* pair) : pair_(pair) {}

  void async_open_channel(transport::ChannelKind kind, transport::ChannelOptions options,
                          OpenCompletion completion) override {
    if (state_.state != transport::TransportState::connected) {
      completion(Result<transport::TransportChannel*>::failure(
          Error{ErrorCode::transport, "loopback", "session_not_connected"}));
      return;
    }
    auto channel = std::make_unique<LoopbackChannel>(kind, options);
    channel->attach_peer_inbound(&peer()->inbound_);
    channels_.push_back(std::move(channel));
    completion(Result<transport::TransportChannel*>::success(channels_.back().get()));
  }

  void set_message_handler(MessageHandler handler) override {
    message_handler_ = std::move(handler);
  }
  void set_state_handler(StateHandler handler) override { state_handler_ = std::move(handler); }

  [[nodiscard]] transport::TransportSessionSnapshot snapshot() const noexcept override {
    transport::TransportSessionSnapshot snapshot;
    snapshot.state = state_.state;
    snapshot.path = state_.path;
    snapshot.error = state_.error;
    snapshot.buffered_amount = buffered_amount();
    return snapshot;
  }

  void close(transport::CloseReason reason) override {
    set_state(transport::TransportState::closed, reason);
    for (auto& channel : channels_) {
      channel->close(reason);
    }
  }

  // Delivers every queued inbound message to the message handler in FIFO order.
  void pump() {
    while (!inbound_.empty() && message_handler_) {
      auto message = std::move(inbound_.front());
      inbound_.pop_front();
      message.sender->note_delivered(message.payload.size());
      for (auto& channel : channels_) {
        if (channel->kind() == message.kind && !channel->closed()) {
          message_handler_(*channel, std::move(message.payload));
          break;
        }
      }
    }
    inbound_.clear();
  }

  void set_state(transport::TransportState state,
                 std::optional<transport::CloseReason> reason,
                 std::optional<Error> error = std::nullopt) {
    state_.state = state;
    state_.error = std::move(error);
    if (reason.has_value()) {
      last_close_reason_ = *reason;
    }
    if (state_handler_) {
      state_handler_(snapshot());
    }
  }

  void set_path(transport::PathInfo path) { state_.path = std::move(path); }

  [[nodiscard]] std::optional<transport::CloseReason> last_close_reason() const noexcept {
    return last_close_reason_;
  }

  [[nodiscard]] std::size_t channel_count() const noexcept { return channels_.size(); }

  [[nodiscard]] std::size_t buffered_amount() const noexcept {
    std::size_t total = 0U;
    for (const auto& channel : channels_) {
      total += channel->buffered_amount();
    }
    return total;
  }

 private:
  [[nodiscard]] LoopbackSession* peer() noexcept;

  LoopbackTransportPair* pair_;
  transport::TransportSessionSnapshot state_;
  std::optional<transport::CloseReason> last_close_reason_;
  MessageHandler message_handler_;
  StateHandler state_handler_;
  std::deque<LoopbackChannel::PendingMessage> inbound_;
  std::vector<std::unique_ptr<LoopbackChannel>> channels_;
};

class LoopbackTransportPair {
 public:
  LoopbackTransportPair()
      : left_(std::make_unique<LoopbackSession>(this)),
        right_(std::make_unique<LoopbackSession>(this)) {}

  void connect() {
    left_->set_state(transport::TransportState::connected, std::nullopt);
    right_->set_state(transport::TransportState::connected, std::nullopt);
  }

  [[nodiscard]] LoopbackSession& left() const noexcept { return *left_; }
  [[nodiscard]] LoopbackSession& right() const noexcept { return *right_; }

  [[nodiscard]] LoopbackSession* peer_of(const LoopbackSession* session) const noexcept {
    return session == left_.get() ? right_.get() : left_.get();
  }

 private:
  std::unique_ptr<LoopbackSession> left_;
  std::unique_ptr<LoopbackSession> right_;
};

inline LoopbackSession* LoopbackSession::peer() noexcept {
  return pair_->peer_of(this);
}

}  // namespace heyaki::test
