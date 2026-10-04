// Heyaki Android (JNI) integration boundary — M11-06, increment 1: session
// lifecycle and authorization.
//
// Concurrency contract (executor boundary, EXEC review): this library creates
// no threads, no executors, no queues, and no monitoring of its own. Every
// Heyaki work item stays on the executor-owned contexts inside
// heyaki::Runtime / heyaki::Node. The only cross-boundary path is observer
// delivery: a callback fires on a Heyaki executor context, which attaches
// that thread to the JVM transiently (AttachCurrentThread/DetachCurrentThread)
// and invokes one Java method. Native state access is serialized on the Java
// monitor (every HeyakiNode method is synchronized); the observer uses only
// the JavaVM handle and its own global refs, which are JVM-safe.
//
// Error contract: C++ exceptions never escape a JNI function (that would call
// std::terminate). Every failure path registers a pending Java exception
// (HeyakiException / IllegalStateException) and returns a sentinel value; the
// JVM raises the pending exception when control returns to Java.
//
// Shutdown order is fixed by NativeNode member declaration order: the node is
// destroyed first, then the profile store, then the owned runtime.

#include <android/log.h>
#include <jni.h>

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <heyaki/error.hpp>
#include <heyaki/ids.hpp>
#include <heyaki/node.hpp>
#include <heyaki/password.hpp>
#include <heyaki/profile_store.hpp>
#include <heyaki/runtime.hpp>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

constexpr char kLogTag[] = "heyaki-jni";

JavaVM* g_jvm = nullptr;

std::string to_std_string(JNIEnv* env, jstring value) {
  if (value == nullptr) {
    return {};
  }
  const char* utf = env->GetStringUTFChars(value, nullptr);
  if (utf == nullptr) {
    return {};
  }
  std::string output{utf};
  env->ReleaseStringUTFChars(value, utf);
  return output;
}

std::vector<std::string> to_std_strings(JNIEnv* env, jobjectArray values) {
  std::vector<std::string> output;
  if (values == nullptr) {
    return output;
  }
  const jsize count = env->GetArrayLength(values);
  output.reserve(static_cast<std::size_t>(count));
  for (jsize index = 0; index < count; ++index) {
    auto* item = static_cast<jstring>(env->GetObjectArrayElement(values, index));
    output.push_back(to_std_string(env, item));
    env->DeleteLocalRef(item);
  }
  return output;
}

// One native node instance. Member declaration order is the shutdown order:
// destruction runs node → profile → runtime (reverse declaration order).
struct NativeNode {
  std::optional<heyaki::Runtime> runtime;
  std::optional<heyaki::ProfileStore> profile;
  std::optional<heyaki::Node> node;

  // Pairing-request listener wiring (receiver side, pairing_approval_v1).
  // Both fields go through atomics: callbacks run on Heyaki executor contexts
  // without the Java monitor, while native entry points replace them under
  // the Java monitor (every HeyakiNode method is synchronized).
  std::atomic<jobject> listener{nullptr};
  std::atomic<jmethodID> listener_method{nullptr};

  ~NativeNode() { clear_listener(); }

  void clear_listener() {
    listener_method.store(nullptr, std::memory_order_release);
    jobject previous = listener.exchange(nullptr, std::memory_order_acq_rel);
    if (previous == nullptr || g_jvm == nullptr) {
      return;
    }
    JNIEnv* env = nullptr;
    if (g_jvm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) == JNI_OK) {
      env->DeleteGlobalRef(previous);
      return;
    }
    // Native entry points run on attached (Java) threads, so this fallback is
    // defensive only; if even attaching fails, leave the ref to be dropped
    // with the process rather than leaking an unbalanced detach.
    if (g_jvm->AttachCurrentThread(&env, nullptr) == JNI_OK) {
      env->DeleteGlobalRef(previous);
      g_jvm->DetachCurrentThread();
    }
  }
};

NativeNode* as_handle(jlong handle) {
  if (handle == 0) {
    return nullptr;
  }
  return reinterpret_cast<NativeNode*>(static_cast<std::intptr_t>(handle));
}

// Registers a pending IllegalStateException and returns; the caller must
// immediately return its own sentinel (0 / nullptr / void). C++ exceptions
// never cross a JNI function boundary.
void fail_java(JNIEnv* env, std::string_view message) {
  if (jclass runtime_exception = env->FindClass("java/lang/IllegalStateException");
      runtime_exception != nullptr) {
    env->ThrowNew(runtime_exception, std::string{message}.c_str());
  }
  __android_log_print(ANDROID_LOG_ERROR, kLogTag, "failed: %s", std::string{message}.c_str());
}

// Registers a pending HeyakiException for one native Error.
void fail_heyaki(JNIEnv* env, const heyaki::Error& error) {
  if (jclass exception_class = env->FindClass("dev/heyaki/core/HeyakiException");
      exception_class != nullptr) {
    if (const jmethodID constructor =
            env->GetMethodID(exception_class, "<init>", "(Ljava/lang/String;Ljava/lang/String;)V");
        constructor != nullptr) {
      jstring code = env->NewStringUTF(std::string{heyaki::error_code_name(error.code())}.c_str());
      jstring detail = env->NewStringUTF(std::string{error.safe_detail()}.c_str());
      jobject instance = env->NewObject(exception_class, constructor, code, detail);
      env->DeleteLocalRef(code);
      env->DeleteLocalRef(detail);
      if (instance != nullptr) {
        env->Throw(reinterpret_cast<jthrowable>(instance));
        env->DeleteLocalRef(instance);
      }
    }
  }
  __android_log_print(ANDROID_LOG_ERROR, kLogTag, "heyaki failure: %s",
                      std::string{error.safe_detail()}.c_str());
}

std::optional<heyaki::DeviceEndpointKey> parse_peer_key(JNIEnv* env, jstring device_hex,
                                                        jstring endpoint_hex) {
  const auto device = heyaki::parse_device_id(to_std_string(env, device_hex));
  if (!device) {
    fail_java(env, std::string{"invalid device id: "}.append(
                       heyaki::identifier_decode_error_name(device.error)));
    return std::nullopt;
  }
  const auto endpoint = heyaki::parse_endpoint_id(to_std_string(env, endpoint_hex));
  if (!endpoint) {
    fail_java(env, std::string{"invalid endpoint id: "}.append(
                       heyaki::identifier_decode_error_name(endpoint.error)));
    return std::nullopt;
  }
  return heyaki::DeviceEndpointKey{*device.value, *endpoint.value};
}

std::optional<heyaki::RequestId> parse_request_id(JNIEnv* env, jstring request_hex) {
  const auto parsed = heyaki::parse_request_id(to_std_string(env, request_hex));
  if (!parsed) {
    fail_java(env, std::string{"invalid request id: "}.append(
                       heyaki::identifier_decode_error_name(parsed.error)));
    return std::nullopt;
  }
  return *parsed.value;
}

jobject build_snapshot_summary(JNIEnv* env, const heyaki::NodeSnapshot& snapshot,
                               std::size_t peer_session_count) {
  jclass summary_class = env->FindClass("dev/heyaki/core/HeyakiNode$SnapshotSummary");
  if (summary_class == nullptr) {
    return nullptr;
  }
  const jmethodID constructor =
      env->GetMethodID(summary_class, "<init>", "(ZLjava/lang/String;ZLjava/lang/String;IIJJ)V");
  if (constructor == nullptr) {
    return nullptr;
  }
  jstring lan_state =
      env->NewStringUTF(std::string{heyaki::lan_readiness_state_name(snapshot.lan_state)}.c_str());
  jstring relay_state =
      env->NewStringUTF(std::string{heyaki::relay_node_state_name(snapshot.relay.state)}.c_str());
  jobject summary = env->NewObject(
      summary_class, constructor,
      static_cast<jboolean>(snapshot.lan_enabled ? JNI_TRUE : JNI_FALSE), lan_state,
      static_cast<jboolean>(snapshot.relay.enabled ? JNI_TRUE : JNI_FALSE), relay_state,
      static_cast<jint>(peer_session_count), static_cast<jlong>(snapshot.announcements_sent),
      static_cast<jlong>(snapshot.datagrams_received));
  env->DeleteLocalRef(lan_state);
  env->DeleteLocalRef(relay_state);
  return summary;
}

void deliver_pairing_request(NativeNode& native_node, const heyaki::DeviceEndpointKey& peer,
                             const heyaki::PairingApprovalRequestBody& request) {
  const jobject listener = native_node.listener.load(std::memory_order_acquire);
  const jmethodID listener_method = native_node.listener_method.load(std::memory_order_acquire);
  if (listener == nullptr || g_jvm == nullptr || listener_method == nullptr) {
    return;
  }
  JNIEnv* env = nullptr;
  bool attached = false;
  if (g_jvm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
    if (g_jvm->AttachCurrentThread(&env, nullptr) != JNI_OK) {
      __android_log_print(ANDROID_LOG_WARN, kLogTag, "pairing delivery: attach failed");
      return;
    }
    attached = true;
  }
  // One Java callback per admitted request; a listener throwable is cleared
  // here and never propagates back through the Heyaki executor context.
  jclass request_class = env->FindClass("dev/heyaki/core/HeyakiNode$PairingRequest");
  jclass list_class = env->FindClass("java/util/ArrayList");
  const jmethodID constructor =
      request_class == nullptr
          ? nullptr
          : env->GetMethodID(request_class, "<init>",
                             "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;"
                             "Ljava/util/List;)V");
  const jmethodID list_constructor =
      list_class == nullptr ? nullptr : env->GetMethodID(list_class, "<init>", "(I)V");
  const jmethodID list_add = list_class == nullptr
                                 ? nullptr
                                 : env->GetMethodID(list_class, "add", "(Ljava/lang/Object;)Z");
  if (request_class != nullptr && constructor != nullptr && list_class != nullptr &&
      list_constructor != nullptr && list_add != nullptr) {
    jobject scopes = env->NewObject(list_class, list_constructor,
                                    static_cast<jint>(request.requested_scopes.size()));
    for (const auto& scope : request.requested_scopes) {
      jstring item = env->NewStringUTF(scope.c_str());
      env->CallBooleanMethod(scopes, list_add, item);
      env->DeleteLocalRef(item);
    }
    jstring device_hex = env->NewStringUTF(std::string{heyaki::to_string(peer.device_id)}.c_str());
    jstring endpoint_hex =
        env->NewStringUTF(std::string{heyaki::to_string(peer.endpoint_id)}.c_str());
    jstring request_hex =
        env->NewStringUTF(std::string{heyaki::to_string(request.request_id)}.c_str());
    jobject pairing_request =
        env->NewObject(request_class, constructor, device_hex, endpoint_hex, request_hex, scopes);
    if (pairing_request != nullptr) {
      env->CallVoidMethod(listener, listener_method, pairing_request);
      env->DeleteLocalRef(pairing_request);
    }
    env->DeleteLocalRef(device_hex);
    env->DeleteLocalRef(endpoint_hex);
    env->DeleteLocalRef(request_hex);
    env->DeleteLocalRef(scopes);
  }
  if (request_class != nullptr) {
    env->DeleteLocalRef(request_class);
  }
  if (list_class != nullptr) {
    env->DeleteLocalRef(list_class);
  }
  if (env->ExceptionCheck() == JNI_TRUE) {
    __android_log_print(ANDROID_LOG_WARN, kLogTag, "pairing listener threw; cleared");
    env->ExceptionClear();
  }
  if (attached) {
    g_jvm->DetachCurrentThread();
  }
}

heyaki::NodeConfig build_node_config(heyaki::ProfileStore& profile, heyaki::Runtime& runtime,
                                     const std::string& application_id,
                                     bool pairing_approval_enabled) {
  heyaki::NodeConfig config;
  config.profile = &profile;
  config.runtime = &runtime;
  config.application_id = application_id;
  config.pairing_approval_enabled = pairing_approval_enabled;
  // Alpha baseline: no relay_override — LAN-only until the host app supplies
  // relay enrollment (M11-07 smoke wires a relay scenario). LAN unavailability
  // still degrades explicitly (M11-05); it is never a silent failure.
  return config;
}

}  // namespace

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* /*reserved*/) {
  g_jvm = vm;
  return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT void JNICALL JNI_OnUnload(JavaVM* /*vm*/, void* /*reserved*/) {
  g_jvm = nullptr;
}

extern "C" JNIEXPORT jlong JNICALL Java_dev_heyaki_core_HeyakiNode_nativeCreate(
    JNIEnv* env, jclass /*clazz*/, jstring database_path, jstring application_id,
    jstring initial_password, jboolean pairing_approval_enabled) {
  const auto path = to_std_string(env, database_path);
  const auto application = to_std_string(env, application_id);
  const auto password = to_std_string(env, initial_password);
  if (path.empty() || application.empty() || password.empty()) {
    fail_java(env, "profileDatabasePath, applicationId and initialPassword are required");
    return 0;
  }

  auto* native_node = new (std::nothrow) NativeNode{};
  if (native_node == nullptr) {
    fail_java(env, "native allocation failed");
    return 0;
  }

  // Owned-runtime pattern (same as the TUI/SOCKS hosting): the runtime lives
  // in the holder, so executor shutdown happens after the node is gone.
  auto runtime_created = heyaki::Runtime::create_owned(heyaki::RuntimeConfig{});
  if (!runtime_created) {
    fail_heyaki(env, *runtime_created.error_if());
    delete native_node;
    return 0;
  }
  native_node->runtime.emplace(std::move(*runtime_created.value_if()));

  heyaki::ProfileOpenOptions profile_options;
  // Alpha disposition (M11-04/A3): the encrypted-file secret backend only —
  // no OS secret-store probe on Android.
  profile_options.secret_backend.prefer_os_backend = false;
  const bool database_exists = std::filesystem::exists(path);
  if (database_exists) {
    auto opened = heyaki::ProfileStore::open(path, profile_options);
    if (!opened) {
      fail_heyaki(env, *opened.error_if());
      delete native_node;
      return 0;
    }
    native_node->profile.emplace(std::move(*opened.value_if()));
  } else {
    auto created = heyaki::ProfileStore::create(path, profile_options);
    if (!created) {
      fail_heyaki(env, *created.error_if());
      delete native_node;
      return 0;
    }
    auto parameters = heyaki::calibrate_password_parameters();
    if (!parameters) {
      fail_heyaki(env, *parameters.error_if());
      delete native_node;
      return 0;
    }
    auto verifier = heyaki::create_password_verifier(password, *parameters.value_if());
    if (!verifier) {
      fail_heyaki(env, *verifier.error_if());
      delete native_node;
      return 0;
    }
    heyaki::LocalProfileInitialization initialization{
        .application_id = application,
        .password_verifier = std::move(*verifier.value_if()),
        .password_generation = 1U,
        .pairing_policy = heyaki::PairingPolicy{},
        .lan = heyaki::LanConfiguration{}};
    auto initialized = created.value_if()->initialize_local(initialization);
    if (!initialized) {
      fail_heyaki(env, *initialized.error_if());
      delete native_node;
      return 0;
    }
    native_node->profile.emplace(std::move(*created.value_if()));
  }

  auto node_config = build_node_config(*native_node->profile, *native_node->runtime, application,
                                       pairing_approval_enabled == JNI_TRUE);
  auto node = heyaki::Node::create(std::move(node_config));
  if (!node) {
    fail_heyaki(env, *node.error_if());
    delete native_node;
    return 0;
  }
  native_node->node.emplace(std::move(*node.value_if()));
  return reinterpret_cast<jlong>(native_node);
}

extern "C" JNIEXPORT jstring JNICALL
Java_dev_heyaki_core_HeyakiNode_nativeDeviceIdHex(JNIEnv* env, jclass /*clazz*/, jlong handle) {
  auto* native_node = as_handle(handle);
  if (native_node == nullptr || !native_node->node.has_value()) {
    fail_java(env, "HeyakiNode is closed");
    return nullptr;
  }
  return env->NewStringUTF(
      std::string{heyaki::to_string(native_node->profile->device_id())}.c_str());
}

extern "C" JNIEXPORT jobject JNICALL
Java_dev_heyaki_core_HeyakiNode_nativeSnapshot(JNIEnv* env, jclass /*clazz*/, jlong handle) {
  auto* native_node = as_handle(handle);
  if (native_node == nullptr || !native_node->node.has_value()) {
    fail_java(env, "HeyakiNode is closed");
    return nullptr;
  }
  return build_snapshot_summary(env, native_node->node->snapshot(),
                                native_node->node->peer_sessions().size());
}

extern "C" JNIEXPORT void JNICALL Java_dev_heyaki_core_HeyakiNode_nativeConnect(
    JNIEnv* env, jclass /*clazz*/, jlong handle, jstring device_hex, jstring endpoint_hex) {
  auto* native_node = as_handle(handle);
  if (native_node == nullptr || !native_node->node.has_value()) {
    fail_java(env, "HeyakiNode is closed");
    return;
  }
  const auto peer = parse_peer_key(env, device_hex, endpoint_hex);
  if (!peer) {
    return;
  }
  if (auto result = native_node->node->connect(*peer); !result) {
    fail_heyaki(env, *result.error_if());
  }
}

extern "C" JNIEXPORT void JNICALL Java_dev_heyaki_core_HeyakiNode_nativeConnectLan(
    JNIEnv* env, jclass /*clazz*/, jlong handle, jstring device_hex, jstring endpoint_hex) {
  auto* native_node = as_handle(handle);
  if (native_node == nullptr || !native_node->node.has_value()) {
    fail_java(env, "HeyakiNode is closed");
    return;
  }
  const auto peer = parse_peer_key(env, device_hex, endpoint_hex);
  if (!peer) {
    return;
  }
  if (auto result = native_node->node->connect_lan(*peer); !result) {
    fail_heyaki(env, *result.error_if());
  }
}

extern "C" JNIEXPORT void JNICALL Java_dev_heyaki_core_HeyakiNode_nativeCloseLan(
    JNIEnv* env, jclass /*clazz*/, jlong handle, jstring device_hex, jstring endpoint_hex) {
  auto* native_node = as_handle(handle);
  if (native_node == nullptr || !native_node->node.has_value()) {
    fail_java(env, "HeyakiNode is closed");
    return;
  }
  const auto peer = parse_peer_key(env, device_hex, endpoint_hex);
  if (!peer) {
    return;
  }
  if (auto result = native_node->node->close_lan(*peer); !result) {
    fail_heyaki(env, *result.error_if());
  }
}

extern "C" JNIEXPORT void JNICALL Java_dev_heyaki_core_HeyakiNode_nativeSetPairingRequestListener(
    JNIEnv* env, jclass /*clazz*/, jlong handle, jobject listener) {
  auto* native_node = as_handle(handle);
  if (native_node == nullptr || !native_node->node.has_value()) {
    fail_java(env, "HeyakiNode is closed");
    return;
  }
  native_node->clear_listener();
  if (listener == nullptr) {
    native_node->node->set_pairing_request_observer({});
    return;
  }
  jobject global = env->NewGlobalRef(listener);
  if (global == nullptr) {
    fail_java(env, "listener global ref allocation failed");
    return;
  }
  jclass listener_class = env->GetObjectClass(listener);
  jmethodID method = env->GetMethodID(listener_class, "onPairingRequest",
                                      "(Ldev/heyaki/core/HeyakiNode$PairingRequest;)V");
  env->DeleteLocalRef(listener_class);
  if (method == nullptr) {
    env->DeleteGlobalRef(global);
    fail_java(env, "PairingRequestListener.onPairingRequest not found");
    return;
  }
  native_node->listener.store(global, std::memory_order_release);
  native_node->listener_method.store(method, std::memory_order_release);
  native_node->node->set_pairing_request_observer(
      [native_node](const heyaki::DeviceEndpointKey& peer,
                    const heyaki::PairingApprovalRequestBody& request) {
        deliver_pairing_request(*native_node, peer, request);
      });
}

extern "C" JNIEXPORT void JNICALL Java_dev_heyaki_core_HeyakiNode_nativeApprovePairing(
    JNIEnv* env, jclass /*clazz*/, jlong handle, jstring device_hex, jstring endpoint_hex,
    jstring request_hex, jobjectArray scopes) {
  auto* native_node = as_handle(handle);
  if (native_node == nullptr || !native_node->node.has_value()) {
    fail_java(env, "HeyakiNode is closed");
    return;
  }
  const auto peer = parse_peer_key(env, device_hex, endpoint_hex);
  if (!peer) {
    return;
  }
  const auto request_id = parse_request_id(env, request_hex);
  if (!request_id) {
    return;
  }
  if (auto result =
          native_node->node->approve_pairing(*peer, *request_id, to_std_strings(env, scopes));
      !result) {
    fail_heyaki(env, *result.error_if());
  }
}

extern "C" JNIEXPORT void JNICALL Java_dev_heyaki_core_HeyakiNode_nativeRejectPairing(
    JNIEnv* env, jclass /*clazz*/, jlong handle, jstring device_hex, jstring endpoint_hex,
    jstring request_hex) {
  auto* native_node = as_handle(handle);
  if (native_node == nullptr || !native_node->node.has_value()) {
    fail_java(env, "HeyakiNode is closed");
    return;
  }
  const auto peer = parse_peer_key(env, device_hex, endpoint_hex);
  if (!peer) {
    return;
  }
  const auto request_id = parse_request_id(env, request_hex);
  if (!request_id) {
    return;
  }
  if (auto result = native_node->node->reject_pairing(*peer, *request_id); !result) {
    fail_heyaki(env, *result.error_if());
  }
}

extern "C" JNIEXPORT jlong JNICALL
Java_dev_heyaki_core_HeyakiNode_nativeRotateAuthorizationPassword(JNIEnv* env, jclass /*clazz*/,
                                                                  jlong handle,
                                                                  jstring new_password) {
  auto* native_node = as_handle(handle);
  if (native_node == nullptr || !native_node->node.has_value()) {
    fail_java(env, "HeyakiNode is closed");
    return 0;
  }
  auto result = native_node->node->rotate_authorization_password(to_std_string(env, new_password));
  if (!result) {
    fail_heyaki(env, *result.error_if());
    return 0;
  }
  return static_cast<jlong>(*result.value_if());
}

extern "C" JNIEXPORT jobject JNICALL
Java_dev_heyaki_core_HeyakiNode_nativeShutdown(JNIEnv* env, jclass /*clazz*/, jlong handle) {
  auto* native_node = as_handle(handle);
  if (native_node == nullptr) {
    return nullptr;
  }
  heyaki::NodeShutdownReport report;
  if (native_node->node.has_value()) {
    report = native_node->node->shutdown();
  }
  delete native_node;
  jclass report_class = env->FindClass("dev/heyaki/core/HeyakiNode$ShutdownReport");
  if (report_class == nullptr) {
    return nullptr;
  }
  const jmethodID constructor = env->GetMethodID(report_class, "<init>", "(ZZ)V");
  if (constructor == nullptr) {
    return nullptr;
  }
  return env->NewObject(report_class, constructor,
                        static_cast<jboolean>(report.stopped ? JNI_TRUE : JNI_FALSE),
                        static_cast<jboolean>(report.timed_out ? JNI_TRUE : JNI_FALSE));
}
