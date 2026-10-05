package dev.heyaki.core;

import java.util.List;

/**
 * Thin Android (JNI) boundary over the Heyaki {@code Node} session-lifecycle
 * and authorization API (M11-06).
 *
 * <p>Concurrency contract: this class creates no threads. All Heyaki work runs
 * on the executor-owned contexts inside the native node; the pairing-request
 * listener is invoked on one of those contexts (transiently attached to the
 * JVM) and must return promptly. Every method is serialized on this object's
 * monitor, and the instance is single-use: after {@link #close()} every call
 * throws {@link IllegalStateException}.
 *
 * <p>Lifecycle: constructing opens (or creates and initializes) the profile at
 * {@code profileDatabasePath}, starts the node, and the instance must be
 * {@link #close()}d exactly once. Closing stops the node and tears the native
 * pieces down in the fixed order node → profile → runtime.
 */
public final class HeyakiNode implements AutoCloseable {
  static {
    System.loadLibrary("heyaki_jni");
  }

  /** Receiver-side passwordless pairing request (pairing_approval_v1). */
  public static final class PairingRequest {
    public final String deviceIdHex;
    public final String endpointIdHex;
    public final String requestIdHex;
    public final List<String> requestedScopes;

    PairingRequest(
        String deviceIdHex, String endpointIdHex, String requestIdHex, List<String> scopes) {
      this.deviceIdHex = deviceIdHex;
      this.endpointIdHex = endpointIdHex;
      this.requestIdHex = requestIdHex;
      this.requestedScopes = scopes;
    }
  }

  /** Callback fired once per admitted passwordless pairing request. */
  public interface PairingRequestListener {
    void onPairingRequest(PairingRequest request);
  }

  /** Bounded view of the native {@code NodeSnapshot}. */
  public static final class SnapshotSummary {
    public final boolean lanEnabled;
    /** One of the {@code lan_readiness_state_name} values (ready/degraded/...). */
    public final String lanState;
    public final boolean relayConfigured;
    /** One of the {@code relay_node_state_name} values when relayConfigured. */
    public final String relayState;
    public final int peerSessionCount;
    public final long announcementsSent;
    public final long datagramsReceived;

    SnapshotSummary(
        boolean lanEnabled,
        String lanState,
        boolean relayConfigured,
        String relayState,
        int peerSessionCount,
        long announcementsSent,
        long datagramsReceived) {
      this.lanEnabled = lanEnabled;
      this.lanState = lanState;
      this.relayConfigured = relayConfigured;
      this.relayState = relayState;
      this.peerSessionCount = peerSessionCount;
      this.announcementsSent = announcementsSent;
      this.datagramsReceived = datagramsReceived;
    }
  }

  /** Outcome of {@link #close()}: one native {@code NodeShutdownReport}. */
  public static final class ShutdownReport {
    public final boolean stopped;
    public final boolean timedOut;

    ShutdownReport(boolean stopped, boolean timedOut) {
      this.stopped = stopped;
      this.timedOut = timedOut;
    }
  }

  private long nativeHandle;
  private ShutdownReport shutdownReport;

  /**
   * Opens the profile at {@code profileDatabasePath} (creating it with the
   * {@code initialPassword} verifier on first use), starts the node, and
   * enables passwordless pairing approval when {@code pairingApprovalEnabled}.
   *
   * @throws HeyakiException for any native failure (profile, runtime, or node)
   */
  public HeyakiNode(
      String profileDatabasePath,
      String applicationId,
      String initialPassword,
      boolean pairingApprovalEnabled)
      throws HeyakiException {
    nativeHandle = nativeCreate(profileDatabasePath, applicationId, initialPassword,
        pairingApprovalEnabled);
  }

  /** Local device identity (hex), from the opened profile. */
  public synchronized String deviceIdHex() {
    return nativeDeviceIdHex(requireHandle());
  }

  public synchronized SnapshotSummary snapshot() {
    return nativeSnapshot(requireHandle());
  }

  public synchronized void connect(String deviceIdHex, String endpointIdHex)
      throws HeyakiException {
    nativeConnect(requireHandle(), deviceIdHex, endpointIdHex);
  }

  public synchronized void connectLan(String deviceIdHex, String endpointIdHex)
      throws HeyakiException {
    nativeConnectLan(requireHandle(), deviceIdHex, endpointIdHex);
  }

  public synchronized void closeLan(String deviceIdHex, String endpointIdHex)
      throws HeyakiException {
    nativeCloseLan(requireHandle(), deviceIdHex, endpointIdHex);
  }

  /**
   * Registers the receiver-side pairing request listener. Replaces any prior
   * listener; {@code null} clears it. Called from a Heyaki executor context —
   * implementations must return promptly and must not call back into this
   * node synchronously from the callback.
   */
  public synchronized void setPairingRequestListener(PairingRequestListener listener) {
    nativeSetPairingRequestListener(requireHandle(), listener);
  }

  public synchronized void approvePairing(
      String deviceIdHex, String endpointIdHex, String requestIdHex, List<String> scopes)
      throws HeyakiException {
    nativeApprovePairing(requireHandle(), deviceIdHex, endpointIdHex, requestIdHex, scopes);
  }

  public synchronized void rejectPairing(
      String deviceIdHex, String endpointIdHex, String requestIdHex) throws HeyakiException {
    nativeRejectPairing(requireHandle(), deviceIdHex, endpointIdHex, requestIdHex);
  }

  /** Rotate-only password rotation; returns the new password generation. */
  public synchronized long rotateAuthorizationPassword(String newPassword)
      throws HeyakiException {
    return nativeRotateAuthorizationPassword(requireHandle(), newPassword);
  }

  /** The report of the {@link #close()} shutdown, or {@code null} before the first close. */
  public synchronized ShutdownReport shutdownReport() {
    return shutdownReport;
  }

  /** Stops the node and releases the native state; idempotent. */
  @Override
  public synchronized void close() {
    long handle = nativeHandle;
    nativeHandle = 0L;
    if (handle != 0L) {
      shutdownReport = nativeShutdown(handle);
    }
  }

  private long requireHandle() {
    if (nativeHandle == 0L) {
      throw new IllegalStateException("HeyakiNode is closed");
    }
    return nativeHandle;
  }

  private static native long nativeCreate(
      String profileDatabasePath, String applicationId, String initialPassword,
      boolean pairingApprovalEnabled) throws HeyakiException;

  private static native String nativeDeviceIdHex(long handle);

  private static native SnapshotSummary nativeSnapshot(long handle);

  private static native void nativeConnect(long handle, String deviceIdHex, String endpointIdHex)
      throws HeyakiException;

  private static native void nativeConnectLan(long handle, String deviceIdHex, String endpointIdHex)
      throws HeyakiException;

  private static native void nativeCloseLan(long handle, String deviceIdHex, String endpointIdHex)
      throws HeyakiException;

  private static native void nativeSetPairingRequestListener(long handle,
      PairingRequestListener listener);

  private static native void nativeApprovePairing(long handle, String deviceIdHex,
      String endpointIdHex, String requestIdHex, List<String> scopes) throws HeyakiException;

  private static native void nativeRejectPairing(long handle, String deviceIdHex,
      String endpointIdHex, String requestIdHex) throws HeyakiException;

  private static native long nativeRotateAuthorizationPassword(long handle, String newPassword)
      throws HeyakiException;

  private static native ShutdownReport nativeShutdown(long handle);
}
