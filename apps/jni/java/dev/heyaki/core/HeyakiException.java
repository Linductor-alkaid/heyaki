package dev.heyaki.core;

/** One native Heyaki failure: the stable {@code ErrorCode} name and detail. */
public class HeyakiException extends Exception {
  public final String code;
  public final String safeDetail;

  public HeyakiException(String code, String safeDetail) {
    super(code + ": " + safeDetail);
    this.code = code;
    this.safeDetail = safeDetail;
  }
}
