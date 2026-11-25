package dev.correcthooks.v2;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.net.URL;

/** Arguments for creating a {@link Verifier}. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public final class VerifierConfig {
  /**
   * The url serving the webhook provider's verifying key set.
   *
   * <p>The webhook provider should give you this url.
   */
  public final URL publicVerifyingKeySetUrl;

  /**
   * How long a signature is considered valid. Defaults to 300 seconds (5 minutes) when null.
   *
   * <p>In most cases, the default parameter should be used. This parameter should not be set to a
   * value larger than 300 (may be enforced in the future).
   */
  public final Long signatureTtlSeconds;

  /**
   * How long a retrieved {@code publicVerifyingKeySet} can be used before it is considered stale.
   * Defaults to 300 seconds (5 minutes) when null.
   *
   * <p>In most cases, the default parameter should be used. This parameter should not be set to a
   * value larger than 300 (may be enforced in the future).
   */
  public final Long publicVerifyingKeySetTtlSeconds;

  @JsonCreator
  public VerifierConfig(
      @JsonProperty(value = "publicVerifyingKeySetUrl", required = true)
          URL publicVerifyingKeySetUrl,
      @JsonProperty("signatureTtlSeconds") Long signatureTtlSeconds,
      @JsonProperty("publicVerifyingKeySetTtlSeconds") Long publicVerifyingKeySetTtlSeconds) {
    this.publicVerifyingKeySetUrl = publicVerifyingKeySetUrl;
    this.signatureTtlSeconds = signatureTtlSeconds;
    this.publicVerifyingKeySetTtlSeconds = publicVerifyingKeySetTtlSeconds;
  }

  public VerifierConfig(URL publicVerifyingKeySetUrl) {
    this(publicVerifyingKeySetUrl, null, null);
  }
}
