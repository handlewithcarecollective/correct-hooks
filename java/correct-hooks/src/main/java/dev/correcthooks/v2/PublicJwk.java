package dev.correcthooks.v2;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.UUID;

@JsonIgnoreProperties(ignoreUnknown = false)
final class PublicJwk {
  public final UUID kid;
  public final String kty;
  public final String crv;
  public final String x;

  @JsonCreator
  PublicJwk(
      @JsonProperty(value = "kid", required = true) UUID kid,
      @JsonProperty(value = "kty", required = true) String kty,
      @JsonProperty(value = "crv", required = true) String crv,
      @JsonProperty(value = "x", required = true) String x) {
    this.kid = kid;
    this.kty = kty;
    this.crv = crv;
    this.x = x;
  }
}
