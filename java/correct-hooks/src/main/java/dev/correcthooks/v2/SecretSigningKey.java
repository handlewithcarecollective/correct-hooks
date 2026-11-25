package dev.correcthooks.v2;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;
import java.util.UUID;

/**
 * A key used to sign requests.
 *
 * <p>Must be kept secret and should only be held by the signer.
 */
public final class SecretSigningKey {
  public final UUID kid;
  public final String kty;
  public final String crv;
  public final String x;
  public final String d;

  @JsonCreator
  public SecretSigningKey(
      @JsonProperty(value = "kid", required = true) UUID kid,
      @JsonProperty(value = "kty", required = true) String kty,
      @JsonProperty(value = "crv", required = true) String crv,
      @JsonProperty(value = "x", required = true) String x,
      @JsonProperty(value = "d", required = true) String d) {
    this.kid = kid;
    this.kty = kty;
    this.crv = crv;
    this.x = x;
    this.d = d;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof SecretSigningKey)) {
      return false;
    }
    SecretSigningKey other = (SecretSigningKey) o;
    return kid.equals(other.kid)
        && kty.equals(other.kty)
        && crv.equals(other.crv)
        && x.equals(other.x)
        && d.equals(other.d);
  }

  @Override
  public int hashCode() {
    return Objects.hash(kid, kty, crv, x, d);
  }
}
