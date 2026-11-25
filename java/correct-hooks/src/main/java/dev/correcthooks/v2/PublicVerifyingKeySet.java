package dev.correcthooks.v2;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/** A set of public keys used to verify signed requests. */
public final class PublicVerifyingKeySet {
  final List<PublicJwk> keys;

  @JsonCreator
  PublicVerifyingKeySet(@JsonProperty(value = "keys", required = true) List<PublicJwk> keys) {
    this.keys = keys;
  }

  @JsonProperty("keys")
  List<PublicJwk> getKeys() {
    return keys;
  }
}
