use std::{
  collections::{HashMap, HashSet},
  sync::Arc,
  time::{SystemTime, UNIX_EPOCH},
};

use base64::{DecodeError, Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{
  KEYPAIR_LENGTH, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, Signature, Signer, SigningKey, VerifyingKey,
};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

/// The signature version produced by this version of the library.
pub const SIGNATURE_VERSION: &'static str = "v2";
const DEFAULT_SIGNATURE_TTL_SECONDS: u64 = 300;
const DEFAULT_PUBLIC_VERIFYING_KEY_SET_TTL_SECONDS: u64 = 300;

/// A key used to sign requests.
///
/// Must be kept secret and should only be held by the signer.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct SecretSigningKey {
  kid: Uuid,
  kty: String,
  crv: String,
  x: String,
  d: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
struct PublicJwk {
  kid: Uuid,
  kty: String,
  crv: String,
  x: String,
}

/// A set of public keys used to verify signed requests.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PublicVerifyingKeySet {
  keys: Vec<PublicJwk>,
}

struct SignatureMessageComponents<'a> {
  pub webhook_id: Uuid,
  pub key_id: Uuid,
  pub signed_at: u64,
  pub target_id: Uuid,
  pub method: &'a str,
  pub request_body: &'a [u8],
}

/// This struct is only public for internal testing purposes and will be made private in a future version of this library.
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SignatureHeaderComponents {
  pub webhook_id: Uuid,
  pub key_id: Uuid,
  pub signed_at: u64,
  pub signature: Vec<u8>,
}

/// Errors that can be returned from [`create_public_verifying_key_set`].
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub enum CreatePublicVerifyingKeySetError {
  InvalidKeyFound,
}

/// The arguments to the [`sign`] function.
#[derive(Clone, Copy)]
pub struct SignArgs<'a> {
  /// An id for the webhook.
  ///
  /// This id should be unique for the event triggering the webhook, and should
  /// be reused for any delivery retries.
  pub webhook_id: Uuid,
  /// The target_id for the webhook.
  ///
  /// This is a unique id assigned when a user registers an endpoint for webhook delivery. If the same endpoint is 
  /// registered more than once, a unique id should be generated every time. This id must be controlled by the webhook producer
  /// and not taken as an input from the webhook consumer
  pub target_id: Uuid,
  /// The HTTP method the webhook will be sent with.
  pub method: &'a str,
  /// The exact body of the webhook request as bytes.
  pub request_body: &'a [u8],
  /// The [`SecretSigningKey`] the signature will be signed with.
  pub secret_signing_key: &'a SecretSigningKey,
}



/// Errors returned by the [`sign`] function.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum SignError {
  InvalidArgs,
  InvalidSigningKey,
}

/// The arguments to [`Verifier::verify`] and [`Verifier::verify_with_time`].
#[derive(Debug, Clone, Copy)]
pub struct VerifyArgs<'a> {
  /// The target id assigned to a webhook target by the webhook producer,
  pub target_id: Uuid,
  /// The HTTP method the request was sent with. Can be extracted from the request.
  pub method: &'a str,
  /// The value from the request's `correct-hooks-signature` header.
  pub correct_hooks_signature: &'a str,
  /// The raw unparsed request body as bytes.
  pub request_body: &'a [u8],
}

/// Validated request data.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedData {
  /// The validated `webhook_id` for the request. These id's can be put in a shared cache
  /// by the webhook consumer and checked against for the highest level of replay protection.
  pub webhook_id: Uuid,
}

/// Errors returned by [`Verifier::verify`]. Receiving any of these errors indicates that a request
/// is invalid and should be rejected with a 4xx error code.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum VerifyError {
  /// The key needed to verify the request was not found in the verifying key set provided by the
  /// webhook provider.
  ///
  /// If you receive this error consistently, the webhook provider may need to update their
  /// published public verifying key set. In some specific cases, this error can also be returned
  /// due to an invalid signature.
  PublicVerifyingKeyNotFound,
  /// The webhook provider's public verifying key set could not be retrieved.
  ///
  /// If you get this error, likely either the `public_verifying_key_set_url` the [`Verifier`] was created with is incorrect,
  /// or the webhook producer's endpoint is unavailable.
  PublicVerifyingKeyRetrievalFailed,
  InvalidSignature,
  /// The public verifying key set retrieved from `public_verifying_key_set_url` could not be parsed and likely
  /// needs to be updated by the webhook producer.
  InvalidPublicVerifyingKey,
}

/// Generate a new [`SecretSigningKey`].
pub fn generate_secret_signing_key() -> SecretSigningKey {
  let key_id = Uuid::new_v4();
  let signing_key: SigningKey = SigningKey::generate(&mut rand::rng());
  let secret_key = encode_base64(signing_key.as_bytes());
  let public_key = encode_base64(signing_key.verifying_key().as_bytes());
  let jwk = SecretSigningKey {
    kid: key_id,
    kty: "OKP".to_string(),
    crv: "Ed25519".to_string(),
    x: public_key,
    d: secret_key,
  };

  jwk
}

/// Creates a [`PublicVerifyingKeySet`] from a list of [`SecretSigningKey`].
///
/// The returned [`PublicVerifyingKeySet`] can be used to verify requests signed
/// by any of the `secret_signing_keys`.
pub fn create_public_verifying_key_set(
  secret_signing_keys: &[SecretSigningKey],
) -> Result<PublicVerifyingKeySet, CreatePublicVerifyingKeySetError> {
  let mut public_jwks = PublicVerifyingKeySet { keys: vec![] };
  for private_key in secret_signing_keys {
    let public_key = PublicJwk {
      kid: private_key.kid,
      kty: "OKP".to_string(),
      crv: "Ed25519".to_string(),
      x: private_key.x.clone(),
    };
    public_jwks.keys.push(public_key);
  }
  Ok(public_jwks)
}

/// Header values to set on the webhook request.
///
/// You must set the request headers `correct-hooks-signature-components` and `correct-hooks-signature` to these values.
/// Webhook consumers will pass the values of the headers to the verify function. Future versions of Correct Hooks with
/// convenience functions that verify specific framework's request objects will expect these exact header names to be set.


/// Returns the signature for a webhook request.
///
/// You must set the request header `correct-hooks-signature` to the returned value.
/// Webhook consumers will pass the header value to the verify function. Future versions of Correct Hooks with
/// convenience functions that verify specific framework's request objects will expect the exact header name 
/// `correct-hooks-signature` to be set.
///
/// `sign` should be called every time a webhook delivery is attempted. The signed headers should not be reused
/// between delivery retries.
pub fn sign(args: SignArgs<'_>) -> Result<String, SignError> {
  let SignArgs {
    webhook_id,
    target_id,
    method,
    request_body,
    secret_signing_key,
  } = args;

  if webhook_id.get_version_num() != 4 {
    return Err(SignError::InvalidArgs);
  }

  if target_id.get_version_num() != 4 {
    return Err(SignError::InvalidArgs);
  }

  if !is_valid_http_method(method) {
    return Err(SignError::InvalidArgs);
  }

  let key_id = secret_signing_key.kid;
  let signed_at = seconds_since_unix_epoch();

  let secret_key_bytes =
    decode_base64(&secret_signing_key.d).map_err(|_| SignError::InvalidSigningKey)?;
  if secret_key_bytes.len() != SECRET_KEY_LENGTH {
    return Err(SignError::InvalidSigningKey);
  }
  let public_key_bytes =
    decode_base64(&secret_signing_key.x).map_err(|_| SignError::InvalidSigningKey)?;
  if public_key_bytes.len() != PUBLIC_KEY_LENGTH {
    return Err(SignError::InvalidSigningKey);
  }
  let mut signing_key_bytes = [0u8; KEYPAIR_LENGTH];
  signing_key_bytes[0..SECRET_KEY_LENGTH].copy_from_slice(&secret_key_bytes);
  signing_key_bytes[SECRET_KEY_LENGTH..KEYPAIR_LENGTH].copy_from_slice(&public_key_bytes);
  let signing_key =
    SigningKey::from_keypair_bytes(&signing_key_bytes).map_err(|_| SignError::InvalidSigningKey)?;

  let signature_message = construct_signature_message(
    SignatureMessageComponents{
      webhook_id,
      key_id,
      signed_at,
      target_id,
      method,
      request_body
    }
  );
  let signature = signing_key.sign(&signature_message);

  let signature_header = encode_signature_header(SignatureHeaderComponents { webhook_id, key_id, signed_at, signature: signature.to_bytes().into_iter().collect() });
  Ok(signature_header)
}

/// Arguments for creating a [`Verifier`].
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VerifierConfig {
  /// The url serving the webhook provider's verfiying key set.
  ///
  /// The webhook provider should give you this url.
  pub public_verifying_key_set_url: Url,
  /// How long a signature is considered valid. Defaults to 300 seconds (5 minutes).
  ///
  /// In most cases, the default parameter should be used.
  /// This parameter should not be set to a value larger than 300 (may be enforced in the future).
  #[serde(skip_serializing_if = "Option::is_none")]
  pub signature_ttl_seconds: Option<u64>,
  /// How long a retrieved `public_verifying_key_set` can be used before it is considered stale. Defaults to 300 seconds (5 minutes).
  ///
  /// In most cases, the default parameter should be used.
  /// This parameter should not be set to a value larger than 300 (may be enforced in the future).
  #[serde(skip_serializing_if = "Option::is_none")]
  pub public_verifying_key_set_ttl_seconds: Option<u64>,
}

#[derive(Clone, Debug)]
struct PublicVerifyingKeySetData {
  pub key_set: PublicVerifyingKeySet,
  pub refreshed_at: u64,
  pub refresh_id: Uuid,
}

/// Verifier for signed webhook requests
///
/// The [`Verifier`] handles retrieving and refreshing the webhook producer's verifying key set for you.
///
/// Ideally you should create one [`Verifier`] when your backend instance starts and reuse it for all requests sent to that backend instance.
///
/// You do not have to wrap the [`Verifier`] in an [`Rc`](std::rc::Rc) or [`Arc`] to reuse it because it already uses [`Arc`]s internally.
#[derive(Clone, Debug)]
pub struct Verifier {
  public_verifying_key_set_url: Url,
  signature_ttl_seconds: u64,
  public_verifying_key_set_ttl_seconds: u64,
  public_verifying_key_set: Arc<std::sync::RwLock<Arc<PublicVerifyingKeySetData>>>,
  public_verifying_key_set_refresh_lock: Arc<tokio::sync::Mutex<()>>,
  http_client: Client,
}

// Todo: Add an alternate constructor for the verifier that takes a jwks directly for testing.
impl Verifier {
  /// Create a new [`Verifier`].
  pub fn new(config: VerifierConfig) -> Verifier {
    let public_verifying_key_set = Arc::new(std::sync::RwLock::new(Arc::new(
      PublicVerifyingKeySetData {
        key_set: PublicVerifyingKeySet { keys: vec![] },
        refreshed_at: 0,
        refresh_id: Uuid::new_v4(),
      },
    )));
    let public_verifying_key_set_refresh_lock = Arc::new(tokio::sync::Mutex::new(()));
    Verifier {
      public_verifying_key_set_url: config.public_verifying_key_set_url,
      signature_ttl_seconds: config
        .signature_ttl_seconds
        .unwrap_or(DEFAULT_SIGNATURE_TTL_SECONDS),
      public_verifying_key_set_ttl_seconds: config
        .public_verifying_key_set_ttl_seconds
        .unwrap_or(DEFAULT_PUBLIC_VERIFYING_KEY_SET_TTL_SECONDS),
      public_verifying_key_set,
      public_verifying_key_set_refresh_lock,
      http_client: reqwest::Client::new(),
    }
  }

  /// Verifies a request and returns validated information from the Correct Hooks request headers.
  ///
  /// This function confirms that the provided request signature is valid, that the signature has not expired, and that the request was sent to the intended endpoint.
  ///
  /// Any returned error indicates that the signature could not be verified and the request should be rejected with a 4xx error
  pub async fn verify(&self, args: VerifyArgs<'_>) -> Result<VerifiedData, VerifyError> {
    let now = seconds_since_unix_epoch();
    self.verify_with_time(args, now).await
  }

  /// The same as [`Verifier::verify`] but with the current time provided by the caller, which
  /// can be useful for testing.
  ///
  /// # Arguments
  /// * args - The request data to verify
  /// * `now` - The current time in seconds since Unix epoch.
  pub async fn verify_with_time(
    &self,
    args: VerifyArgs<'_>,
    now: u64,
  ) -> Result<VerifiedData, VerifyError> {
    let public_verifying_key_set = self.current_key_set();
    if now > public_verifying_key_set.refreshed_at + self.public_verifying_key_set_ttl_seconds {
      let _ = self.refresh_jwks(public_verifying_key_set.refresh_id).await;
    }

    let public_verifying_key_set = self.current_key_set();
    let result = verify_with_time(
      args,
      self.signature_ttl_seconds,
      &public_verifying_key_set.key_set,
      now,
    );
    if let Err(VerifyError::PublicVerifyingKeyNotFound) = result {
      if self
        .refresh_jwks(public_verifying_key_set.refresh_id)
        .await
        .is_err()
      {
        return Err(VerifyError::PublicVerifyingKeyRetrievalFailed);
      }
      let public_verifying_key_set = self.current_key_set();
      return verify_with_time(
        args,
        self.signature_ttl_seconds,
        &public_verifying_key_set.key_set,
        now,
      );
    }
    return result;
  }

  async fn refresh_jwks(&self, old_refresh_id: Uuid) -> Result<(), VerifyError> {
    let _refresh_lock = self.public_verifying_key_set_refresh_lock.lock().await;
    let current_public_verifying_key_set = self.current_key_set();
    if current_public_verifying_key_set.refresh_id != old_refresh_id {
      return Ok(());
    }

    let response = self
      .http_client
      .get(self.public_verifying_key_set_url.clone())
      .send()
      .await
      .map_err(|_| VerifyError::PublicVerifyingKeyRetrievalFailed)?;
    if response.status() != StatusCode::OK {
      return Err(VerifyError::PublicVerifyingKeyRetrievalFailed);
    }
    let key_set_json = response
      .json::<serde_json::Value>()
      .await
      .map_err(|_| VerifyError::PublicVerifyingKeyRetrievalFailed)?;
    let key_set = parse_public_verifying_key_set(key_set_json)
      .map_err(|_| VerifyError::PublicVerifyingKeyRetrievalFailed)?;

    let new_refresh_time = seconds_since_unix_epoch();
    let new_public_verifying_key_set = Arc::new(PublicVerifyingKeySetData {
      key_set,
      refreshed_at: new_refresh_time,
      refresh_id: Uuid::new_v4(),
    });

    *self.public_verifying_key_set.write().unwrap() = new_public_verifying_key_set;
    Ok(())
  }

  fn current_key_set(&self) -> Arc<PublicVerifyingKeySetData> {
    self.public_verifying_key_set.read().unwrap().clone()
  }
}

/// This function is only public for internal testing purposes and will be made private in a future version of this library.
pub fn verify_with_time(
  args: VerifyArgs<'_>,
  signature_ttl_seconds: u64,
  public_verifying_key_set: &PublicVerifyingKeySet,
  now: u64,
) -> Result<VerifiedData, VerifyError> {
  let VerifyArgs {
    target_id,
    method,
    correct_hooks_signature,
    request_body,
  } = args;
  let signature_components_encoded = split_versioned_header(correct_hooks_signature)?
    .get(SIGNATURE_VERSION)
    .ok_or(VerifyError::InvalidSignature)?
    .clone();
  let signature_components = decode_signature_header(&signature_components_encoded)
    .map_err(|_| VerifyError::InvalidSignature)?;

  if now > (signature_components.signed_at + signature_ttl_seconds)
    || now + signature_ttl_seconds < signature_components.signed_at
  {
    return Err(VerifyError::InvalidSignature);
  }

  let verifying_key_jwk = public_verifying_key_set
    .keys
    .iter()
    .find(|x| x.kid == signature_components.key_id)
    .ok_or(VerifyError::PublicVerifyingKeyNotFound)?;
  let public_key_bytes =
    decode_base64(&verifying_key_jwk.x).map_err(|_| VerifyError::InvalidPublicVerifyingKey)?;
  if public_key_bytes.len() != PUBLIC_KEY_LENGTH {
    return Err(VerifyError::InvalidPublicVerifyingKey);
  };
  let mut verifying_key_bytes = [0u8; PUBLIC_KEY_LENGTH];
  verifying_key_bytes[0..PUBLIC_KEY_LENGTH].copy_from_slice(&public_key_bytes);
  let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes)
    .map_err(|_| VerifyError::InvalidPublicVerifyingKey)?;

  let signature_message = construct_signature_message(
    SignatureMessageComponents{
      webhook_id: signature_components.webhook_id,
      key_id: signature_components.key_id,
      signed_at: signature_components.signed_at,
      target_id,
      method,
      request_body,
    }
  );

  let signature = Signature::from_slice(&signature_components.signature)
    .map_err(|_| VerifyError::InvalidSignature)?;

  let signature_is_valid = verifying_key
    .verify_strict(&signature_message, &signature)
    .is_ok();
  if !signature_is_valid {
    return Err(VerifyError::InvalidSignature);
  }

  Ok(VerifiedData {
    webhook_id: signature_components.webhook_id,
  })
}

fn construct_signature_message(
  components: SignatureMessageComponents,
) -> Vec<u8> {
  let webhook_id_base64 = encode_base64_from_string(&components.webhook_id.to_string());
  let key_id_base64 = encode_base64_from_string(&components.key_id.to_string());
  let signed_at_base64 = encode_base64_from_string(&components.signed_at.to_string());
  let target_id_base64 = encode_base64_from_string(&components.target_id.to_string());
  let method = components.method;
  let mut signature_message =
    format!("{webhook_id_base64}.{key_id_base64}.{signed_at_base64}.{target_id_base64}.{method}.")
      .bytes()
      .collect::<Vec<_>>();
  signature_message.extend(components.request_body);
  signature_message
}

/// This function is only public for internal testing purposes and will be made private in a future version of this library.
pub fn version_header_value(header_value: &str) -> String {
  format!("{SIGNATURE_VERSION},{header_value}")
}

/// This function is only public for internal testing purposes and will be made private in a future version of this library.
pub fn split_versioned_header(header: &str) -> Result<HashMap<String, String>, VerifyError> {
  let mut split_headers = HashMap::new();
  for versioned_value in header.split(' ') {
    let mut version_it = versioned_value.split(',');
    let version = version_it.next();
    let value = version_it.next();
    if version.is_none() || value.is_none() {
      continue;
    }
    let version = version.unwrap().to_string();
    let value = value.unwrap().to_string();
    if split_headers.contains_key(&version) {
      return Err(VerifyError::InvalidSignature);
    }
    split_headers.insert(version, value);
  }
  Ok(split_headers)
}

fn encode_signature_header(
  components: SignatureHeaderComponents
) -> String {
  let webhook_id_base64 = encode_base64_from_string(&components.webhook_id.to_string());
  let key_id_base64 = encode_base64_from_string(&components.key_id.to_string());
  let signed_at_base64 = encode_base64_from_string(&components.signed_at.to_string());
  let signature_base64 = encode_base64(&components.signature);

  format!("{SIGNATURE_VERSION},{webhook_id_base64}.{key_id_base64}.{signed_at_base64}.{signature_base64}")
}

/// This function is only public for internal testing purposes and will be made private in a future version of this library.
pub fn decode_signature_header(
  encoded_signature_components: &str,
) -> Result<SignatureHeaderComponents, String> {
  let components = encoded_signature_components.split('.').collect::<Vec<_>>();
  if components.len() != 4 {
    return Err("Invalid component count".to_owned());
  }
  let webhook_id = decode_base64_to_string(components[0])?
    .parse()
    .map_err(|_| "invalid webhook_id".to_owned())?;
  let key_id = decode_base64_to_string(components[1])?
    .parse()
    .map_err(|_| "invalid key_id".to_owned())?;
  let signed_at = decode_base64_to_string(components[2])?
    .parse()
    .map_err(|_| "invalid timestamp".to_owned())?;
  let signature = decode_base64(components[3])
    .map_err(|_| "invalid signature".to_owned())?;

  let result = Ok(SignatureHeaderComponents {
    webhook_id,
    key_id,
    signed_at,
    signature
  });

  result
}

fn parse_public_verifying_key_set(
  json_key_set: serde_json::Value,
) -> Result<PublicVerifyingKeySet, String> {
  #[derive(Deserialize)]
  #[serde(deny_unknown_fields)]
  struct PublicVerifyingKeySetPartialParse {
    keys: Vec<serde_json::Value>,
  }
  let partially_parsed_key_set =
    serde_json::from_value::<PublicVerifyingKeySetPartialParse>(json_key_set)
      .map_err(|_| "key set parse failed".to_owned())?;

  // Keys that are not an exact match for PublicJwk fields give an error and are excluded.
  let parsed_keys = partially_parsed_key_set
    .keys
    .into_iter()
    .map(|jwk| serde_json::from_value::<PublicJwk>(jwk))
    .flatten()
    .collect::<Vec<_>>();

  // Duplicate key ids in a key set are not allowed
  let mut key_ids = HashSet::new();
  for key in parsed_keys.iter() {
    if key_ids.contains(&key.kid) {
      return Err("found duplicate key id".to_owned());
    }
    key_ids.insert(key.kid);
  }

  Ok(PublicVerifyingKeySet { keys: parsed_keys })
}

fn is_valid_http_method(method: &str) -> bool {
  matches!(
    method,
    "GET" | "HEAD" | "POST" | "PUT" | "DELETE" | "CONNECT" | "OPTIONS" | "TRACE" | "PATCH"
  )
}

/// This function is only public for internal testing purposes and will be made private in a future version of this library.
pub fn encode_base64(data: &[u8]) -> String {
  URL_SAFE_NO_PAD.encode(data)
}

/// This function is only public for internal testing purposes and will be made private in a future version of this library.
pub fn decode_base64(base64_str: &str) -> Result<Vec<u8>, DecodeError> {
  URL_SAFE_NO_PAD.decode(base64_str)
}

fn encode_base64_from_string(data: &str) -> String {
  encode_base64(data.as_bytes())
}

fn decode_base64_to_string(base64_str: &str) -> Result<String, String> {
  let data = decode_base64(base64_str).map_err(|_| "base64 decode error".to_owned())?;
  String::from_utf8(data).map_err(|_| "utf-8 failure".to_owned())
}

/// This function is only public for internal testing purposes and will be made private in a future version of this library.
pub fn seconds_since_unix_epoch() -> u64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap()
    .as_secs() as u64
}
