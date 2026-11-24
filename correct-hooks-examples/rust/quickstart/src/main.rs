use axum::http::StatusCode;
use correct_hooks::{
  PublicVerifyingKeySet, SecretSigningKey, SignArgs, Verifier, VerifierConfig, VerifyArgs,
  create_public_verifying_key_set, generate_secret_signing_key, sign,
};
use uuid::Uuid;

#[tokio::main]
async fn main() {
  println!("{}", example().await);
}

fn create_secret_signing_key() -> SecretSigningKey {
  //=============================
  let secret_signing_key = generate_secret_signing_key();
  let secret_signing_key_json = serde_json::to_string(&secret_signing_key).unwrap();
  //=============================

  let _ = secret_signing_key_json;

  secret_signing_key
}

fn create_key_set(secret_signing_key: &SecretSigningKey) -> PublicVerifyingKeySet {
  //=============================
  let public_verifying_key_set =
    create_public_verifying_key_set(&[secret_signing_key.clone()]).unwrap();
  let public_verifying_key_set_json = serde_json::to_string(&public_verifying_key_set).unwrap();
  //=============================

  let _ = public_verifying_key_set_json;

  public_verifying_key_set
}

fn sign_request(
  secret_signing_key: &SecretSigningKey,
  target_id: Uuid,
  method: &str,
  request_body: &[u8],
) -> String {
  let webhook_id = Uuid::new_v4();

  //=============================
  let correct_hooks_signature = sign(SignArgs {
    webhook_id,
    target_id,
    method,
    request_body,
    secret_signing_key,
  })
  .unwrap();
  //=============================

  correct_hooks_signature
}

fn create_verifier() -> Verifier {
  let public_verifying_key_set_url = "https://webhookproducersdomain.com/known/path/to/key/set"
    .parse()
    .unwrap();

  //=============================
  let verifier = Verifier::new(VerifierConfig {
    public_verifying_key_set_url,
    signature_ttl_seconds: None,
    public_verifying_key_set_ttl_seconds: None,
  });
  //=============================

  verifier
}

async fn verify_request(
  verifier: &Verifier,
  target_id: Uuid,
  method: &str,
  correct_hooks_signature: &str,
  request_body: &[u8],
) -> StatusCode {
  //=============================
  let verify_result = verifier
    .verify(VerifyArgs {
      target_id,
      method,
      correct_hooks_signature,
      request_body,
    })
    .await;

  if verify_result.is_err() {
    return StatusCode::FORBIDDEN;
  }
  let verified_data = verify_result.unwrap();
  let webhook_id = verified_data.webhook_id;
  //=============================

  let _ = webhook_id;

  StatusCode::OK
}

async fn example() -> StatusCode {
  let secret_signing_key = create_secret_signing_key();
  let _ = create_key_set(&secret_signing_key);

  let target_id = Uuid::new_v4();
  let method = "POST";
  let request_body = "a payload".as_bytes();

  let correct_hooks_signature =
    sign_request(&secret_signing_key, target_id, method, request_body);

  let verifier = create_verifier();
  let status = verify_request(
    &verifier,
    target_id,
    method,
    &correct_hooks_signature,
    request_body,
  )
  .await;

  status
}
