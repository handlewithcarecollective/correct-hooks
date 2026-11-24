use axum::http::StatusCode;
use correct_hooks::{
  SignArgs, Verifier, VerifierConfig, VerifyArgs, create_public_verifying_key_set,
  generate_secret_signing_key, sign,
};

#[tokio::main]
async fn main() {
  println!("{}", example().await);
}

async fn example() -> StatusCode {
  // Create a secret signing key and serialize it to a json string
  // Store the string in your secret manager
  let secret_signing_key = generate_secret_signing_key();
  let secret_signing_key_json = serde_json::to_string(&secret_signing_key).unwrap();

  let _ = secret_signing_key_json;

  // Create a public verifying key set for a list of signing keys and serialize it to a json string
  // Store the string in your database
  // Serve the json string at a known `GET` endpoint, `public_verifying_key_set_url`
  let public_verifying_key_set =
    create_public_verifying_key_set(&[secret_signing_key.clone()]).unwrap();
  let public_verifying_key_set_json = serde_json::to_string(&public_verifying_key_set).unwrap();

  let _ = public_verifying_key_set_json;

  // Sign a webhook request (webhook producer side).
  // `target_id` is assigned by the producer when the consumer registers an endpoint.
  let webhook_id = uuid::Uuid::new_v4();
  let target_id = uuid::Uuid::new_v4();

  let method = "POST";
  let request_body = "a payload".as_bytes();

  // Send the returned string in the `correct-hooks-signature` header
  let correct_hooks_signature = sign(SignArgs {
    webhook_id,
    target_id,
    method,
    request_body,
    secret_signing_key: &secret_signing_key,
  })
  .unwrap();

  let public_verifying_key_set_url = "https://webhookproducersdomain.com/known/path/to/key/set"
    .parse()
    .unwrap();

  // Create a verifier with the webhook producer's `public_verifying_key_set_url`.
  // Reuse it to validate all requests sent to this instance
  let verifier = Verifier::new(VerifierConfig {
    public_verifying_key_set_url,
    signature_ttl_seconds: None,
    public_verifying_key_set_ttl_seconds: None,
  });

  // Verify a request with the verifier
  // Any error indicates that the signature is invalid and the request should
  // be immediately rejected.
  let verified_data = match verifier
    .verify(VerifyArgs {
      target_id,
      method,
      correct_hooks_signature: &correct_hooks_signature,
      request_body,
    })
    .await
  {
    Ok(verified_data) => verified_data,
    Err(_) => return StatusCode::FORBIDDEN,
  };

  let _ = verified_data;

  StatusCode::OK
}
