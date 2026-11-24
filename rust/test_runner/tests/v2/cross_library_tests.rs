use correct_hooks::v2::{
  SignArgs, VerifyArgs, create_public_verifying_key_set, generate_secret_signing_key, sign,
  verify_with_time,
};
use test_runner::test_client_v2::{CorrectHooksTestClient, decode_signature_header_test};

#[tokio::test]
#[async_backtrace::framed]
async fn generate_key_test() {
  let target_id = "9f1c2a4e-3b7d-4c58-a6e1-52d8b0c47f93".parse().unwrap();
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba".parse().unwrap();
  let method = "POST";
  let request_body = "{\"testfield\": 234}".to_string().as_bytes().to_vec();
  let signature_ttl_seconds = 300;

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key = test_library.generate_secret_signing_key().await;
  let public_key_set = create_public_verifying_key_set(&vec![signing_key.clone()]).unwrap();

  let signature_header = sign(SignArgs {
    webhook_id,
    target_id,
    method,
    request_body: &request_body,
    secret_signing_key: &signing_key,
  })
  .unwrap();

  let signature_components = decode_signature_header_test(&signature_header);

  let verify_result = verify_with_time(
    VerifyArgs {
      target_id,
      method,
      correct_hooks_signature: &signature_header,
      request_body: &request_body,
    },
    signature_ttl_seconds,
    &public_key_set,
    signature_components.signed_at + 1,
  )
  .unwrap();

  assert_eq!(verify_result.webhook_id, signature_components.webhook_id);
}

#[tokio::test]
#[async_backtrace::framed]
async fn create_public_verifying_key_set_test() {
  let target_id = "9f1c2a4e-3b7d-4c58-a6e1-52d8b0c47f93".parse().unwrap();
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba".parse().unwrap();
  let method = "POST";
  let request_body = "{\"testfield\": 234}".to_string().as_bytes().to_vec();
  let signature_ttl_seconds = 300;

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key = generate_secret_signing_key();
  let public_key_set = test_library
    .create_public_verifying_key_set(&vec![signing_key.clone()])
    .await
    .unwrap();

  let signature_header = sign(SignArgs {
    webhook_id,
    target_id,
    method,
    request_body: &request_body,
    secret_signing_key: &signing_key,
  })
  .unwrap();

  let signature_components = decode_signature_header_test(&signature_header);

  let verify_result = verify_with_time(
    VerifyArgs {
      target_id,
      method,
      correct_hooks_signature: &signature_header,
      request_body: &request_body,
    },
    signature_ttl_seconds,
    &public_key_set,
    signature_components.signed_at + 1,
  )
  .unwrap();

  assert_eq!(verify_result.webhook_id, signature_components.webhook_id);
}

#[tokio::test]
#[async_backtrace::framed]
async fn sign_webhook_test() {
  let target_id = "9f1c2a4e-3b7d-4c58-a6e1-52d8b0c47f93".parse().unwrap();
  // values lead to base64 encoding with special characters and uneven bytes (that would be padded if the encoder used padding)
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba".parse().unwrap();
  let method = "POST";
  let request_body = "{\"testfield\": \">>>???\"}"
    .to_string()
    .as_bytes()
    .to_vec();
  let signature_ttl_seconds = 300;

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key = generate_secret_signing_key();
  let public_key_set = create_public_verifying_key_set(&vec![signing_key.clone()]).unwrap();

  let signature_header = test_library
    .sign(SignArgs {
      webhook_id,
      target_id,
      method,
      request_body: &request_body,
      secret_signing_key: &signing_key,
    })
    .await
    .unwrap();

  let signature_components = decode_signature_header_test(&signature_header);

  let verify_result = verify_with_time(
    VerifyArgs {
      target_id,
      method,
      correct_hooks_signature: &signature_header,
      request_body: &request_body,
    },
    signature_ttl_seconds,
    &public_key_set,
    signature_components.signed_at + 1,
  )
  .unwrap();

  assert_eq!(verify_result.webhook_id, signature_components.webhook_id);
}

#[tokio::test]
#[async_backtrace::framed]
async fn verify_webhook_test() {
  let target_id = "9f1c2a4e-3b7d-4c58-a6e1-52d8b0c47f93".parse().unwrap();
  // values lead to base64 encoding with special characters and uneven bytes (that would be padded if the encoder used padding)
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba".parse().unwrap();
  let method = "POST";
  let request_body = "{\"testfield\": \">>>???\"}"
    .to_string()
    .as_bytes()
    .to_vec();
  let signature_ttl_seconds = 300;

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key = generate_secret_signing_key();
  let public_key_set = create_public_verifying_key_set(&vec![signing_key.clone()]).unwrap();

  let signature_header = sign(SignArgs {
    webhook_id,
    target_id,
    method,
    request_body: &request_body,
    secret_signing_key: &signing_key,
  })
  .unwrap();

  let signature_components = decode_signature_header_test(&signature_header);

  let verify_result = test_library
    .verify_with_time(
      VerifyArgs {
        target_id,
        method,
        correct_hooks_signature: &signature_header,
        request_body: &request_body,
      },
      signature_ttl_seconds,
      &public_key_set,
      signature_components.signed_at + 1,
    )
    .await
    .unwrap();

  assert_eq!(verify_result.webhook_id, signature_components.webhook_id);
}

#[tokio::test]
#[async_backtrace::framed]
async fn identical_signature_test() {
  let target_id = "9f1c2a4e-3b7d-4c58-a6e1-52d8b0c47f93".parse().unwrap();
  // values lead to base64 encoding with special characters and uneven bytes (that would be padded if the encoder used padding)
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba".parse().unwrap();
  let method = "POST";
  let request_body = "{\"testfield\": \">>>???\"}"
    .to_string()
    .as_bytes()
    .to_vec();

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key = generate_secret_signing_key();

  let signature_header_base = sign(SignArgs {
    webhook_id,
    target_id,
    method,
    request_body: &request_body,
    secret_signing_key: &signing_key,
  })
  .unwrap();
  let signature_header_lib = test_library
    .sign(SignArgs {
      webhook_id,
      target_id,
      method,
      request_body: &request_body,
      secret_signing_key: &signing_key,
    })
    .await
    .unwrap();

  assert_eq!(signature_header_base, signature_header_lib);
}
