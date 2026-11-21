use correct_hooks::v2::{SIGNATURE_VERSION, SignArgs, VerifyArgs};
use test_runner::test_client_v2::{CorrectHooksTestClient, decode_signature_header_test};

#[tokio::test]
#[async_backtrace::framed]
async fn sign_verify_test() {
  let target_id = "9f1c2a4e-3b7d-4c58-a6e1-52d8b0c47f93".parse().unwrap();
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba".parse().unwrap();
  let method = "POST";
  let request_body = "{\"testfield\": 234}".to_string().as_bytes().to_vec();
  let signature_ttl_seconds = 300;

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key = test_library.generate_secret_signing_key().await;
  let public_key_set = test_library
    .create_public_verifying_key_set(&vec![signing_key.clone()])
    .await
    .unwrap();

  let webhook_headers = test_library
    .sign(SignArgs {
      webhook_id,
      target_id,
      method,
      request_body: &request_body,
      secret_signing_key: &signing_key,
    })
    .await
    .unwrap();

  let signature_components =
    decode_signature_header_test(&webhook_headers);

  let verify_result = test_library
    .verify_with_time(
      VerifyArgs {
        target_id,
        method,
        correct_hooks_signature: &webhook_headers,
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
async fn sign_verify_large_body_test() {
  let target_id = "9f1c2a4e-3b7d-4c58-a6e1-52d8b0c47f93".parse().unwrap();
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba".parse().unwrap();
  let method = "POST";
  let request_body = (0..100000).map(|_| rand::random()).collect::<Vec<u8>>();
  let signature_ttl_seconds = 300;

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key = test_library.generate_secret_signing_key().await;
  let public_key_set = test_library
    .create_public_verifying_key_set(&vec![signing_key.clone()])
    .await
    .unwrap();

  let webhook_headers = test_library
    .sign(SignArgs {
      webhook_id,
      target_id,
      method,
      request_body: &request_body,
      secret_signing_key: &signing_key,
    })
    .await
    .unwrap();

  let signature_components =
    decode_signature_header_test(&webhook_headers);

  let verify_result = test_library
    .verify_with_time(
      VerifyArgs {
        target_id,
        method,
        correct_hooks_signature: &webhook_headers,
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
async fn multiple_public_keys_test() {
  let target_id = "9f1c2a4e-3b7d-4c58-a6e1-52d8b0c47f93".parse().unwrap();
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba".parse().unwrap();
  let method = "POST";
  let request_body = "{\"testfield\": 234}".to_string().as_bytes().to_vec();
  let signature_ttl_seconds = 300;

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key_1 = test_library.generate_secret_signing_key().await;
  let signing_key_2 = test_library.generate_secret_signing_key().await;
  let public_key_set = test_library
    .create_public_verifying_key_set(&vec![signing_key_1.clone(), signing_key_2.clone()])
    .await
    .unwrap();

  let webhook_headers_1 = test_library
    .sign(SignArgs {
      webhook_id,
      target_id,
      method,
      request_body: &request_body,
      secret_signing_key: &signing_key_1,
    })
    .await
    .unwrap();

  let signature_components_1 =
    decode_signature_header_test(&webhook_headers_1);

  let verify_result = test_library
    .verify_with_time(
      VerifyArgs {
        target_id,
        method,
        correct_hooks_signature: &webhook_headers_1,
        request_body: &request_body,
      },
      signature_ttl_seconds,
      &public_key_set,
      signature_components_1.signed_at + 1,
    )
    .await
    .unwrap();

  assert_eq!(verify_result.webhook_id, signature_components_1.webhook_id);

  let webhook_headers_2 = test_library
    .sign(SignArgs {
      webhook_id,
      target_id,
      method,
      request_body: &request_body,
      secret_signing_key: &signing_key_2,
    })
    .await
    .unwrap();

  let signature_components_2 =
    decode_signature_header_test(&webhook_headers_2);

  let verify_result = test_library
    .verify_with_time(
      VerifyArgs {
        target_id,
        method,
        correct_hooks_signature: &webhook_headers_2,
        request_body: &request_body,
      },
      signature_ttl_seconds,
      &public_key_set,
      signature_components_2.signed_at + 1,
    )
    .await
    .unwrap();

  assert_eq!(verify_result.webhook_id, signature_components_2.webhook_id);
}

#[tokio::test]
#[async_backtrace::framed]
async fn sign_verify_unused_versions_test() {
  let target_id = "9f1c2a4e-3b7d-4c58-a6e1-52d8b0c47f93".parse().unwrap();
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba".parse().unwrap();
  let method = "POST";
  let request_body = "{\"testfield\": 234}".to_string().as_bytes().to_vec();
  let signature_ttl_seconds = 300;

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key = test_library.generate_secret_signing_key().await;
  let signing_key_alt = test_library.generate_secret_signing_key().await;

  let public_key_set = test_library
    .create_public_verifying_key_set(&vec![signing_key.clone()])
    .await
    .unwrap();

  let webhook_headers = test_library
    .sign(SignArgs {
      webhook_id,
      target_id,
      method,
      request_body: &request_body,
      secret_signing_key: &signing_key,
    })
    .await
    .unwrap();

  let mut header_alt = test_library
    .sign(SignArgs {
      webhook_id,
      target_id,
      method,
      request_body: &request_body,
      secret_signing_key: &signing_key_alt,
    })
    .await
    .unwrap();

  let mut header_invalid = header_alt.clone();
  header_invalid.insert(10, '~');

  let signature_version = SIGNATURE_VERSION[1..].parse::<usize>().unwrap();

  header_alt = header_alt.replace(SIGNATURE_VERSION, &format!("v{}", signature_version + 1));
  header_invalid = header_invalid.replace(SIGNATURE_VERSION, &format!("v{}", signature_version + 2));

  let joined_webhook_header = vec![
    header_alt,
    webhook_headers.clone(),
    header_invalid,
  ]
  .join(" ");
  let signature_components =
    decode_signature_header_test(&webhook_headers);

  let verify_result = test_library
    .verify_with_time(
      VerifyArgs {
        target_id,
        method,
        correct_hooks_signature: &joined_webhook_header,
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
async fn sign_verify_old_versions_test() {
  let target_id = "9f1c2a4e-3b7d-4c58-a6e1-52d8b0c47f93".parse().unwrap();
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba".parse().unwrap();
  let method = "POST";
  let request_body = "{\"testfield\": 234}".to_string().as_bytes().to_vec();
  let signature_ttl_seconds = 300;

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key = test_library.generate_secret_signing_key().await;

  let public_key_set = test_library
    .create_public_verifying_key_set(&vec![signing_key.clone()])
    .await
    .unwrap();

    let header_v1 = test_runner::test_client_v1::CorrectHooksTestClient::new(test_server_port)
    .sign(correct_hooks::v1::SignArgs {
      webhook_id, 
      recipient_id: "7ee6ade2-8b56-4e83-b481-497848bb1f85".parse().unwrap(), 
      target_url: "https://adomain.com/a/path", 
      method, 
      request_body: &request_body, 
      secret_signing_key: &serde_json::from_value(serde_json::to_value(&signing_key).unwrap()).unwrap()
    })
    .await
    .unwrap().correct_hooks_signature;

  let header_v2 = test_library
    .sign(SignArgs {
      webhook_id,
      target_id,
      method,
      request_body: &request_body,
      secret_signing_key: &signing_key,
    })
    .await
    .unwrap();

  let joined_webhook_header = vec![
    header_v1,
    header_v2.clone(),
  ]
  .join(" ");

  let signature_components =
    decode_signature_header_test(&header_v2);

  let verify_result = test_library
    .verify_with_time(
      VerifyArgs {
        target_id,
        method,
        correct_hooks_signature: &joined_webhook_header,
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
async fn sign_verify_empty_body_test() {
  let target_id = "9f1c2a4e-3b7d-4c58-a6e1-52d8b0c47f93".parse().unwrap();
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba".parse().unwrap();
  let method = "POST";
  let request_body = "".to_string().as_bytes().to_vec();
  let signature_ttl_seconds = 300;

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key = test_library.generate_secret_signing_key().await;
  let public_key_set = test_library
    .create_public_verifying_key_set(&vec![signing_key.clone()])
    .await
    .unwrap();

  let webhook_headers = test_library
    .sign(SignArgs {
      webhook_id,
      target_id,
      method,
      request_body: &request_body,
      secret_signing_key: &signing_key,
    })
    .await
    .unwrap();

  let signature_components =
    decode_signature_header_test(&webhook_headers);

  let verify_result = test_library
    .verify_with_time(
      VerifyArgs {
        target_id,
        method,
        correct_hooks_signature: &webhook_headers,
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
