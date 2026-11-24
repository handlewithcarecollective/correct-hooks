use correct_hooks::v2::{
  SecretSigningKey, SignArgs, SignError, SignatureHeaderComponents, VerifyArgs, VerifyError,
  encode_signature_header,
};
use test_runner::test_client_v2::{CorrectHooksTestClient, decode_signature_header_test};
use uuid::Uuid;

#[tokio::test]
#[async_backtrace::framed]
async fn invalid_target_id_test() {
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

  let verify_result = test_library
    .verify_with_time(
      VerifyArgs {
        target_id: Uuid::new_v4(),
        method,
        correct_hooks_signature: &signature_header,
        request_body: &request_body,
      },
      signature_ttl_seconds,
      &public_key_set,
      signature_components.signed_at + 1,
    )
    .await;

  assert_eq!(verify_result, Err(VerifyError::InvalidSignature));
}

#[tokio::test]
#[async_backtrace::framed]
async fn invalid_method_test() {
  let target_id = "9f1c2a4e-3b7d-4c58-a6e1-52d8b0c47f93".parse().unwrap();
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba".parse().unwrap();
  let method = "POST";
  let expected_method = "PUT";
  let request_body = "{\"testfield\": 234}".to_string().as_bytes().to_vec();
  let signature_ttl_seconds = 300;

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key = test_library.generate_secret_signing_key().await;
  let public_key_set = test_library
    .create_public_verifying_key_set(&vec![signing_key.clone()])
    .await
    .unwrap();

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

  let verify_result = test_library
    .verify_with_time(
      VerifyArgs {
        target_id,
        method: expected_method,
        correct_hooks_signature: &signature_header,
        request_body: &request_body,
      },
      signature_ttl_seconds,
      &public_key_set,
      signature_components.signed_at + 1,
    )
    .await;

  assert_eq!(verify_result, Err(VerifyError::InvalidSignature));
}

#[tokio::test]
#[async_backtrace::framed]
async fn expired_signature_test() {
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
      signature_components.signed_at + signature_ttl_seconds + 1,
    )
    .await;

  assert_eq!(verify_result, Err(VerifyError::InvalidSignature));
}

#[tokio::test]
#[async_backtrace::framed]
async fn in_the_future_signature_test() {
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
      signature_components.signed_at - signature_ttl_seconds - 1,
    )
    .await;

  assert_eq!(verify_result, Err(VerifyError::InvalidSignature));
}

#[tokio::test]
#[async_backtrace::framed]
async fn invalid_signature_components_webhook_id_test() {
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

  let actual_signature_components = decode_signature_header_test(&signature_header);

  let invalid_signature_components = SignatureHeaderComponents {
    webhook_id: Uuid::new_v4(),
    key_id: actual_signature_components.key_id,
    signed_at: actual_signature_components.signed_at,
    signature: actual_signature_components.signature.clone(),
  };

  let invalid_signature_header_value = encode_signature_header(invalid_signature_components);

  let verify_result = test_library
    .verify_with_time(
      VerifyArgs {
        target_id,
        method,
        correct_hooks_signature: &invalid_signature_header_value,
        request_body: &request_body,
      },
      signature_ttl_seconds,
      &public_key_set,
      actual_signature_components.signed_at + 1,
    )
    .await;

  assert_eq!(verify_result, Err(VerifyError::InvalidSignature));
}

#[tokio::test]
#[async_backtrace::framed]
async fn invalid_signature_components_signed_at_test() {
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

  let actual_signature_components = decode_signature_header_test(&signature_header);

  let invalid_signature_components = SignatureHeaderComponents {
    webhook_id: actual_signature_components.webhook_id,
    key_id: actual_signature_components.key_id,
    signed_at: actual_signature_components.signed_at + 1,
    signature: actual_signature_components.signature.clone(),
  };

  let invalid_signature_header_value = encode_signature_header(invalid_signature_components);

  let verify_result = test_library
    .verify_with_time(
      VerifyArgs {
        target_id,
        method,
        correct_hooks_signature: &invalid_signature_header_value,
        request_body: &request_body,
      },
      signature_ttl_seconds,
      &public_key_set,
      actual_signature_components.signed_at + 1,
    )
    .await;

  assert_eq!(verify_result, Err(VerifyError::InvalidSignature));
}

#[tokio::test]
#[async_backtrace::framed]
async fn invalid_public_key_test() {
  let target_id = "9f1c2a4e-3b7d-4c58-a6e1-52d8b0c47f93".parse().unwrap();
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba".parse().unwrap();
  let method = "POST";
  let request_body = "{\"testfield\": 234}".to_string().as_bytes().to_vec();
  let signature_ttl_seconds = 300;

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key_1 = test_library.generate_secret_signing_key().await;
  let signing_key_1_value = serde_json::to_value(&signing_key_1).unwrap();
  let signing_key_2 = test_library.generate_secret_signing_key().await;
  let mut signing_key_2_value = serde_json::to_value(&signing_key_2).unwrap();
  signing_key_2_value["kid"] = signing_key_1_value["kid"].clone();
  let signing_key_2 = serde_json::from_value::<SecretSigningKey>(signing_key_2_value).unwrap();
  let public_key_set = test_library
    .create_public_verifying_key_set(&vec![signing_key_2.clone()])
    .await
    .unwrap();

  let signature_header = test_library
    .sign(SignArgs {
      webhook_id,
      target_id,
      method,
      request_body: &request_body,
      secret_signing_key: &signing_key_1,
    })
    .await
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
    .await;

  assert_eq!(verify_result, Err(VerifyError::InvalidSignature));
}

#[tokio::test]
#[async_backtrace::framed]
async fn missing_public_key_test() {
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

  let actual_signature_components = decode_signature_header_test(&signature_header);

  let invalid_signature_components = SignatureHeaderComponents {
    webhook_id: actual_signature_components.webhook_id,
    key_id: Uuid::new_v4(),
    signed_at: actual_signature_components.signed_at + 1,
    signature: actual_signature_components.signature.clone(),
  };

  let invalid_signature_header_value = encode_signature_header(invalid_signature_components);

  let verify_result = test_library
    .verify_with_time(
      VerifyArgs {
        target_id,
        method,
        correct_hooks_signature: &invalid_signature_header_value,
        request_body: &request_body,
      },
      signature_ttl_seconds,
      &public_key_set,
      actual_signature_components.signed_at + 1,
    )
    .await;

  assert_eq!(verify_result, Err(VerifyError::PublicVerifyingKeyNotFound));
}

#[tokio::test]
#[async_backtrace::framed]
async fn invalid_sign_args_method_test() {
  let target_id = "9f1c2a4e-3b7d-4c58-a6e1-52d8b0c47f93".parse().unwrap();
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba".parse().unwrap();
  let method = "GETTTTT";
  let request_body = "{\"testfield\": 234}".to_string().as_bytes().to_vec();

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key = test_library.generate_secret_signing_key().await;

  let sign_result = test_library
    .sign(SignArgs {
      webhook_id,
      target_id,
      method,
      request_body: &request_body,
      secret_signing_key: &signing_key,
    })
    .await;

  assert_eq!(sign_result, Err(SignError::InvalidArgs));
}

#[tokio::test]
#[async_backtrace::framed]
async fn invalid_sign_args_method_lower_case_test() {
  let target_id = "9f1c2a4e-3b7d-4c58-a6e1-52d8b0c47f93".parse().unwrap();
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba".parse().unwrap();
  let method = "post";
  let request_body = "{\"testfield\": 234}".to_string().as_bytes().to_vec();

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key = test_library.generate_secret_signing_key().await;

  let sign_result = test_library
    .sign(SignArgs {
      webhook_id,
      target_id,
      method,
      request_body: &request_body,
      secret_signing_key: &signing_key,
    })
    .await;

  assert_eq!(sign_result, Err(SignError::InvalidArgs));
}

#[tokio::test]
#[async_backtrace::framed]
async fn invalid_sign_args_target_id_not_v4_test() {
  let target_id = Uuid::nil();
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba".parse().unwrap();
  let method = "POST";
  let request_body = "{\"testfield\": 234}".to_string().as_bytes().to_vec();

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key = test_library.generate_secret_signing_key().await;

  let sign_result = test_library
    .sign(SignArgs {
      webhook_id,
      target_id,
      method,
      request_body: &request_body,
      secret_signing_key: &signing_key,
    })
    .await;

  assert_eq!(sign_result, Err(SignError::InvalidArgs));
}

#[tokio::test]
#[async_backtrace::framed]
async fn duplicate_header_version_test() {
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

  let correct_hooks_signature = format!("{} {}", signature_header, signature_header);

  let verify_result = test_library
    .verify_with_time(
      VerifyArgs {
        target_id,
        method,
        correct_hooks_signature: &correct_hooks_signature,
        request_body: &request_body,
      },
      signature_ttl_seconds,
      &public_key_set,
      signature_components.signed_at + 1,
    )
    .await;

  assert_eq!(verify_result, Err(VerifyError::InvalidSignature));
}
