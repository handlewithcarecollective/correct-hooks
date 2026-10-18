
### Webhook Producers

#### Key generation
To sign requests, you first need to generate a secret signing key. The key serializes to a json string which should be stored in your secret manager. The secret signing key should be treated as an opaque blob, and you should never edit it's contents.
```rust
use correct_hooks::generate_secret_signing_key;

let secret_signing_key = generate_secret_signing_key();
let secret_signing_key_json = serde_json::to_string(&secret_signing_key).unwrap();
```

#### Public key generation
For your webhook consumers to verify your signatures, they need the public verifying key set for your signing keys.

`create_public_verifying_key_set` creates a public verifying key set from a list of your secret keys. 
You should serialize the public verifying key set to a json string and serve it from a public GET endpoint. Document this endpoint's url
for your webhook consumers. Initial deployments can serve the public verifying key set directly. Moderate and large scale deployments may
want to put this endpoint behind a CDN.
```rust
use correct_hooks::create_public_verifying_key_set;

let public_verifying_key_set = create_public_verifying_key_set(&vec![secret_signing_key]).unwrap();
let public_verifying_key_set_json = serde_json::to_string(&public_verifying_key_set);
```

#### Sign a request

Sign the request data and set the headers `correct-hooks-signature-components` and `correct-hooks-signature` to
the returned values. See [SignArgs](https://github.com/handlewithcarecollective/correct-hooks/blob/accffd39544b64392a8d7edcb5b42ea03fd2e2d5/rust/correct_hooks/src/lib.rs#L65) for argument details.
```rust
use correct_hooks::{SignArgs, sign};

let signature_headers = sign(
  SignArgs {
    webhook_id,
    recipient_id,
    target_url,
    method,
    request_body, 
    secret_signing_key,
  }
).unwrap();
let correct_hooks_signature_components = &signature_headers.correct_hooks_signature_components;
let correct_hooks_signature = &signature_headers.correct_hooks_signature;
```

### Webhook Consumers

#### Create a verifier
Create a Verifier with the webhook producer's public verifying key set url. You should create a Verifier once when your backend instance starts and reuse it for all requests to that instance.

See [VerifyConfig](https://github.com/handlewithcarecollective/correct-hooks/blob/accffd39544b64392a8d7edcb5b42ea03fd2e2d5/rust/correct_hooks/src/lib.rs#L276) for argument details.

```rust
use correct_hooks::{Verifier, VerifierConfig};

let verifier = Verifier::new(
  VerifierConfig {
    recipient_id,
    public_verifying_key_set_url,
    signature_ttl_seconds: None,
    public_verifying_key_set_ttl_seconds: None,
  }
);
```

#### Verify a request
Verify a request with the Verifier. Any error indicates that the signature is invalid and that the request should be immediately rejected.

See [VerifyArgs](https://github.com/handlewithcarecollective/correct-hooks/blob/accffd39544b64392a8d7edcb5b42ea03fd2e2d5/rust/correct_hooks/src/lib.rs#L111) for argument details.
```rust
use correct_hooks::VerifyArgs;

let verify_result = verifier.verify(VerifyArgs{
  target_url,
  method,
  correct_hooks_signature_components,
  correct_hooks_signature,
  request_body,
}).await;

if verify_result.is_err() {
  return StatusCode::FORBIDDEN;
}
let verified_data = verify_result.unwrap();
```
