# Correct Hooks

A set of cross-language libraries that perform asymmetric signing, verification, and key management for webhook authentication. 

Correct Hooks makes one of the most secure authentication mechanisms for webhooks the easiest to implement for both webhook producers and consumers.

## Table of Contents

- [Why](#why)
- [How It Works](#how-it-works)
- [Language Support](#language-support)
- [Quickstart - Typescript](#quickstart---typescript)
- [Quickstart - Python](#quickstart---python)
- [Quickstart - Rust](#quickstart---rust)
- [Key Rotation](#key-rotation)
- [Migration](#migration)
- [Upgrades](#upgrades)
- [Other concerns](#other-concerns)
- [Looking for someone to collaborate with?](#looking-for-someone-to-collaborate-with)
- [Security](#security)

## Why

Because the existing options are bad. If you want to provide webhooks to your users, you quickly discover that unlike with regular api auth there are few prebuilt auth systems intended for use with webhooks. The options that do exist require you to implement complex secret management systems if you want to serve webhooks from your own infrastructure.

Most webhook producers authenticate their webhooks using symmetric signatures (HMAC). Signing and verifying a symmetric signature is easy, and naive authentication implementations using symmetric signatures start off simple. But because symmetric signatures use the same secret key for signing and verification, the webhook producer has to keep a unique shared secret for every user they have (and in practice every endpoint they send a webhook to). Managing a set of shared secrets that scales with the size of your customer base creates a cascade of security and quality of service liabilities that introduce significant system complexity to resolve.

Asymmetric signatures on the other hand do not have this problem. The webhook producer can hold a single private signing key stored in a secret manager and all webhook consumers can access the public verifying key through a public endpoint the webhook producer provides. When the key needs to be rotated, the webhook producer updates their public verifying key set, and webhook consumers can automatically retrieve the new verifying key for a zero-downtime rotation.

But actually signing and verifying asymmetric signatures is much harder than symmetric signatures. Identifying how to format and distribute asymmetric keys is time consuming, and the steps to properly sign and verify an asymmetric signature are not always intuitive, requiring extra data in the signature message and reaching into cryptography libraries that are not always well documented and contain sharp edges. Even if a webhook producer is willing to take the time to implement asymmetric signing they may not want to put the burden of properly verifying those signatures on their customers.

The goal of Correct Hooks is to provide the best of both worlds, encapsulating the code to sign, verify, and manage keys for asymmetric signatures in a user friendly library with language support that covers the needs of the large majority of developers, making the auth solution that is the most fundamentally secure the easiest to implement for both webhook producers and consumers.

## How it works
Correct Hooks creates signatures with ed25519. The signature includes a timestamp, the intended recipient's id, the target endpoint's url and method, a unique id for the webhook, and the request body. The verify function only succeeds if the signature data matches expected values and is not expired. The built in Verifier also ensures that the verifying key set used to verify signatures is not stale allowing key rotation to occur without any intervention required by webhook consumers. If verification succeeds, the webhook id is returned to the consumer to allow for idempotency.  

These steps provide replay protection, message integrity, and non-repudiation all through an interface that is easy to use correctly and difficult to use incorrectly.

## Language Support 
Correct Hooks is in the early stages of development but is usable. We have support for [Typescript](#quickstart---typescript), [Python](#quickstart---python), and [Rust](#quickstart---rust) and are planning to add support for Java, Go, and C#. We will continue evaluating additional languages to support. If you have a language you want us to support [let us know](https://forms.gle/XbpSgS5ubg9x8M826)!

If you want support for your language of choice before we get to it, we would love to help you write a community library! Using the existing library implementations as references, you can implement Correct Hooks in a new language pretty quickly. We can advise on key points of the implementation that need to be covered as well as any questions around the library's cryptographic steps. We have a cross language test suite that is easy to connect to Correct Hooks libraries in any language, so you only have to write code for the library itself and a small test server. We are planning to write a spec for Correct Hooks libraries as well. 

## Quickstart - Typescript

[Back to top](#correct-hooks)

### Installation
```
npm i @handlewithcare/correct-hooks
```

### Webhook Producers

#### Key generation
To sign requests, you first need to generate a secret signing key. The key serializes to a json string which should be stored in your secret manager. The secret signing 
key should be treated as an opaque blob, and you should never edit its contents.
```typescript
import { generateSecretSigningKey } from "@handlewithcare/correct-hooks";

const secretSigningKey = generateSecretSigningKey();
const secretSigningKeyJson = JSON.stringify(secretSigningKey);
```

#### Public key generation
For your webhook consumers to verify your signatures, they need the public verifying key set for your signing keys.

`createPublicVerifyingKeySet` creates a public verifying key set from a list of your secret keys. 
You should serialize the public verifying key set to a json string and serve it from a public GET endpoint. Document this endpoint's url
for your webhook consumers. Initial deployments can serve the public verifying key set directly. Moderate and large scale deployments may
want to put this endpoint behind a CDN.
```typescript
import { createPublicVerifyingKeySet } from "@handlewithcare/correct-hooks";

const publicVerifyingKeySet = createPublicVerifyingKeySet([secretSigningKey]);
const publicVerifyingKeySetJson = JSON.stringify(publicVerifyingKeySet);
```

#### Sign a request

Sign the request data and set the headers `correct-hooks-signature-components` and `correct-hooks-signature` to
the returned values. See [SignArgs](https://github.com/handlewithcarecollective/correct-hooks/blob/accffd39544b64392a8d7edcb5b42ea03fd2e2d5/typescript/correct-hooks/src/index.ts#L76) for argument details.
```typescript
import { sign } from "@handlewithcare/correct-hooks";

const signatureHeaders = sign({
  webhookId,
  recipientId,
  targetUrl,
  method,
  requestBody,
  secretSigningKey,
});
const { correctHooksSignatureComponents, correctHooksSignature } = signatureHeaders;
```

### Webhook Consumers

#### Create a verifier
Create a Verifier with the webhook producer's public verifying key set url. You should create a Verifier once when your backend instance starts and reuse it for all requests to that instance.

See [VerifyConfig](https://github.com/handlewithcarecollective/correct-hooks/blob/accffd39544b64392a8d7edcb5b42ea03fd2e2d5/typescript/correct-hooks/src/index.ts#L316) for argument details.

```typescript
import { Verifier } from "@handlewithcare/correct-hooks";

const verifier = new Verifier({
  recipientId,
  publicVerifyingKeySetUrl,
});
```

#### Verify a request
Verify a request with the Verifier. Any error indicates that the signature is invalid and that the request should be immediately rejected.

See [VerifyArgs](https://github.com/handlewithcarecollective/correct-hooks/blob/accffd39544b64392a8d7edcb5b42ea03fd2e2d5/typescript/correct-hooks/src/index.ts#L128) for argument details.
```typescript
let verifiedData;
try {
  verifiedData = await verifier.verify({
    targetUrl,
    method,
    correctHooksSignatureComponents,
    correctHooksSignature,
    requestBody,
  });
} catch {
  return StatusCode.FORBIDDEN;
}
const { webhookId } = verifiedData 
```


## Quickstart - Python

[Back to top](#correct-hooks)

### Installation
```
pip install correct_hooks
```

### Webhook Producers

#### Key generation
To sign requests, you first need to generate a secret signing key. The key serializes to a json string which should be stored in your secret manager. 

The secret signing key should be treated as an opaque blob, and you should never edit its contents.
```python
from correct_hooks import generate_secret_signing_key

secret_signing_key = generate_secret_signing_key()
secret_signing_key_json = secret_signing_key.model_dump_json()
```

#### Public key generation
For your webhook consumers to verify your signatures, they need the public verifying key set for your signing keys.

`create_public_verifying_key_set` creates a public verifying key set from a list of your secret keys. 
You should serialize the public verifying key set to a json string and serve it from a public GET endpoint. Document this endpoint's url
for your webhook consumers. Initial deployments can serve the public verifying key set directly. Moderate and large scale deployments may
want to put this endpoint behind a CDN.
```python
from correct_hooks import create_public_verifying_key_set

public_verifying_key_set = create_public_verifying_key_set([secret_signing_key])
public_verifying_key_set_json = public_verifying_key_set.model_dump_json()
```

#### Sign a request

Sign the request data and set the headers `correct-hooks-signature-components` and `correct-hooks-signature` to
the returned values. See [SignArgs](https://github.com/handlewithcarecollective/correct-hooks/blob/accffd39544b64392a8d7edcb5b42ea03fd2e2d5/python/correct_hooks/src/correct_hooks/__init__.py#L82) for argument details.
```python
from correct_hooks import (sign, SignArgs)

signature_headers = sign(SignArgs(
  webhook_id=webhook_id,
  recipient_id=recipient_id,
  target_url=target_url,
  method=method,
  request_body=request_body,
  secret_signing_key=secret_signing_key,
))
correct_hooks_signature_components = signature_headers.correct_hooks_signature_components
correct_hooks_signature = signature_headers.correct_hooks_signature
```

### Webhook Consumers

#### Create a verifier
Create a Verifier with the webhook producer's public verifying key set url. You should create a Verifier once when your backend instance starts and reuse it for all requests to that instance.

See [VerifyConfig](https://github.com/handlewithcarecollective/correct-hooks/blob/accffd39544b64392a8d7edcb5b42ea03fd2e2d5/python/correct_hooks/src/correct_hooks/__init__.py#L285) for argument details.

```python
from correct_hooks import (Verifier, VerifierConfig)

verifier = Verifier(VerifierConfig(
  recipient_id=recipient_id,
  public_verifying_key_set_url=AnyUrl(public_verifying_key_set_url),
))
```

#### Verify a request
Verify a request with the Verifier. Any error indicates that the signature is invalid and that the request should be immediately rejected.

See [VerifyArgs](https://github.com/handlewithcarecollective/correct-hooks/blob/accffd39544b64392a8d7edcb5b42ea03fd2e2d5/python/correct_hooks/src/correct_hooks/__init__.py#L130) for argument details.
```python
from correct_hooks import VerifyArgs

try:
  verified_data = await verifier.verify(
    target_url=target_url,
    method=method,
    correct_hooks_signature_components=signature_headers.correct_hooks_signature_components,
    correct_hooks_signature=signature_headers.correct_hooks_signature,
    request_body=request_body,
  )
except Exception:
  return HTTPStatus.FORBIDDEN
```


## Quickstart - Rust

[Back to top](#correct-hooks)

### Installation
```
cargo add correct_hooks
```

### Webhook Producers

#### Key generation
To sign requests, you first need to generate a secret signing key. The key serializes to a json string which should be stored in your secret manager. The secret signing key should be treated as an opaque blob, and you should never edit its contents.
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


## Key Rotation

[Back to top](#correct-hooks)

One of the great things about asymmetric signatures is that rotating keys is exceptionally easy. The basic steps are as follows.
1. Generate a new signing key.
2. Create and publish a new public verifying key set with your new and old secret signing keys (eg. `createPublicVerifyingKeySet([oldSecretKey, newSecretKey])`). If you put your public verifying key set behind a cache or cdn, purge the cache.
3. Start signing requests with your new secret signing key
4. Create and publish a new public verifying key set with just your new secret signing key (eg. `createPublicVerifyingKeySet([newSecretKey])`). If you put your public verifying key set behind a cache or cdn, purge the cache.
5. Enjoy your afternoon

When you rotate your key, your webhook consumer's Verifiers will automatically retrieve the new public verifying key set, so you can do this as much as you want and no one will even notice. Go nuts. What else do you have going on on a Friday?


## Migration

[Back to top](#correct-hooks)

Correct Hooks is designed so that it can be used in parallel with other webhook authentication approaches, allowing you to migrate your existing webhook system to Correct Hooks without downtime. To start migrating to Correct Hooks, all you have to do is add the Correct Hooks headers to your webhook requests.


## Upgrades

[Back to top](#correct-hooks)

Correct Hooks is designed to be independently upgradable by webhook producers and consumers. There are two version numbers that need to be paid attention to when upgrading, the library version and the signature version.

Correct Hooks libraries use semantic versioning and may have breaking changes on major version updates or prior to a 1.0 release, on minor version updates.
A Correct Hooks library also has a signature version, generally stored in the `SIGNATURE_VERSION` constant. An update with breaking changes 
will not necessarily change a library's signature version, but changing the signature version will constitute a breaking change.

Correct Hooks libraries sign signatures with their `SIGNATURE_VERSION` by default but will have functions to sign a signatures with earlier versions. When performing a Correct Hooks update that has breaking changes, signers should check if the signature version has changed. If it has, you can create signatures with both the new signature version and the old signature version and add them to the Correct Hooks headers separated by a space. 

Correct Hooks libraries can verify signatures with versions less than or equal to their signature version and will attempt to verify the highest signature version that they can. This allows webhook consumers to update their version of Correct Hooks whenever they want, and allows webhook producers to upgrade Correct Hooks without downtime, supporting multiple signature versions until they choose to deprecate and remove support for older versions.

As of now, this is largely hypothetical because there is only one signature version, but the support for backwards compatibility is already built into the Correct Hooks libraries. If we release a new signature version in the future, we will provide detailed instructions on how to upgrade.


## Other concerns

[Back to top](#correct-hooks)

### I'm using \<INSERT OBSCURE LANGUAGE\>. How do I verify webhooks?
If you are a webhook consumer using a language we do not provide library support for, there are a few things you can do:
1. Let us know. The goal of this project is to provide the language support for the large majority of developers. If there is enough demand, we can add official support for a language.
2. Implement the verification steps yourself, or even better build a community library for your language! Using the existing library implementations as references, you can implement Correct Hooks in a new language pretty quickly. We have resources that make implementing a community library easy, in particular a cross language test suite, and can advise on key steps the library needs function properly (also see [Language Support](#language-support)).

### Don't I still need a unique private key for every endpoint I send webhooks to?
No. I don't know how this idea got started, but I see it cited a lot. Correct hooks includes all the information in its signature needed to confirm that a request was both signed by the webhook producer and is intended to be received by the consumer and endpoint it was sent to. One private key can be used for all webhooks sent by the webhook producer.

### Isn't asymmetric signing slow?
Nope. Evaluations of signing methods often fall into a performance optimization trap, evaluating how fast two algorithms are compared to each other instead of whether the difference matters.

While symmetric HMAC signatures are in fact extremely fast to sign and verify, the modern ed25519 algorithm Correct Hooks uses for its signatures is also very fast. Profiling on my laptop, signing a 5 KiB payload with ed25519 in Rust takes 27μs. That is a rate of 37,000 signatures per second on a single cpu thread. Typescript came in at (a mere) 28,000 signatures per second. This has no meaningful impact on the performance of a webhook system.

### What other considerations do I need to keep in mind when building a webook system?
Correct Hooks makes webhook signing, verification, and key management easy, but there are additional security and quality of service considerations to take into account when building a webhook system. These include but are not limited to enforcing https, protecting against SSRF attacks, implementing reliable retries, and dead letter management. The [Standard Webhooks](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md#operational-considerations) spec has good recommendations to consider when building a webhook system.

## Looking for someone to collaborate with?
[Back to top](#correct-hooks)

Reach out to [Handle with Care](https://handlewithcare.dev/#get-in-touch)! The code and infrastructure required for a well designed webhook system is actually not too complicated, but it can be time consuming to identify and design around all of the requirements for the first time and then realize you missed something and have to wedge new requirements in. If you want full control over your webhooks but don't want to reinvent the wheel, come talk to us! We're cool and can help get your team up and running with webhooks quickly.  

## Security
If you discover a security vulnerability within Correct Hooks, please report it via [GitHub Security Advisories](https://github.com/pdiffley/correct-hooks/security/advisories/new).

All reports will be promptly addressed, and you'll be credited accordingly.
