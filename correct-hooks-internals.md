# Correct Hooks Internals

Correct Hooks is designed to be used securely without webhook producers or consumers needing in depth knowledge of its underlying cryptographic primitives, but as a system designer or tech lead, it’s important to verify that your auth system actually works the way it says it does. So if you’re here reading this, like actually reading it, with your eyes, congratulations! You actually care about how the tools you use work and aren’t just accepting my empty promises. That’s great.

If you have not already, I would recommend reading through one of our [quickstarts](https://github.com/handlewithcarecollective/correct-hooks#table-of-contents) to get an understanding of how the library is used. We will be referencing functions explained in the quickstarts throughout this doc.

We’ll go over how keys are managed with Correct Hooks, what goes into the Correct Hooks signature headers, and how the verifiers work. When referencing functions and other language symbols, we will be using the [Rust](https://github.com/handlewithcarecollective/correct-hooks#quickstart---rust) library’s naming semantics (snake case for functions, upper camel case for structs/classes).

## The algorithm
Correct Hooks uses [ed25519](https://www.rfc-editor.org/info/rfc8032/#section-5) signatures. All keys and signatures are made for and with ed25519.

All base64 encodings are [urlsafe with no padding](https://www.rfc-editor.org/info/rfc4648/#section-5).

## Keys
Correct Hooks has two built in key types, SecretSigningKey and PublicVerifyingKeySet. These classes hold the ed25519 key details and serialize directly to a JWK and JWKS respectively. If you are not already familiar with JWKs, a JWK is a JSON Web Key and a JWKS is a JSON Web Key Set (see [RFC 7517](https://www.rfc-editor.org/info/rfc7517/)). I avoid using these acronyms in most of Correct Hooks’ public interfaces both to be explicit about the use and secrecy of the keys and because whenever I see them, my mind glazes over, I forget what I was trying to do and I don't come to until a few minutes later. 

A SecretSigningKey has following fields
```
{
	“kid”: assigned to a key by Correct Hooks when it is created and is used to identify the correct
           public key to verify a request with
	“kty”: set to “OKP” for all keys
	“crv”: set to “Ed25519” for all keys
	“x”: the key’s public bytes
	“d”: the key’s secret bytes
}
```

A PublicVerifyingKeySet has the following fields
```
{
	“keys”: an array of public JWKs with the same fields as the SecretSigningKey except no "d" field
}
```

A SecretSigningKey is created with the `generate_secret_signing_key` function.

A PublicVerifyingKeySet is created with the `create_public_verifying_key_set` function. `create_public_verifying_key_set` takes a list of SecretSigningKey and returns the corresponding public JWKS. The webhook producer must provide all of the signing keys they want to be represented in the public verifying key set when the key set is made. This avoids a situation where a potentially compromised secret key was rotated out, but its public key is not removed from the public verifying key set. 

Correct Hooks is designed to work directly with the keys it creates, and while we cannot stop anyone from manually editing the json of a key after it is serialized, we recommend against it. As an extra security feature, the Verifier class ignores public keys that have unexpected fields. In the event that a secret is leaked in the public verifying key set, that key will functionally be disabled until it is rotated.

## Signature
A Correct Hooks signature message contains the following elements
* webhook id: a unique identifier for the webhook and that is reused on any delivery retries.
* key id: the id of the secret signing key used to sign the signature message
* timestamp: the time the signature was created in seconds since unix epoch.
* recipient id: the id of the account receiving the webhook
* target url: the url the producer is sending the webhook to
* method: the http method the webhook is being sent with (using exclusively POST is recommended)
* request body: the webhook's raw unparsed request body bytes

These fields are similar to what should typically be included in a symmetric signature with the addition of the recipient id, target url and method fields. These additional fields allow the webhook producer to sign all requests with a single private key while ensuring that
a malicious consumer cannot masquerade as the webhook producer by forwarding their requests to other consumers and that the producer cannot be tricked into sending a verifiable webhook intended for one consumer to another.

Before being added to the signature message, the following fields are base64 encoded: webhook id, key id, timestamp, recipient id, target url. 

The signature message consists of the signature fields separated by periods in the following order:

`"<webhook id base64>.<key id base64>.<timestamp base64>.<recipient id base64>.<target url base64>.<method>.<request body bytes>"`

This signature message is then signed with ed25519 to create the signature. This signature is base64 encoded and is prefixed with “v1,” resulting in the string
`"v1,<base64 encoded ed25519 signature>"`. The “correct-hooks-signature” header is set to this value by the webhook producer.

The webhook id, key id, and timestamp fields need to be passed along with the request for the signature to be verified. These values are passed through the “correct-hooks-signature-components” header. To create this header value, the base64 encoded values of the fields are concatenated together, separated by periods, and prefixed with “v1,”. The resulting header value is

`“v1,<webhook id base64>.<key id base64>.<timestamp base64>”`

## Verification
Correct Hooks signatures are verified through the library's Verifier class. The Verifier manages caching and refreshing the public verifying key set used to verify requests, and signatures are verified with the Verifier’s `verify` function.

A Verifier takes the following configuration fields on construction
* recipient_id: the consumer’s recipient id
* public_verifying_key_set_url: the public url for the webhook producer’s public verifying key set
* signature_ttl_seconds: how long a signature is considered valid in seconds. Defaults to 300 seconds (5 minutes).
* public_verifying_key_set_ttl_seconds: how long a public verifying key set can be used before a refresh is forced. Defaults to 300 seconds (5 minutes).

When the verifier is created, it is initialized with an empty public verifying key set. 

The Verifier reloads the public verifying key set from public_verifying_key_set_url when the `verify` function is called. The following conditions can trigger a refresh:
1. The key id for the signature is not found in the public verifying key set.
2. public_verifying_key_set_ttl_seconds have passed since the verifying key set was last refreshed.

The public verifying key set refresh function is gated by an async mutex and simultaneous refreshes are consolidated into one request. Only one refresh is attempted when one of the conditions is triggered. If the refresh fails, the verification fails, and webhoook consumers are instructed to immediately reject the request. Attempts to re-verify should be triggered by the webhook producer's delivery retry mechanism.

When the Verifier refreshes the public verifying key, it checks that each public key only has fields set by Correct Hooks. If a key has extra or missing fields, potentially indicating a leaked secret, that key is excluded from the set.

The `verify` function takes the two Correct Hooks headers, "correct-hooks-signature" and "correct-hooks-signature-components", along with the target url and request data. It validates that the expected values provided by the consumer and the values contained in the "correct-hooks-signature-components" header match the signature and confirms that the timestamp for the signature is not older than signature_ttl_seconds. 

If verification is successful, the webhook id is returned, and can be used by the consumer to facilitate idempotency and strict replay protection. If verification fails, an error is either returned or thrown depending on language semantics.
