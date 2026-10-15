# Correct Hooks

A multi-language set of libraries that perform asymmetric signing, verification, and key management for webhook authentication. 

Correct Hooks makes one of the most secure authentication mechanisms for webhooks the easiest to implement for both webhook producers and consumers.

## Why:

Because the existing options are bad. If you want to provide webhooks to your users, you quickly discover that there are few prebuilt auth systems intended for use with webhooks. The options that do exist require you to implement complex secret mangagement systems if you want to serve webhooks from your own infrastructure.

Most webhook producers authenticate their webhooks using symmetric signatures (HMAC). Signing and verifying a symmetric signature is easy, and naive authentication implementations using symmetric signatures start off simple. But because symmetric signatures use the same secret key for signing and verification, the webhook producer has to keep a unique shared secret for every user they have (and in practice every endpoint they send a webhook to). Managing a set of shared secrets that scales with the size of your customer base creates a cascade of security and quality of service liabilities that introduce significant system complexity to resolve.

Asymmetric signatures on the other hand do not have this problem. The webhook producer can hold a single private signing key stored in a secret manager and all webhook consumers can access the public verifying key through a public endpoint the webhook producer provides. When the key needs to be rotated, the webhook producer updates their public verifying key set, and webhook consumers can automatically retrieve the new verifying key for a zero-downtime rotation.

But actually signing and verifying asymmetric signatures is much harder than symmetric signatures. Identifying how to generatie and distribute asymmetric keys is time consuming, and the steps to properly sign and verify an asymmetric signature are not always intuitive, requiring putting extra data in the signature message and reaching into cryptography libraries that are not always well documented and contain sharp edges. Even if a webhook producer is willing to take the time to implement asymmetric signing they may not want to put the burden of properly verifying those signatures on their customers.

The goal of Correct Hooks is to provide the best of both worlds, encapsulating the code to sign, verify, and manage keys for asymmetric signatures in a user friendly library with language support that covers the needs of the large majority of developers, making the auth solution that is the most fundamentally secure the easiest to implement for both webhook producers and consumers.

## Language Support 
Correct Hooks is in the early stages of development but is currently usable. We have support for Typescript, Python, and Rust, and are planning to add support for Java, Go, and C# over the next few weeks. We will continue evaluating additional languages to support. 

If you want support for your language of choice before we get to it, we would love to help you write a community library. Using the existing library implementations as references, you can implement Correct Hooks in a new language pretty quickly, and we can advise on key points of the library that need to be implemented as well as any questions around the library's cryptographic steps. We have a cross langauge test suite that is easy to connect to Correct Hooks libraries in any language, so you only have to write code for the library itself and a small test server. We are also planning to write a spec detailing what need to go into a Correct Hooks library. 

## Quickstart - Typescript
### Installation
```
npm i @handlewithcare/correct-hooks
```

### Webhook Producers

#### Key generation and rotation
To sign requests, you first need to generate a secret signing key. This key serializes to a json string and should be stored in your secret manager. The secret signing 
key should be treated as an opaque blob, and you should never edit it's contents.
Typescript:
```typescript
import { generateSecretSigningKey } from "@handlewithcare/correct-hooks";

const secretSigningKey = generateSecretSigningKey();
const secretSigningKeyJson = JSON.stringify(secretSigningKey);
```

#### Public key generation
For your webhook consumers to verify your signatures, they need the public verifying key set for your signing keys.

`createPublicVerifyingKeySet` creates a public keys set from a list of your secret keys. 
You should serialize the public key set to a json string and serve it from a public GET endpoint. Document this endpoint
for your webhook consumers (Todo: see `publicVerifyingKeySetUrl`)
```typescript
import { createPublicVerifyingKeySet } from "@handlewithcare/correct-hooks";

const publicVerifyingKeySet = createPublicVerifyingKeySet([secretSigningKey]);
const publicVerifyingKeySetJson = JSON.stringify(publicVerifyingKeySet);
```

#### Sign a request

Sign the request data and set the headers `correct-hooks-signature-components` and `correct-hooks-signature` to
the returned values. See (SignArgs) for argument details.
```typescript
import { sign } from "@handlewithcare/correct-hooks";

const signatureHeaders = sign({
  webhookId,
  targetUrl,
  method,
  requestBody,
  secretSigningKey,
});
const { correctHooksSignatureComponents, correctHooksSignature } = signatureHeaders;
```

### Webhook Consumers

Create a Verifier with the webhook producers public verifying key set url. You create a Verifier once when you backend instance starts and reuse it for all requests to that instance.
#### Create a verifier
```typescript
import { Verifier, createPublicVerifyingKeySet, generateSecretSigningKey, sign, } from "@handlewithcare/correct-hooks";
const verifier = new Verifier({
  publicVerifyingKeySetUrl,
});
```

#### Verify a request
Verify a request with the Verifier. Any error indicates that the signature is invalid and the request should be immediately rejected.

See (VerifyArgs) for argument details.
```typescript
import { Verifier, createPublicVerifyingKeySet, generateSecretSigningKey, sign, } from "@handlewithcare/correct-hooks";

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


## Key Rotation
we are also have a cli that can create secret and public keys to assist with key rotation

you can do this as much as you want and your customers won't even notice. What else do you have going on on a Friday?


## Migration
Correct Hooks is designed so that it can be used in parallel with other webhook authentication approaches allowing you to migrate your existing webhook system to Correct Hooks without downtime. To start migrating to Correct Hooks, all you have to do is add the Correct Hooks headers to your webhook requests.

## Upgrades
Correct Hooks is designed to be independently upgradable by webhook producers and consumers. 

Correct Hooks has two version numbers that need to be paid attention to when upgrading, the library version and the signature version.

Correct Hooks libraries use semantic versioning and may have breaking changes on major version updates and prior to a 1.0 release, on minor version updates.
A Correct Hooks library also has a signature version, generally stored in the `SIGNATURE_VERSION` constant. An update with breaking changes 
will not necessarily change a library's signature version, but changing the signature version will constitute a breaking change.

Correct Hooks libraries sign signatures with their version by default but will have functions to sign a signature with earlier versions. When performing a Correct Hooks update that has breaking changes, signers should check if the signature version has changed. If it has, you can create signatures with the new signature version and the old signature version and add both to the Correct Hooks headers separated by a space. 

Correct Hooks libraries can verify signatures with versions less than or equal to their signature version and will attempt to verify the highest signature version that they can. This allows webhook consumers to update their version of Correct Hooks whenever they want, and allows webhook producers to upgrade Correct Hooks without downtime, supporting multiple signature versions until they choose to deprecate and remove support for older versions.

As of now this is largely hypothetical because there is only one signature version, but the support for backwards compatibility is already built into the Correct Hooks libraries. If we release a new signature version in the future, we will provide detailed instructions on how to upgrade.

## Other concerns

### I'm using <INSERT OBSCURE LANGUAGE>. How do I verify webhooks?
If you are a webhook consumer using a language we do not provide library support for, there are a few things you can do:
1. Let us know. The goal of this project is to provide the language support for the large majority of developers. If there is enough demand, we can add official support for a language.
2. Implement the verification steps yourself, or even better build a community library for your language! Using the existing library implemenations as references, you can implement Correct Hooks in a new language pretty quickly. We have resources that make implementing a community library easy, in particular a cross language test suite, and can advise on key steps the library needs function properly (also see #language-support).

### Don't I need still need a unique private key for every endpoint I send webhooks to?
No. I don't know how this idea got started, but I see it cited a lot. Sometimes by people who should know better <Todo: Remove?>. Correct hooks includes all the information in it's signature needed to confirm that a request was both signed by the webhook producer and is intended to be recieved at the endpoint it was sent to. One private key can be used for all webhooks sent by the webhook producer.

### Isn't asymmetric signing slow?
Nope. Evaluations of signing methods often fall into a performance optimization trap, evaluating how fast two algorithms are compared to each other instead of whether the difference matters.

While symmetric HMAC signatures are in fact extremely fast to sign and verify, the modern ed25519 algorithm Correct Hooks uses for its signatures is also very fast. Profiling on my laptop, signing a 5 KiB payload with ed25519 in Rust takes 35μs. That is a rate of 28,000 signatures per second on a single cpu thread. Typescript came in at (a mere) 28,000 signatures per second. This has no meaningful impact on the performance of a webhook system.

### What other considerations do I need to keep in mind when building a webook system?
Correct Hooks makes webhook signing, verification, and key management easy, but there are additional security and quality of service considerations to take into account when building a webhook system. These include but are not limited to enforcing https, protecting against SSRF attacks, implementing reliable retries, and dead letter management. The (Standard Webhooks Spec)[https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md#operational-considerations] has good recommendations to consider when building a webhook system.

The code and infrastructure required for a well designed webhook system is actually not too complicated, but it can be time consuming to identify and design around all of the requirements for the first time and then realize you missed something and have to wedge new requirements in. If you want full control over your webhooks, but don't want to reinvent the wheel, come talk to us! We can help get your team up and running with webhooks quickly.  

