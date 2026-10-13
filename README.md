# Correct Hooks

A multi-language set of libraries that perform asymmetric signing, verification, and key management for webhook authentication. 

Correct Hooks makes one of the most secure authentication mechanisms for webhooks the easiest to implement for both webhook producers and consumers.

## Why:

Because the existing options are bad. If you want to provide webhooks to your users, you quickly discover that there are few prebuilt auth systems intended for use with webhooks. The options that do exist require you to implement complex secret mangagement systems if you want to serve webhooks from your own infrastructure.

Most webhook producers authenticate their webhooks using symmetric signatures (HMAC). Signing and verifying a symmetric signature is easy, and naive authentication implementations using symmetric signatures start off simple. But because symmetric signatures use the same secret key for signing and verification, the webhook producer has to keep a unique shared secret for every user they have (and in practice every endpoint they send a webhook to). Managing a set of shared secrets that scales with the size of your customer base creates a cascade of security and quality of service liabilities that introduce significant system complexity to resolve.

Asymmetric signatures on the other hand do not have this problem. The webhook producer can hold a single private signing key stored in a secret manager and all webhook consumers can access the public verifying key through a public endpoint the webhook producer provides. When the key needs to be rotated, the webhook producer updates their public verifying key set, and webhook consumers can automatically retrieve the new verifying key for a zero-downtime rotation.

But actually signing and verifying asymmetric signatures is much harder than symmetric signatures. Identifying how to generating and distribute asymmetric keys is time consuming, and the steps to properly sign and verify an asymmetric signature are not always intuitive, requiring extra data in the signature message and cryptography libraries that are not always well documented and contain lots of sharp edges. Even if a webhook producer is willing to take the time to implement asymmetric signing they may not want to put the burden of properly verifying those signatures on their customers.

The goal of Correct Hooks is to provide the best of both worlds, encapsulating the code to sign, verify, and manage keys for asymmetric signatures in a user friendly library with language support that covers the needs of the large majority of developers, making the auth solution that is the most fundamentally secure the easiest to implement for both webhook producers and consumers.

## Where is this going
Correct Hooks is in the early stages of development but is currently usable. We have support for Typescript, Python, and Rust, and are planning to add support for Java, Go, and C# over the next few weeks. We also provide prebuilt CLI binaries that can be called from any language.

We will continue evaluating additional languages to support and are happy to advise on the development of community libraries. We also provide a cross language test suite that can be used to test community built libraries.

## How to authenticate webhooks with Correct Hooks

### Webhook Producers

### Key generation and rotation
To sign requests, you first need a secret signing key
This key serializes to a json string. The json string representing the key should be stored in your secret manager. The secret signing key should be treated as an opaque blob, and you should never edit it's contents.

Todo: Generate secret signing key
      Serialize to json

When you need to use the secret signing key, you can reload it from it's json string.

### Public key generation
For your webhook consumers to verify your signatures, they need the public verifying key set for your signing keys. create this with jfaljdslkafld

This key set serializes to a json string. You should put this key set in your database and serve it from a published url, Todo: url var name

### Key Rotation

### Signing


### Verifying

## Migration
Correct Hooks is designed so that it can be used in parallel with other webhook authentication approaches allowing you to migrate your existing webhook system to Correct Hooks without downtime.

## Upgrades
Correct Hooks is designed to be independently upgraded by webhook producers and consumers. 

Correct Hooks has two version numbers that need to be paid attention to when upgrading, the library version and the signature version.

Correct Hooks libraries use semantic versioning and may have breaking changes on major version updates or prior to a 1.0 release, on minor version updates.
Any given version of a correct hooks library has a signature version, generally stored in the `SIGNATURE_VERSION` constant. An update with breaking changes 
will not necessarily change a library's signature version, but changing the signature version will constitute a breaking change.

Correct Hooks libraries sign signatures with their version by default but will have functions to sign a signature with earlier versions. When updating Correct Hooks to a version with breaking changes, signers should check if the signature version has changed. If it has, you can create signatures with the new signature version and the old signature version and add both to the Correct Hooks headers separated by a space. 

The library can verify signatures with versions less than or equal to its signature version and will attempt to verify the highest signature version that it can. This allows
webhook consumers to update their version of Correct Hooks whenever they want, and allows webhook producers to upgrade Correct Hooks without downtime, supporting multiple signature versions until they choose to deprecate and remove support for older versions.

As of now this is largely hypothetical because there is only one signature version, but the support for backwards compatibility is already built into the Correct Hooks libraries. If we release a new signature version in the future, we will provide detailed instructions on how to upgrade.

## Other concerns

### My customer is using <INSERT OBSCURE LANGUAGE>. How do they verify my webhooks?
If you or a customer is a webhook consumer using a language we do not provide library support for, there are a few things to do:
1. Let us know. The goal of this project is to provide the language support for the large majority of developers. If there is enough demand, we can add official support for a language.
2. If we don't plan to support a language or can't provide support soon enough for the webhook consumer's needs, we also provide compiled binaries that execute the verification functions of the library (todo: build this). These can be executed from any language and can be used as a stop gap.
3. Any production language should support the cryptographic functions necessary to verify Correct Hooks signatures, and the webhook consumer can implement their own verification function based on our code. (todo: mention planned spec?) We are also happy to advise on a customer's verification implementation, or advise on making a community supported library.

### Don't I need still need a unique private key for every endpoint I send webhooks to?
No. I don't know how this idea got started, but I see it cited a lot. <todo: insert links?>. Sometimes by people who should know better. Correct hooks includes all the information in it's signature to confirm that a request was both signed by the webhook provider and is intended to be recieved at the endpoint it was sent to. One private key can be used for all webhooks sent by the webhook producer.

### Isn't asymmetric signing slow?
Nope. Evaluations of signing methods often fall into a performance optimization trap, evaluating how fast two algorithms are compared to each other instead of whether the difference matters.

While symmetric HMAC signatures are in fact extremely fast to sign and verify, the modern ed25519 algorithm Correct Hooks uses for its signatures is also very fast. Profiling on my laptop, our signatures take (todo: insert microseconds) to sign, that is a rate of (insert rate) signature per second on a single cpu thread. This has no meaningful impact on the performance of a webhook system. (todo: insert a caveat?)

### What other considerations do I need to keep in mind when building a webook system?
Correct Hooks makes webhook signing, verification, and key management easy, but there are additional security and quality of service considerations to take into account when build a webhook system. These include but are not limited to enforcing https, protecting against SSRF attacks, implementing reliable retries and dead letter management. The (Standard Webhooks Spec)[https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md#operational-considerations] has good recommendations to consider when building a webhook system.

The code and infrastructure required for a well designed webhook system is actually not too complicated, but it can be time consuming to identify and design around all of the requirements for the first time, and then realized you missed something and have to wedge new requirements in. If you want full control over your webhooks, but don't want to reinvent the wheel, come talk to us! We can help get your team up and running with webhooks quickly.  

Todo: add a implementation details section?
