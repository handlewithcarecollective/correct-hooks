# correct-hooks

### Webhook Producers

#### Key generation

To sign requests, you first need to generate a secret signing key. The key serializes to a json string which should be stored in your secret manager. The secret signing
key should be treated as an opaque blob, and you should never edit it's contents.

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
const { webhookId } = verifiedData;
```
