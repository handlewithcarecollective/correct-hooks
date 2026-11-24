import {
  Verifier,
  createPublicVerifyingKeySet,
  generateSecretSigningKey,
  sign,
} from "@handlewithcare/correct-hooks";
import { randomUUID } from "node:crypto";

const StatusCode = { OK: 200, FORBIDDEN: 403 } as const;
type StatusCode = (typeof StatusCode)[keyof typeof StatusCode];

async function example(): Promise<StatusCode> {
  // Create a secret signing key and serialize it to a json string
  // Store the string in your secret manager
  const secretSigningKey = generateSecretSigningKey();
  const secretSigningKeyJson = JSON.stringify(secretSigningKey);

  // Create a public verifying key set for a list of signing keys and serialize it to a json string
  // Store the string in your database
  // Serve the json string at a known `GET` endpoint, `publicVerifyingKeySetUrl`
  const publicVerifyingKeySet = createPublicVerifyingKeySet([secretSigningKey]);
  const publicVerifyingKeySetJson = JSON.stringify(publicVerifyingKeySet);

  void secretSigningKeyJson;
  void publicVerifyingKeySetJson;

  // Sign a webhook request (webhook producer side).
  // `targetId` is assigned by the producer when the consumer registers an endpoint.
  const webhookId = randomUUID();
  const targetId = randomUUID();

  const method = "POST";
  const requestBody = new TextEncoder().encode("a payload");

  // Send the returned string in the `correct-hooks-signature` header
  const correctHooksSignature = sign({
    webhookId,
    targetId,
    method,
    requestBody,
    secretSigningKey,
  });

  const publicVerifyingKeySetUrl = new URL(
    "https://webhookproducersdomain.com/known/path/to/key/set",
  );

  // Create a verifier with the webhook producer's `publicVerifyingKeySetUrl`.
  // Reuse it to validate all requests sent to this instance
  const verifier = new Verifier({
    publicVerifyingKeySetUrl,
  });

  // Verify a request with the verifier
  // Any error indicates that the signature is invalid and the request should
  // be immediately rejected.
  let verifiedData;
  try {
    verifiedData = await verifier.verify({
      targetId,
      method,
      correctHooksSignature,
      requestBody,
    });
  } catch {
    return StatusCode.FORBIDDEN;
  }

  void verifiedData;

  return StatusCode.OK;
}

console.log(await example());
