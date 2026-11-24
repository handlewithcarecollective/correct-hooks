import {
  Verifier,
  createPublicVerifyingKeySet,
  generateSecretSigningKey,
  sign,
  type PublicVerifyingKeySet,
  type SecretSigningKey,
} from "@handlewithcare/correct-hooks";
import { randomUUID } from "node:crypto";

const StatusCode = { OK: 200, FORBIDDEN: 403 } as const;
type StatusCode = (typeof StatusCode)[keyof typeof StatusCode];

function createSecretSigningKey(): SecretSigningKey {
  //=============================
  const secretSigningKey = generateSecretSigningKey();
  const secretSigningKeyJson = JSON.stringify(secretSigningKey);
  //=============================

  return secretSigningKey;
}

function createKeySet(secretSigningKey: SecretSigningKey): PublicVerifyingKeySet {
  //=============================
  const publicVerifyingKeySet = createPublicVerifyingKeySet([secretSigningKey]);
  const publicVerifyingKeySetJson = JSON.stringify(publicVerifyingKeySet);
  //=============================

  return publicVerifyingKeySet;
}

function signRequest(
  secretSigningKey: SecretSigningKey,
  targetId: string,
  method: string,
  requestBody: Uint8Array,
): string {
  const webhookId = randomUUID();

  //=============================
  const correctHooksSignature = sign({
    webhookId,
    targetId,
    method,
    requestBody,
    secretSigningKey,
  });
  //=============================

  return correctHooksSignature;
}

function createVerifier(): Verifier {
  const publicVerifyingKeySetUrl = new URL(
    "https://webhookproducersdomain.com/known/path/to/key/set",
  );

  //=============================
  const verifier = new Verifier({
    publicVerifyingKeySetUrl,
  });
  //=============================

  return verifier;
}

async function verifyRequest(
  verifier: Verifier,
  targetId: string,
  method: string,
  correctHooksSignature: string,
  requestBody: Uint8Array,
): Promise<StatusCode> {
  //=============================
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
  //=============================

  void verifiedData;

  return StatusCode.OK;
}

async function example(): Promise<StatusCode> {
  const secretSigningKey = createSecretSigningKey();
  createKeySet(secretSigningKey);

  const targetId = randomUUID();
  const method = "POST";
  const requestBody = new TextEncoder().encode("a payload");

  const correctHooksSignature = signRequest(secretSigningKey, targetId, method, requestBody);

  const verifier = createVerifier();
  const status = await verifyRequest(
    verifier,
    targetId,
    method,
    correctHooksSignature,
    requestBody,
  );

  return status;
}

console.log(await example());
