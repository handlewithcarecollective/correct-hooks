import asyncio
import uuid
from http import HTTPStatus

from correct_hooks import (
  PublicVerifyingKeySet,
  SecretSigningKey,
  SignArgs,
  Verifier,
  VerifierConfig,
  VerifyArgs,
  create_public_verifying_key_set,
  generate_secret_signing_key,
  sign,
)
from pydantic import AnyUrl


def create_secret_signing_key() -> SecretSigningKey:
  #=============================
  secret_signing_key = generate_secret_signing_key()
  secret_signing_key_json = secret_signing_key.model_dump_json()
  #=============================

  _ = secret_signing_key_json

  return secret_signing_key


def create_key_set(secret_signing_key: SecretSigningKey) -> PublicVerifyingKeySet:
  #=============================
  public_verifying_key_set = create_public_verifying_key_set([secret_signing_key])
  public_verifying_key_set_json = public_verifying_key_set.model_dump_json()
  #=============================

  _ = public_verifying_key_set_json

  return public_verifying_key_set


def sign_request(
  secret_signing_key: SecretSigningKey,
  target_id: uuid.UUID,
  method: str,
  request_body: bytes,
) -> str:
  webhook_id = uuid.uuid4()

  #=============================
  correct_hooks_signature = sign(
    SignArgs(
      webhook_id=webhook_id,
      target_id=target_id,
      method=method,
      request_body=request_body,
      secret_signing_key=secret_signing_key,
    )
  )
  #=============================

  return correct_hooks_signature


def create_verifier() -> Verifier:
  public_verifying_key_set_url = (
    "https://webhookproducersdomain.com/known/path/to/key/set"
  )

  #=============================
  verifier = Verifier(
    VerifierConfig(
      public_verifying_key_set_url=AnyUrl(public_verifying_key_set_url),
    )
  )
  #=============================

  return verifier


async def verify_request(
  verifier: Verifier,
  target_id: uuid.UUID,
  method: str,
  correct_hooks_signature: str,
  request_body: bytes,
) -> HTTPStatus:
  #=============================
  try:
    verified_data = await verifier.verify(
      VerifyArgs(
        target_id=target_id,
        method=method,
        correct_hooks_signature=correct_hooks_signature,
        request_body=request_body,
      )
    )
  except Exception:
    return HTTPStatus.FORBIDDEN
  #=============================

  _ = verified_data

  return HTTPStatus.OK


async def example() -> HTTPStatus:
  secret_signing_key = create_secret_signing_key()
  _ = create_key_set(secret_signing_key)

  target_id = uuid.uuid4()
  method = "POST"
  request_body = b"a payload"

  correct_hooks_signature = sign_request(
    secret_signing_key, target_id, method, request_body
  )

  verifier = create_verifier()
  status = await verify_request(
    verifier, target_id, method, correct_hooks_signature, request_body
  )

  return status


def main() -> None:
  print(asyncio.run(example()))
