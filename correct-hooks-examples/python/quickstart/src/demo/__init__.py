import asyncio
import uuid
from http import HTTPStatus

from correct_hooks import (
  SignArgs,
  Verifier,
  VerifierConfig,
  VerifyArgs,
  create_public_verifying_key_set,
  generate_secret_signing_key,
  sign,
)
from pydantic import AnyUrl


async def example() -> HTTPStatus:
  # Create a secret signing key and serialize it to a json string
  # Store the string in your secret manager
  secret_signing_key = generate_secret_signing_key()
  secret_signing_key_json = secret_signing_key.model_dump_json()

  _ = secret_signing_key_json

  # Create a public verifying key set for a list of signing keys and serialize it to a json string
  # Store the string in your database
  # Serve the json string at a known `GET` endpoint, `public_verifying_key_set_url`
  public_verifying_key_set = create_public_verifying_key_set([secret_signing_key])
  public_verifying_key_set_json = public_verifying_key_set.model_dump_json()

  _ = public_verifying_key_set_json

  # Sign a webhook request (webhook producer side).
  # `target_id` is assigned by the producer when the consumer registers an endpoint.
  webhook_id = uuid.uuid4()
  target_id = uuid.uuid4()

  method = "POST"
  request_body = b"a payload"

  # Send the returned string in the `correct-hooks-signature` header
  correct_hooks_signature = sign(
    SignArgs(
      webhook_id=webhook_id,
      target_id=target_id,
      method=method,
      request_body=request_body,
      secret_signing_key=secret_signing_key,
    )
  )

  public_verifying_key_set_url = (
    "https://webhookproducersdomain.com/known/path/to/key/set"
  )

  # Create a verifier with the webhook producer's `public_verifying_key_set_url`.
  # Reuse it to validate all requests sent to this instance
  verifier = Verifier(
    VerifierConfig(
      public_verifying_key_set_url=AnyUrl(public_verifying_key_set_url),
    )
  )

  # Verify a request with the verifier
  # Any error indicates that the signature is invalid and the request should
  # be immediately rejected.
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

  _ = verified_data

  return HTTPStatus.OK


def main() -> None:
  print(asyncio.run(example()))
