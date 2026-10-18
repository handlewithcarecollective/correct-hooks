# Correct Hook


### Webhook Producers

#### Key generation
To sign requests, you first need to generate a secret signing key. The key serializes to a json string which should be stored in your secret manager. 

The secret signing key should be treated as an opaque blob, and you should never edit it's contents.
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
