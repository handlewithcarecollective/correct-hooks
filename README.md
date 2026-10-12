# Correct Hooks

Multi language set of libraries that 
designed to makes asymetric signing, verfication, and key rotation for webhooks trivial for webhook producers and consumers.

Giving your webhook system better security and better developer experience than is possible with symmetric signing
Give your customers peace of mind that your webhooks are well secured.


Why:

Most webhook services use sign webhooks using symmetric signign (HMAC). This starts off easy, but to be done securely requires the webhook provider to create a unique secret for every consmer endpoint they send webhooks to. 

Introduces development complexity
Security liability.
Inherently less secure than a system that can use 
