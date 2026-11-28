These RSA keys are synthetic, publicly committed test fixtures generated locally
with JDK KeyPairGenerator. They have never been registered with OpenAI or used
for a real account. The PKCS#8 base64 files intentionally contain test-only
private keys so tests can sign altered claims using actual SHA256withRSA.

rsa2048: lower accepted RSA boundary; rsa8192: upper accepted RSA boundary.
The matching JWKS files contain public keys only. Tokens are generated in test
memory; no live credentials, transport, listener or browser is involved.
