# Apple app attest Architecture
This document describes the architecture of the Apple app attest system.
### Actors 

- **Apple App Attest Server**: The server that issues the attestation keys to the app.
- **An iOS App**: The app that wants to use the attestation keys.
- **App Backend Server**: The server that the app communicates with.

### Flow

Phase 1: Attestation
1. The iOS app creates a public-private key pair in the Secure Enclave.
2. The iOS app requests the server for some random data.
3. The iOS app send the data and the public key to the Apple App Attest Server.
4. The Apple App Attest Server signs and creates an attestation object and sends it back to the iOS app.
5. The iOS app sends the attestation object to the App Backend Server.
6. The App Backend Server verifies the attestation object with the Apple Certificate Authority which is publicly available and other verification steps as mentioned in the [Apple documentation for attestation validity](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server#Verify-the-attestation).
7. The App Backed also store the public key hash of the leaf X.509 certificate in the attestation object for future verification.
8. Optionally, the App Backend Server will also verify receipt of the attestation object with the Apple App Attest Server and stores it.

Phase 2: Assertion

The iOS app after attestation can request the server for some data with an assertion. The backend server will verify the assertion with the public key hash stored from attestation object.The backend can decide to when when assertion is required based on the business logic.

1. The iOS app requests the server for some random data .
2. The iOS app generates an assertion using the private key in the Secure Enclave and `clientDataHash`.
3. The iOS app sends the assertion to the App Backend Server which verifies the assertion and checks if the hash of the public key has been attested before. Refer to the [Apple documentation for assertion validity](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server#Verify-the-assertion).

### Notes
1. Attestation object contains three X.509 certificates: 
    - **Leaf X.509 certificate**: The certificate that contains the public key of the app.
    - **Intermediate X.509 certificate**: The certificate that signs the leaf certificate.
    - **Root X.509 certificate**: The certificate that signs the intermediate certificate and is the root certificate of the Apple App Attest Server available at [Apple  CA](https://www.apple.com/certificateauthority/private/).
  - All the certificate for attestations are generated using the Elliptic Curve Digital Signature Algorithm (ECDSA) with the P-384 curve.
  - Assuming there will only be 3 certificates in the attestation object.
    - The leaf certificate is the first certificate in the `x5c` array needs P-384 curve verification with SHA-256 of RawTBSData from leaf certificate and public key of intermediate certificate.
    - The intermediate certificate is the second certificate in the `x5c` array needs P-384 curve verification with SHA-384 of RawTBSData from intermediate certificate and public key of root certificate.
    - THe root certificate is the third certificate in the `x5c` array needs P-384 curve verification with SHA-384 of RawTBSData from root certificate and public key of root certificate itself.
  - The attestation object is in CBOR encoding.
```cbor
{
  fmt: 'apple-appattest',
  attStmt: {
    x5c: [
      <Buffer 30 82 02 cc ... >,
      <Buffer 30 82 02 36 ... >
    ],
    receipt: <Buffer 30 80 06 09 ... >
  },
  authData: <Buffer 21 c9 9e 00 ... >
}
```
2. Assertions are signed using the Elliptic Curve Digital Signature Algorithm (ECDSA) with the P-256 curve.


### POC and Demo Plan
We use the flow to prove a user in in Asia without revealing which country you are in.
1. Create a simple iOS app that address to the above flow to generate attestation object and verify on chain.
2. Verifier contract that verifies the attestation object and stores the public key hash.
3. iOS application will generate a assertion with proof that the device is in a particular location.
4. Verifier contract will verify the assertion and location proof.

### Blockers

1. Implementation of variable length sha-384.