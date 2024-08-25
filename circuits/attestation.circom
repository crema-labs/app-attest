pragma circom 2.1.5;

import "@crema-labs/ecdsa-p384-circom/circuits/ecdsa.circom";
import "./hash-circuit/circuits/sha2/sha384/sha384_hash_bytes.circom";

template VerifyCertChain(m){
  signal input r[3][8];
  signal input s[3][8];

  signal input TBS1Size;
  signal input TBS2Size;
  signal input TBS3Size;
  signal input TBSData[3][m];

  signal input PubKeys[3][2][8];

  signal output out;

  signal status[3];

  component hash[2];
  component ecdsa[3];

  for (var i = 0; i < 3; i++) {
    has[i] = Sha384_hash_bytes_digest(m);
    ecdsa[i] = ECDSAVerifyNoPubkeyCheck(48, 8);

    hash[i].inp_bytes <== TBSData[i];
    ecdsa[i].msghash <== hash[i].hash_bytes;
    ecdsa[i].r <== r[i];
    ecdsa[i].s <== s[i];
    ecdsa[i].pubkey <== PubKeys[i];
    ecdsa[i].result ==> out;
  }

  out <== status[0] + status[1] + status[2];

  out === 3;
}

