pragma circom 2.1.9;

include "@crema-labs/ecdsa-p384-circom/circuits/ecdsa.circom";
include "hash-circuits/circuits/sha2/sha384/sha384_hash_bits.circom";
include "sha256-var/circuits/sha256Var.circom";


template VerifyCertChain(TBS2Size,TBS3Size){
  signal input r[3][8];
  signal input s[3][8];

  signal input TBS1Size;
  signal input TBS1Data[8192]; // max size of TBS1Data in bits as per sha256var spec
  signal input TBS2Data[TBS2Size];
  signal input TBS3Data[TBS3Size];

  signal input PubKeys[3][2][8];

  signal output out;

  signal status[3];

  component sha256Hash = Sha256Var(4); // 4 bits for 16 blocks each of 512 bits
  component sha384Hash[2];
  component p384Ecdsa[3];
  component bitsToWords[3];


  // variable length hash of leaf certificate raw tbs data
  sha256Hash.in <== TBS1Data;
  sha256Hash.len <== TBS1Size;

  bitsToWords[0] = BitStreamToWords(256);
  bitsToWords[0].in <== sha256Hash.out;

  // signature verification with public key of next certificate in chain
  p384Ecdsa[0] = ECDSAVerifyNoPubkeyCheck(48, 8);
  p384Ecdsa[0].msghash <== bitsToWords[0].out;

  p384Ecdsa[0].r <== r[0];
  p384Ecdsa[0].s <== s[0];
  p384Ecdsa[0].pubkey <== PubKeys[0];
  p384Ecdsa[0].result ==> status[0];

  // const length hash of intermediate certificate raw tbs data
  sha384Hash[0] = Sha384_hash_bytes_digest(TBS2Size);
  sha384Hash[0].inp_bytes <== TBS2Data;

  bitsToWords[1] = BitStreamToWords(384);
  bitsToWords[1].in <== sha384Hash[0].hash_bytes;

  p384Ecdsa[1] = ECDSAVerifyNoPubkeyCheck(48, 8);
  p384Ecdsa[1].msghash <== bitsToWords[1].out;
  p384Ecdsa[1].r <== r[1];
  p384Ecdsa[1].s <== s[1];
  p384Ecdsa[1].pubkey <== PubKeys[1];
  p384Ecdsa[1].result ==> status[1];


  // variable length hash of root certificate raw tbs data
  sha384Hash[1] = Sha384_hash_bytes_digest(TBS3Size);
  sha384Hash[1].inp_bytes <== TBS3Data;

  bitsToWords[2] = BitStreamToWords(384);
  bitsToWords[2].in <== sha384Hash[1].hash_bytes;

  p384Ecdsa[2] = ECDSAVerifyNoPubkeyCheck(48, 8);
  p384Ecdsa[2].msghash <== bitsToWords[2].out;
  p384Ecdsa[2].r <== r[2];
  p384Ecdsa[2].s <== s[2];
  p384Ecdsa[2].pubkey <== PubKeys[2];
  p384Ecdsa[2].result ==> status[2];

  out <== status[0] + status[1] + status[2];

  out === 3;
}