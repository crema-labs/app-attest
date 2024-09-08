pragma circom 2.1.9;

include "@crema-labs/ecdsa-p384-circom/circuits/ecdsa.circom";
include "./hash-circuits/circuits/sha2/sha384/sha384_hash_bits.circom";
include "./sha256-var-module/circuits/sha256Var.circom";
include "./utils.circom";


template VerifyCertChain(TBS2Size,TBS3Size,BlockSpace){
  signal input r[3][8];
  signal input s[3][8];
  signal input TBS1Size;
  
  var BLOCK_LEN = 512;
  var MaxBlockCount = pow(2, BlockSpace);
  var MaxLen = BLOCK_LEN * MaxBlockCount; // max size of TBS1Data in bits as per sha256var spec
  signal input TBS1Data[MaxLen];

  signal input TBS2Data[TBS2Size];
  signal input TBS3Data[TBS3Size];
  signal input PubKeys[3][2][8];

  signal output out;
  signal status[3];   
  component sha384Hash[2];
  component p384Ecdsa[3];
  component bitsToWords[3];
  component padding;
  component bytesToBits[2];   
  component sha256Hash = Sha256Var(4); // 4 bits for 16 blocks each of 512 bits   
  // variable length hash of leaf certificate raw tbs data
  sha256Hash.in <== TBS1Data;
  sha256Hash.len <== TBS1Size;    
  padding = PadBits(256, 384);
  padding.in <== sha256Hash.out;  
  bitsToWords[0] = SplitToWords(384, 48, 8);
  bitsToWords[0].in <== padding.out;  
  // signature verification with public key of next certificate in chain
  p384Ecdsa[0] = ECDSAVerifyNoPubkeyCheck(48, 8);
  p384Ecdsa[0].msghash <== bitsToWords[0].out;    
  p384Ecdsa[0].r <== r[0];
  p384Ecdsa[0].s <== s[0];
  p384Ecdsa[0].pubkey <== PubKeys[0];
  p384Ecdsa[0].result ==> status[0];    
  // const length hash of intermediate certificate raw tbs data
  sha384Hash[0] = Sha384_hash_bits_digest(TBS2Size);
  sha384Hash[0].inp_bits <== TBS2Data;   
  bytesToBits[0] = BytesToBits(48);
  bytesToBits[0].in <== sha384Hash[0].hash_bytes; 
  bitsToWords[1] = SplitToWords(384, 48, 8);
  bitsToWords[1].in <== bytesToBits[0].out;  
  p384Ecdsa[1] = ECDSAVerifyNoPubkeyCheck(48, 8);
  p384Ecdsa[1].msghash <== bitsToWords[1].out;
  p384Ecdsa[1].r <== r[1];
  p384Ecdsa[1].s <== s[1];
  p384Ecdsa[1].pubkey <== PubKeys[1];
  p384Ecdsa[1].result ==> status[1];
  // const length hash of root certificate raw tbs data
  sha384Hash[1] = Sha384_hash_bits_digest(TBS3Size);
  sha384Hash[1].inp_bits <== TBS3Data;
  bytesToBits[1] = BytesToBits(48);
  bytesToBits[1].in <== sha384Hash[1].hash_bytes; 
  bitsToWords[2] = SplitToWords(384, 48, 8);
  bitsToWords[2].in <== bytesToBits[1].out;
  p384Ecdsa[2] = ECDSAVerifyNoPubkeyCheck(48, 8);
  p384Ecdsa[2].msghash <== bitsToWords[2].out;
  p384Ecdsa[2].r <== r[2];
  p384Ecdsa[2].s <== s[2];
  p384Ecdsa[2].pubkey <== PubKeys[2];
  p384Ecdsa[2].result ==> status[2];
  out <== status[0] + status[1] + status[2];
  out === 3;
}