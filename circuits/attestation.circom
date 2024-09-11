pragma circom 2.1.9;

include "@crema-labs/ecdsa-p384-circom/circuits/ecdsa.circom";
include "hash-circuits/circuits/sha2/sha384/sha384_hash_bits.circom";
include "sha256-var-module/circuits/sha256Var.circom";
include "utils.circom";
include "ecdsa-with-sha384.circom";

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

  component ecdsaWith384[2];
  component sha256Hash = Sha256Var(4);

   // 4 bits for 16 blocks each of 512 bits   
  // variable length hash of leaf certificate raw tbs data
  sha256Hash.in <== TBS1Data;
  sha256Hash.len <== TBS1Size;    
  component padding = PadBits(256, 384);
  padding.in <== sha256Hash.out;  
  component bitsToWords = SplitToWords(384, 48, 8);
  bitsToWords.in <== padding.out;  

  // signature verification with public key of next certificate in chain
  component p384Ecdsa = ECDSAVerifyNoPubkeyCheck(48, 8);
  p384Ecdsa.msghash <== bitsToWords.out;    
  p384Ecdsa.r <== r[0];
  p384Ecdsa.s <== s[0];
  p384Ecdsa.pubkey <== PubKeys[0];
  p384Ecdsa.result ==> status[0]; 
  p384Ecdsa.result === 1;


  ecdsaWith384[0] = Sha384ECDSAVerify(TBS2Size);
  ecdsaWith384[0].TBSData <== TBS2Data;
  ecdsaWith384[0].r <== r[1];
  ecdsaWith384[0].s <== s[1];
  ecdsaWith384[0].PubKey <== PubKeys[1];
  ecdsaWith384[0].status ==> status[1];
  ecdsaWith384[0].status === 1;


  ecdsaWith384[1] = Sha384ECDSAVerify(TBS3Size);
  ecdsaWith384[1].TBSData <== TBS3Data;
  ecdsaWith384[1].r <== r[2];
  ecdsaWith384[1].s <== s[2];
  ecdsaWith384[1].PubKey <== PubKeys[2];
  ecdsaWith384[1].status ==> status[2];
  ecdsaWith384[1].status === 1;
  
  out <== status[0] + status[1] + status[2];
}