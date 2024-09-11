pragma circom 2.1.9;

include "@crema-labs/ecdsa-p384-circom/circuits/ecdsa.circom";
include "hash-circuits/circuits/sha2/sha384/sha384_hash_bits.circom";
include "utils.circom";

template Sha384ECDSAVerify(TBSSize){
    signal input TBSData[TBSSize];

    signal input r[8];
    signal input s[8];

    signal input PubKey[2][8];
    signal output status;

    component sha384Hash = Sha384_hash_bits_digest(TBSSize);
    sha384Hash.inp_bits <== TBSData; 

    component bytesToBits = BytesToBits(48);
    bytesToBits.in <== sha384Hash.hash_bytes; 

    component bitsToWords = SplitToWords(384, 48, 8);
    bitsToWords.in <== bytesToBits.out;  

    component p384Ecdsa = ECDSAVerifyNoPubkeyCheck(48, 8);
    p384Ecdsa.msghash <== bitsToWords.out;
    p384Ecdsa.r <== r;
    p384Ecdsa.s <== s;
    p384Ecdsa.pubkey <== PubKey;
    p384Ecdsa.result ==> status;
}