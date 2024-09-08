pragma circom 2.1.9;

include "circomlib/circuits/bitify.circom";

template SplitToWords(nBits, wordsize, numberElement) {
    signal input in[nBits];
    signal output out[numberElement];

    assert(numberElement * wordsize == nBits);

    component bitsToNum[numberElement];  

    for (var i = 0; i < numberElement; i++) {
        bitsToNum[i] = Bits2Num(wordsize);
        for (var j = 0; j < wordsize; j++) {
            bitsToNum[i].in[wordsize-1-j] <== in[i*wordsize + j];
        }
        bitsToNum[i].out ==> out[numberElement-1-i];
    }
}

template BytesToBits(nBytes) {
    signal input in[nBytes];
    signal output out[nBytes*8];

    component NumToBits[nBytes];

    for (var i=0; i < nBytes; i++) {
        NumToBits[i] = Num2Bits(8);
        NumToBits[i].in <== in[i];
       for (var j=0; j < 8; j++) {
            out[i*8 + j] <== NumToBits[i].out[j];
        }
    }
}

template PadBits(nBits,target){
    assert(nBits <= target);
    
    signal input in[nBits];
    signal output out[target];

    for (var i=0; i < target-nBits; i++) {
        out[i] <== 0;
    }
    for (var i= target-nBits; i < target; i++) {
        out[i] <== in[i-(target-nBits)];
    }
}
