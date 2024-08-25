export function splitToWords(number: bigint, wordsize: bigint, numberElement: bigint): bigint[] {
  let t = number;
  const words: bigint[] = [];
  const mask = BigInt(BigInt(1) << wordsize) - 1n;
  for (let i = BigInt(0); i < numberElement; ++i) {
    const word = t & mask;
    words.push(word);
    t >>= wordsize;
  }
  if (!(t == BigInt(0))) {
    throw `Number ${number} does not fit in ${(wordsize * numberElement).toString()} bits`;
  }
  return words;
}

export function hexToBigInt(hex: string) {
  return BigInt(`0x${hex}`);
}

export function bufferToBigIntArray(buffer: Buffer): bigint[] {
  const bigIntArray: bigint[] = [];

  for (const byte of buffer) {
    bigIntArray.push(BigInt(byte));
  }

  return bigIntArray;
}
