import { WitnessTester } from "circomkit";
import crypto from "crypto";
import { circomkit } from "./common";
import { hexToBigInt, splitToWords, bufferToBigIntBitArray } from "../src";

describe("SplitToWords", () => {
  let circuit: WitnessTester<["in"], ["out"]>;

  before(async () => {
    circuit = await circomkit.WitnessTester(`SplitToWords`, {
      file: "utils",
      template: "SplitToWords",
      params: [384, 48, 8],
    });
    console.log("#constraints:", await circuit.getConstraintCount());
  });

  it("should parse Bit Stream to words", async () => {
    const msg = crypto.createHash("sha384").update("foo world").digest("hex");
    const words = splitToWords(hexToBigInt(msg), 48n, 8n);
    await circuit.expectPass(
      {
        in: bufferToBigIntBitArray(Buffer.from(msg, "hex")),
      },
      {
        out: words,
      }
    );
  });
});

describe("PadBits", () => {
  let circuit: WitnessTester<["in"], ["out"]>;

  before(async () => {
    circuit = await circomkit.WitnessTester(`PadBits`, {
      file: "utils",
      template: "PadBits",
      params: [6, 8],
    });
    console.log("#constraints:", await circuit.getConstraintCount());
  });

  it("should pad bits correctly", async () => {
    const inputBits = [1, 0, 1, 1, 0, 1];
    const expectedOutput = [0, 0, 1, 0, 1, 1, 0, 1];
    await circuit.expectPass({ in: inputBits }, { out: expectedOutput });
  });
});


function byteToBits(byte: number): number[] {
  let bits = [];
  for (let i = 7; i >= 0; i--) {
    bits.push((byte >> i) & 1);
  }
  return bits;
}

describe("BytesToBits", () => {
  let circuit: WitnessTester<["in"], ["out"]>;

  const sha384BytesDigest = [
    237, 100, 209, 7, 109, 211, 190, 176, 239, 60, 81, 47, 203, 179, 183, 52, 170, 110, 108, 58, 200, 31, 50, 225, 2,
    235, 178, 131, 102, 79, 129, 147, 34, 125, 222, 195, 183, 42, 75, 123, 153, 33, 60, 250, 207, 8, 238, 37,
  ];

  before(async () => {
    circuit = await circomkit.WitnessTester(`BytesToBits`, {
      file: "utils",
      template: "BytesToBits",
      params: [sha384BytesDigest.length],
    });
    console.log("#constraints:", await circuit.getConstraintCount());
  });

  it("should convert bytes to bits", async () => {
    const expectedBits = sha384BytesDigest.map((byte) => byteToBits(byte)).flat();
    await circuit.expectPass({ in: sha384BytesDigest }, { out: expectedBits });
  });
});
