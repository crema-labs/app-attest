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
      params: [4, 8],
    });
    console.log("#constraints:", await circuit.getConstraintCount());
  });

  it("should pad bits correctly", async () => {
    const inputBits = [1, 0, 1, 1];
    const expectedOutput = [1, 0, 1, 1, 0, 0, 0, 0];
    await circuit.expectPass({ in: inputBits }, { out: expectedOutput });
  });
});

function byteToBits(byte: number): number[] {
  let bits = [];
  for (let i = 7; i >= 0; i--) {
    bits.push((byte >> i) & 1);
  }
  return bits.reverse();
}

describe("BytesToBits", () => {
  let circuit: WitnessTester<["in"], ["out"]>;
  const testBytes = [0xa5, 0x53, 0x21, 0x12];

  before(async () => {
    circuit = await circomkit.WitnessTester(`BytesToBits`, {
      file: "utils",
      template: "BytesToBits",
      params: [testBytes.length],
    });
    console.log("#constraints:", await circuit.getConstraintCount());
  });

  it("should convert bytes to bits", async () => {
    const expectedBits = testBytes.map((byte) => byteToBits(byte)).flat();
    await circuit.expectPass({ in: testBytes }, { out: expectedBits });
  });
});
