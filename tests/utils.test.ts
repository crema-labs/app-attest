import { WitnessTester } from "circomkit";
import crypto from "crypto";
import { circomkit } from "./common";
import { hexToBigInt, splitToWords, bufferToBigIntBitArray } from "../src";
import { log } from "console";
describe("SplitToWords", () => {
  let circuit: WitnessTester<["in"], ["out"]>;

  before(async () => {
    circuit = await circomkit.WitnessTester(`SplitToWords`, {
      file: "attestation",
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
