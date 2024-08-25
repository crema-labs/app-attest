import { WitnessTester } from "circomkit";
import { circomkit } from "./common";
import { hexToBigInt, splitToWords, bufferToBigIntArray } from "../src";
import elliptic, { SignatureInput } from "elliptic";
import crypto from "crypto";

describe("Attestation", () => {
  const verifySig = (
    curve: string,
    hash: string,
    r: string,
    s: string,
    p_x: string,
    p_y: string,
    tbs: Buffer,
    id: string
  ) => {
    const ec = new elliptic.ec(curve);
    const key = ec.keyFromPublic({ x: p_x, y: p_y }, "hex");
    const hashMessage = crypto.createHash(hash).update(tbs).digest();

    const signature: SignatureInput = {
      r: r,
      s: s,
    };

    const isValid = key.verify(hashMessage, signature);

    console.log(id, "isValid:", isValid);
  };
  describe("VerifyCertChain", () => {
    let circuit: WitnessTester<["r", "s", "TBSData", "PubKeys"], ["out"]>;

    const MAX_CERT_CHAIN_LEN = 100;

    before(async () => {
      circuit = await circomkit.WitnessTester(`Add`, {
        file: "attestation",
        template: "VerifyCertChain",
        params: [MAX_CERT_CHAIN_LEN],
      });
      console.log("#constraints:", await circuit.getConstraintCount());
    });

    it("should verify correct certificate path", async () => {
      // generated from example from here https://developer.apple.com/documentation/devicecheck/attestation-object-validation-guide
      const r1 = "224e2f1e5a02eb80b21bbc64ea6102db0364e2116ff82af20710938ab1b864e75182ed02aef16e8f7cd0126b4b0d47b6";
      const s1 = "028b661e6c2cb2ce177c0301f586f2e022ba66323d80262cb48acf59e4e2c3624cfd04d517d0805618995ec2a76bda25";

      const r2 = "bbbe888d738d0502cfbcfd666d09575035bcd6872c3f8430492629edd1f914e879991c9ae8b5aef8d3a85433f7b60d06";
      const s2 = "ab38edd0cc81ed00a452c3ba44f993636553fecc297f2eb4df9f5ebe5a4acab6995c4b820df904386f7807bb589439b7";

      const r3 = "4201469c1cafb2255ba532b04a06b490fd1ef047834b8fac4264ef6fbbe7e773b9f8545781e2e1a49d3acac0b93eb3b2";
      const s3 = "a79538c43804825945ec49f755c13789ec5966d29e627a6ab628d5a3216b696548c9dfdd81a9e6addb82d5b993046c03";

      const x1 = "ae5b37a0774d79b2358f40e7d1f22626f1c25fef17802deab3826a59874ff8d2ad1525789aa26604191248b63cb96706";
      const y1 = "9e98d363bd5e370fbfa08e329e8073a985e7746ea359a2f66f29db32af455e211658d567af9e267eb2614dc21a66ce99";

      const x2 = "4531e198b5b4ec04da1502045704ed4f877272d76135b26116cfc88b615d0a000719ba69858dfe77caa3b839e020ddd6";
      const y2 = "56141404702831e43f70b88fd6c394b608ea2bd6ae61e9f598c12f46af52937266e57f14eb61fec530f7144f53812e35";

      const tbs1 = Buffer.from(
        "30820339a0030201020206018ef1fd4d4a300a06082a8648ce3d040302304f3123302106035504030c1a4170706c6520417070204174746573746174696f6e204341203131133011060355040a0c0a4170706c6520496e632e3113301106035504080c0a43616c69666f726e6961301e170d3234303431373136313435335a170d3234303432303136313435335a3081913149304706035504030c4036643261633438343566313332333332326635393233663062643964323264626535306530366237623830313231666365326232623565363665396539386436311a3018060355040b0c114141412043657274696669636174696f6e31133011060355040a0c0a4170706c6520496e632e3113301106035504080c0a43616c69666f726e69613059301306072a8648ce3d020106082a8648ce3d030107034200048c2e0cab6f9223970e7f5ab6e92fd7a4d6d621a60e548644bf19764ef1ef853611f6c2b6bb53b2bba2d3468197e4beab2c36cac0e4e24f41f35132c9475e5c24a38201bc308201b8300c0603551d130101ff04023000300e0603551d0f0101ff0404030204f030818806092a864886f763640805047b3079a40302010abf893003020101bf893103020100bf893203020101bf893303020101bf8934290427303335323138373339312e636f6d2e6170706c652e6578616d706c655f6170705f617474657374a5060404736b7320bf893603020105bf893703020100bf893903020100bf893a03020100bf893b030201003081d706092a864886f7636408070481c93081c6bf8a7806040431382e30bf885007020500ffffffffbf8a7b09040732324132343462bf8a7c06040431382e30bf8a7d06040431382e30bf8a7e03020100bf8a7f03020100bf8b0003020100bf8b0103020100bf8b0203020100bf8b0303020100bf8b0403020101bf8b0503020100bf8b0a10040e32322e312e3234342e302e322c30bf8b0b10040e32322e312e3234342e302e322c30bf8b0c10040e32322e312e3234342e302e322c30bf88020a04086970686f6e656f73bf88050a0408496e7465726e616c303306092a864886f76364080204263024a1220420fb6d162a717ecab1778900506fa94d67ee0c1dc3d45b12cdde81befc56e5b7eb",
        "hex"
      );
      const tbs2 = Buffer.from(
        "308201c8a003020102021009bac5e1bc401ad9d45395bc381a0854300a06082a8648ce3d04030330523126302406035504030c1d4170706c6520417070204174746573746174696f6e20526f6f7420434131133011060355040a0c0a4170706c6520496e632e3113301106035504080c0a43616c69666f726e6961301e170d3230303331383138333935355a170d3330303331333030303030305a304f3123302106035504030c1a4170706c6520417070204174746573746174696f6e204341203131133011060355040a0c0a4170706c6520496e632e3113301106035504080c0a43616c69666f726e69613076301006072a8648ce3d020106052b8104002203620004ae5b37a0774d79b2358f40e7d1f22626f1c25fef17802deab3826a59874ff8d2ad1525789aa26604191248b63cb967069e98d363bd5e370fbfa08e329e8073a985e7746ea359a2f66f29db32af455e211658d567af9e267eb2614dc21a66ce99a366306430120603551d130101ff040830060101ff020100301f0603551d23041830168014ac91105333bdbe6841ffa70ca9e5faeae5e58aa1301d0603551d0e041604143ee35d1c0419a9c9b431f88474d6e1e15772e39b300e0603551d0f0101ff040403020106",
        "hex"
      );
      const tbs3 = Buffer.from(
        "308201a7a00302010202100bf3be0ef1cdd2e0fb8c6e721f621798300a06082a8648ce3d04030330523126302406035504030c1d4170706c6520417070204174746573746174696f6e20526f6f7420434131133011060355040a0c0a4170706c6520496e632e3113301106035504080c0a43616c69666f726e6961301e170d3230303331383138333235335a170d3435303331353030303030305a30523126302406035504030c1d4170706c6520417070204174746573746174696f6e20526f6f7420434131133011060355040a0c0a4170706c6520496e632e3113301106035504080c0a43616c69666f726e69613076301006072a8648ce3d020106052b81040022036200044531e198b5b4ec04da1502045704ed4f877272d76135b26116cfc88b615d0a000719ba69858dfe77caa3b839e020ddd656141404702831e43f70b88fd6c394b608ea2bd6ae61e9f598c12f46af52937266e57f14eb61fec530f7144f53812e35a3423040300f0603551d130101ff040530030101ff301d0603551d0e04160414ac91105333bdbe6841ffa70ca9e5faeae5e58aa1300e0603551d0f0101ff040403020106",
        "hex"
      );

      const r = [
        splitToWords(hexToBigInt(r1), 48n, 8n),
        splitToWords(hexToBigInt(r2), 48n, 8n),
        splitToWords(hexToBigInt(r3), 48n, 8n),
      ];
      const s = [
        splitToWords(hexToBigInt(s1), 48n, 8n),
        splitToWords(hexToBigInt(s2), 48n, 8n),
        splitToWords(hexToBigInt(s3), 48n, 8n),
      ];

      const PubKeys = [
        [splitToWords(hexToBigInt(x1), 48n, 8n), splitToWords(hexToBigInt(y1), 48n, 8n)],
        [splitToWords(hexToBigInt(x2), 48n, 8n), splitToWords(hexToBigInt(y2), 48n, 8n)],
        [splitToWords(hexToBigInt(x2), 48n, 8n), splitToWords(hexToBigInt(y2), 48n, 8n)],
      ];

      const TBSData = [bufferToBigIntArray(tbs1), bufferToBigIntArray(tbs2), bufferToBigIntArray(tbs3)];

      verifySig("p384", "sha256", r1, s1, x1, y1, tbs1, "cert 1");
      verifySig("p384", "sha384", r2, s2, x2, y2, tbs2, "cert 2");
      verifySig("p384", "sha384", r3, s3, x2, y2, tbs3, "cert 3");

      circuit.expectPass(
        {
          r,
          s,
          TBSData,
          PubKeys,
        },
        { out: 3n }
      );
    });
  });
});
