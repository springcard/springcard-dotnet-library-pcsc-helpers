using System;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Agreement;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto.Parameters;
using SpringCard.LibCs;
using SpringCard.LibCs.Crypto;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Asn1.X9;

namespace SpringCard.PCSC.CardEmulation
{
    public partial class CardEmulMifareDuoX
    {
        public class MifareDuoXCipher : DesfireEV2Cipher
        {
            public MifareDuoXCipher(CardEmulDesfire Card, ECPublicKeyParameters EPubA, ECPublicKeyParameters EPubB, ECPrivateKeyParameters EPriB) : base(Card)
            {
                this.Card = Card;

                ECDHBasicAgreement agreement = new ECDHBasicAgreement();
                agreement.Init(EPriB);
                byte[] ShS = agreement.CalculateAgreement(EPubA).ToByteArray();
                if (ShS == null)
                    throw new Exception("ECDH failed");

                if (ShS.Length > 32)
                {
                    if (ShS[0] != 0x00)
                        throw new Exception("ECDH invalid");
                    ShS = BinUtils.Copy(ShS, 1, ShS.Length - 1);
                }

                Card.logger.debug("Shared secret: {0}", BinConvert.ToHex(ShS));

                byte[] cmacKey = BinUtils.Concat(BinUtils.Copy(EPubA.Q.GetEncoded(false), 1 + 32 - 8, 8), BinUtils.Copy(EPubB.Q.GetEncoded(false), 1 + 32 - 8, 8));

                Card.logger.debug("Cmac Key: {0}", BinConvert.ToHex(cmacKey));

                SessionCmacKey = cmacKey;
                InitCmac();

                ComputeCmacEx(ShS);
                byte[] KDK = BinUtils.Copy(InitVector);

                Card.logger.debug("KDK: {0}", BinConvert.ToHex(KDK));

                SessionCmacKey = KDK;
                InitCmac();

                byte[] SV1 = new byte[16];
                SV1[0] = 0xB4; SV1[1] = 0x4B; SV1[3] = 0x01; SV1[5] = 0x80;
                Card.logger.debug("SV1: {0}", BinConvert.ToHex(SV1));

                ResetInitVector();
                ComputeCmacEx(SV1);
                byte[] encKeyValue = BinUtils.Copy(InitVector);

                byte[] SV2 = new byte[16];
                SV2[0] = 0x4B; SV2[1] = 0xB4; SV2[3] = 0x01; SV2[5] = 0x80;
                Card.logger.debug("SV2: {0}", BinConvert.ToHex(SV2));

                ResetInitVector();
                ComputeCmacEx(SV2);
                byte[] cmacKeyValue = BinUtils.Copy(InitVector);

                Card.logger.debug("ENC: {0}", BinConvert.ToHex(encKeyValue));
                Card.logger.debug("MAC: {0}", BinConvert.ToHex(cmacKeyValue));

                SessionEncKey = encKeyValue;
                SessionCmacKey = cmacKeyValue;
                InitCmac();

                TransactionIdentifier = new byte[4];
            }

            public static bool Verify(ECPublicKeyParameters ecPublicKey, byte[] Message, byte[] Signature)
            {
                ISigner ecdsaSign = SignerUtilities.GetSigner("SHA256withECDSA");

                ecdsaSign.Init(false, ecPublicKey);

                ecdsaSign.BlockUpdate(Message, 0, Message.Length);

                byte[] der = null;

                /* Retrieve both numbers and make sure can be interpreted correctly as positive integers */
                byte[] R = BinUtils.Copy(Signature, 0, 32);
                if ((R[0] & 0x80) != 0)
                {
                    R = BinUtils.Concat(0, R);
                }
                else if ((R[0] == 0) && ((R[1] & 0x80) == 0))
                {
                    R = BinUtils.Copy(R, 1, 31);
                }
                byte[] S = BinUtils.Copy(Signature, 32, 32);
                if ((S[0] & 0x80) != 0)
                {
                    S = BinUtils.Concat(0, S);
                }
                else if ((S[0] == 0) && ((S[1] & 0x80) == 0))
                {
                    S = BinUtils.Copy(S, 1, 31);
                }

                /* Assemble the result */
                der = new byte[0];

                /* ASN.1 header */
                der = BinUtils.Concat(der, 0x30);
                der = BinUtils.Concat(der, (byte)(1 + 1 + R.Length + 1 + 1 + S.Length));

                /* R number */
                der = BinUtils.Concat(der, 0x02);
                der = BinUtils.Concat(der, (byte)R.Length);
                der = BinUtils.Concat(der, R);

                /* S number */
                der = BinUtils.Concat(der, 0x02);
                der = BinUtils.Concat(der, (byte)S.Length);
                der = BinUtils.Concat(der, S);

                if (!ecdsaSign.VerifySignature(der))
                    return false;

                return true;
            }

            public static byte[] Sign(ECPrivateKeyParameters ecPrivateKey, byte[] Message)
            {
                ISigner ecdsaSign = SignerUtilities.GetSigner("SHA256withECDSA");

                ecdsaSign.Init(true, ecPrivateKey);

                ecdsaSign.BlockUpdate(Message, 0, Message.Length);

                byte[] buffer = ecdsaSign.GenerateSignature();

                /* If msb is 1 (0x80) it considered as a negative number, to avoid that we add 0x00 byte inn the front */

                byte topLevelTag = buffer[0];
                byte topLevelLength = buffer[1];

                byte part1Tag = buffer[2];
                byte part1Length = buffer[3];
                byte[] part1Value = BinUtils.Copy(buffer, 4, part1Length);

                byte part2Tag = buffer[4 + part1Length];
                byte part2Length = buffer[5 + part1Length];
                byte[] part2Value = BinUtils.Copy(buffer, 6 + part1Length, part2Length);

                if ((part1Value[0] & 0x80) != 0) part1Value = BinUtils.Concat(0x00, part1Value);
                if ((part2Value[0] & 0x80) != 0) part2Value = BinUtils.Concat(0x00, part2Value);

                byte[] der = new byte[2 + 2 + part1Value.Length + 2 + part2Value.Length];

                der[0] = topLevelTag;
                der[1] = (byte)(2 + part1Value.Length + 2 + part2Value.Length);

                der[2] = part1Tag;
                der[3] = (byte)part1Value.Length;
                Array.Copy(part1Value, 0, der, 4, part1Value.Length);

                der[4 + part1Value.Length] = part2Tag;
                der[5 + part1Value.Length] = (byte)part2Value.Length;
                Array.Copy(part2Value, 0, der, 6 + part1Value.Length, part2Value.Length);

                int offset = 0;

                if (der == null)
                    return null;
                if (der.Length < 2)
                    return null;
                if (der[offset++] != 0x30)
                    return null;
                int length = der[offset++];
                if (der.Length != 2 + length)
                    return null;

                if (der[offset++] != 0x02)
                    return null;
                int R_length = der[offset++];
                if (R_length + offset > der.Length)
                    return null;

                byte[] R = BinUtils.Copy(der, offset, R_length);
                offset += R_length;

                while (R.Length < 32)
                    R = BinUtils.Concat(0x00, R);
                while (R.Length > 32)
                {
                    if (R[0] != 0x00)
                        return null;
                    R = BinUtils.Copy(R, 1, R.Length - 1);
                }

                if (der[offset++] != 0x02)
                    return null;
                int S_length = der[offset++];
                if (S_length + offset > der.Length)
                    return null;

                byte[] S = BinUtils.Copy(der, offset, S_length);
                offset += S_length;

                while (S.Length < 32)
                    S = BinUtils.Concat(0x00, S);
                while (S.Length > 32)
                {
                    if (S[0] != 0x00)
                        return null;
                    S = BinUtils.Copy(S, 1, S.Length - 1);
                }

                return BinUtils.Concat(R, S);
            }

        }
    }
}

