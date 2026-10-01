/*
 * SpringCard DESFire Library (C#)
 * Copyright (c) SpringCard SAS, 2008-2025
 *
 * This file is part of the SpringCard DESFire library.
 * See LICENSE.txt for license details and restrictions.
 *
 */
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using SpringCard.LibCs;
using System;


namespace SpringCard.PCSC.CardHelpers
{
    public partial class Desfire
    {
        #region ECC Wrappers

        public static class ECC
        {

            public static string GetCurveName(byte CurveId)
            {
                return GetCurveName((MifareDuoXEccCurve)CurveId);
            }

            public static string GetCurveOid(byte CurveId)
            {
                return GetCurveOid((MifareDuoXEccCurve)CurveId);
            }

            public static string GetCurveName(MifareDuoXEccCurve CurveId)
            {
                switch (CurveId)
                {
                    case MifareDuoXEccCurve.NistP256:
                        return "secp256r1";

                    case MifareDuoXEccCurve.BrainPoolP256R1:
                        return "brainpoolP256r1";

                    default:
                        return null;
                }
            }

            public static string GetCurveOid(MifareDuoXEccCurve CurveId)
            {
                switch (CurveId)
                {
                    case MifareDuoXEccCurve.NistP256:
                        return "1.2.840.10045.3.1.7";

                    case MifareDuoXEccCurve.BrainPoolP256R1:
                        return "1.3.36.3.3.2.8.1.1.7";

                    default:
                        return null;
                }
            }

            public static bool GenerateKeyPair(MifareDuoXEccCurve CurveId, out byte[] PrivateKey, out byte[] PublicKey)
            {
                PrivateKey = null;
                PublicKey = null;
                if (!GenerateKeyPair(CurveId, out ECPrivateKeyParameters ecPrivateKey, out ECPublicKeyParameters ecPublicKey))
                    return false;

                if (!GetPrivateBytes(CurveId, ecPrivateKey, out PrivateKey))
                    return false;
                if (!GetPublicBytes(ecPublicKey, out PublicKey))
                    return false;

                return true;
            }

            public static bool GenerateKeyPair(MifareDuoXEccCurve CurveId, out ECPrivateKeyParameters ecPrivateKey, out ECPublicKeyParameters ecPublicKey)
            {
                ecPrivateKey = null;
                ecPublicKey = null;

                string curveName = GetCurveName(CurveId);
                if (curveName == null)
                    return false;

                X9ECParameters curve = ECNamedCurveTable.GetByName(curveName);
                if (curve == null)
                    return false;

                ECDomainParameters domainParameters = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);
                ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();
                keyPairGenerator.Init(new ECKeyGenerationParameters(domainParameters, new SecureRandom()));

                AsymmetricCipherKeyPair keyPair = keyPairGenerator.GenerateKeyPair();

                ecPrivateKey = (ECPrivateKeyParameters)keyPair.Private;
                ecPublicKey = (ECPublicKeyParameters)keyPair.Public;

                return true;
            }

            public static bool Sign(MifareDuoXEccCurve CurveId, byte[] PrivateKey, byte[] Message, out byte[] Signature, bool RawNotPer = true)
            {
                Signature = null;

                if (!ImportPrivate(CurveId, PrivateKey, out ECPrivateKeyParameters privateKey))
                    return false;

                if (!Sign(CurveId, privateKey, Message, out Signature, RawNotPer))
                    return false;

                return true;
            }

            public static bool Sign(MifareDuoXEccCurve CurveId, ECPrivateKeyParameters ecPrivateKey, byte[] Message, out byte[] Signature, bool RawNotPer = true)
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

                Signature = new byte[2 + 2 + part1Value.Length + 2 + part2Value.Length];

                Signature[0] = topLevelTag;
                Signature[1] = (byte)(2 + part1Value.Length + 2 + part2Value.Length);

                Signature[2] = part1Tag;
                Signature[3] = (byte)part1Value.Length;
                Array.Copy(part1Value, 0, Signature, 4, part1Value.Length);

                Signature[4 + part1Value.Length] = part2Tag;
                Signature[5 + part1Value.Length] = (byte)part2Value.Length;
                Array.Copy(part2Value, 0, Signature, 6 + part1Value.Length, part2Value.Length);

                if (RawNotPer)
                {
                    if (!SignatureDERToRaw(Signature, out Signature))
                        return false;
                }

                return true;
            }

            public static bool ImportPrivate(MifareDuoXEccCurve CurveId, byte[] PrivateKey, out ECPrivateKeyParameters ecPrivateKey)
            {
                ecPrivateKey = null;

                if ((PrivateKey[0] & 0x80) != 0)
                    PrivateKey = BinUtils.Concat(0x00, PrivateKey); /* Make sure the private key is a positive number */

                string curveName = GetCurveName(CurveId);
                if (curveName == null)
                    return false;

                X9ECParameters curve = SecNamedCurves.GetByName(curveName);
                if (curve == null)
                    return false;

                ECDomainParameters curveSpec = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());
                ECPrivateKeyParameters result = new ECPrivateKeyParameters("ECDSA", new BigInteger(PrivateKey), curveSpec);

                if (result == null)
                    return false;

                ecPrivateKey = result;
                return true;
            }

            public static bool PrivateToPublic(MifareDuoXEccCurve CurveId, ECPrivateKeyParameters ecPrivateKey, out ECPublicKeyParameters ecPublicKey)
            {
                ecPublicKey = null;

                string curveName = GetCurveName(CurveId);
                if (curveName == null)
                    return false;

                X9ECParameters curve = SecNamedCurves.GetByName(curveName);
                if (curve == null)
                    return false;

                ECDomainParameters curveSpec = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());
                Org.BouncyCastle.Math.EC.ECPoint curvePoint = curve.G.Multiply(ecPrivateKey.D);
                ECPublicKeyParameters result = new ECPublicKeyParameters("ECDSA", curvePoint, curveSpec);
                if (result == null)
                    return false;

                ecPublicKey = result;
                return true;
            }

            public static bool PrivateToPublic(MifareDuoXEccCurve CurveId, ECPrivateKeyParameters ecPrivateKey, out byte[] PublicKey)
            {
                PublicKey = null;
                if (!PrivateToPublic(CurveId, ecPrivateKey, out ECPublicKeyParameters publicKey))
                    return false;
                if (publicKey == null)
                    return false;
                if (!GetPublicBytes(publicKey, out PublicKey))
                    return false;
                return true;
            }

            public static bool PrivateToPublic(MifareDuoXEccCurve CurveId, byte[] PrivateKey, out byte[] PublicKey)
            {
                PublicKey = null;
                if (!ImportPrivate(CurveId, PrivateKey, out ECPrivateKeyParameters privateKey))
                    return false;
                if (!PrivateToPublic(CurveId, privateKey, out PublicKey))
                    return false;
                return true;
            }

            public static bool GetPublicBytes(ECPublicKeyParameters ecPublicKey, out byte[] PublicKey)
            {
                PublicKey = ecPublicKey.Q.GetEncoded(false);
                return true;
            }

            public static bool GetPrivateBytes(MifareDuoXEccCurve CurveId, ECPrivateKeyParameters ecPrivateKey, out byte[] PrivateKey)
            {
                PrivateKey = ecPrivateKey.D.ToByteArray();
                return true;
            }

            public static bool SignatureRawToDER(byte[] SignatureRaw, out byte[] SignatureDER)
            {
                SignatureDER = null;

                if (SignatureRaw == null)
                    return false;
                if (SignatureRaw.Length != 64)
                    return false;

                /* Retrieve both numbers and make sure can be interpreted correctly as positive integers */
                byte[] R = BinUtils.Copy(SignatureRaw, 0, 32);
                if ((R[0] & 0x80) != 0)
                {
                    R = BinUtils.Concat(0, R);
                }
                else if ((R[0] == 0) && ((R[1] & 0x80) == 0))
                {
                    R = BinUtils.Copy(R, 1, 31);
                }
                byte[] S = BinUtils.Copy(SignatureRaw, 32, 32);
                if ((S[0] & 0x80) != 0)
                {
                    S = BinUtils.Concat(0, S);
                }
                else if ((S[0] == 0) && ((S[1] & 0x80) == 0))
                {
                    S = BinUtils.Copy(S, 1, 31);
                }

                /* Assemble the result */
                SignatureDER = new byte[0];

                /* ASN.1 header */
                SignatureDER = BinUtils.Concat(SignatureDER, 0x30);
                SignatureDER = BinUtils.Concat(SignatureDER, (byte)(1 + 1 + R.Length + 1 + 1 + S.Length));

                /* R number */
                SignatureDER = BinUtils.Concat(SignatureDER, 0x02);
                SignatureDER = BinUtils.Concat(SignatureDER, (byte)R.Length);
                SignatureDER = BinUtils.Concat(SignatureDER, R);

                /* S number */
                SignatureDER = BinUtils.Concat(SignatureDER, 0x02);
                SignatureDER = BinUtils.Concat(SignatureDER, (byte)S.Length);
                SignatureDER = BinUtils.Concat(SignatureDER, S);

                return true;
            }

            public static bool SignatureDERToRaw(byte[] SignatureDER, out byte[] SignatureRaw)
            {
                SignatureRaw = null;

                int offset = 0;

                if (SignatureDER == null)
                    return false;
                if (SignatureDER.Length < 2)
                    return false;
                if (SignatureDER[offset++] != 0x30)
                    return false;
                int length = SignatureDER[offset++];
                if (SignatureDER.Length != 2 + length)
                    return false;

                if (SignatureDER[offset++] != 0x02)
                    return false;
                int R_length = SignatureDER[offset++];
                if (R_length + offset > SignatureDER.Length)
                    return false;

                byte[] R = BinUtils.Copy(SignatureDER, offset, R_length);
                offset += R_length;

                while (R.Length < 32)
                    R = BinUtils.Concat(0x00, R);
                while (R.Length > 32)
                {
                    if (R[0] != 0x00)
                        return false;
                    R = BinUtils.Copy(R, 1, R.Length - 1);
                }

                if (SignatureDER[offset++] != 0x02)
                    return false;
                int S_length = SignatureDER[offset++];
                if (S_length + offset > SignatureDER.Length)
                    return false;

                byte[] S = BinUtils.Copy(SignatureDER, offset, S_length);
                offset += S_length;

                while (S.Length < 32)
                    S = BinUtils.Concat(0x00, S);
                while (S.Length > 32)
                {
                    if (S[0] != 0x00)
                        return false;
                    S = BinUtils.Copy(S, 1, S.Length - 1);
                }

                SignatureRaw = BinUtils.Concat(R, S);
                return true;
            }

            public static bool Verify(MifareDuoXEccCurve CurveId, byte[] PiccPublicKey, byte[] Message, byte[] Signature)
            {
                if (!ImportPublic(CurveId, PiccPublicKey, out ECPublicKeyParameters publicKey))
                    return false;

                if (!Verify(CurveId, publicKey, Message, Signature))
                    return false;

                /* Success. */
                return true;
            }

            public static bool Verify(MifareDuoXEccCurve CurveId, ECPublicKeyParameters publicKey, byte[] Message, byte[] Signature)
            {
                ISigner ecdsaSign = SignerUtilities.GetSigner("SHA256withECDSA");

                ecdsaSign.Init(false, publicKey);

                ecdsaSign.BlockUpdate(Message, 0, Message.Length);

                if (Signature.Length == 64)
                    if (!SignatureRawToDER(Signature, out Signature))
                        return false;

                if (!ecdsaSign.VerifySignature(Signature))
                    return false;

                return true;
            }

            public static bool ImportPublic(MifareDuoXEccCurve CurveId, byte[] PublicKey, out ECPublicKeyParameters ecPublicKey)
            {
                ecPublicKey = null;

                string curveName = GetCurveName(CurveId);
                if (curveName == null)
                    return false;

                if ((PublicKey == null) || (PublicKey.Length != 65) || (PublicKey[0] != 0x04))
                    return false;

                X9ECParameters curve = SecNamedCurves.GetByName(curveName);
                if (curve == null)
                    return false;

                ECDomainParameters curveSpec = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());
                Org.BouncyCastle.Math.EC.ECPoint curvePoint = curve.Curve.DecodePoint(PublicKey);
                ecPublicKey = new ECPublicKeyParameters("ECDSA", curvePoint, curveSpec);
                if (ecPublicKey == null)
                    return false;

                return true;
            }

            public static bool Derive(MifareDuoXEccCurve CurveId, ECPrivateKeyParameters privateKey, ECPublicKeyParameters publicKey, out byte[] sharedSecret)
            {
                ECDHBasicAgreement agreement = new ECDHBasicAgreement();
                agreement.Init(privateKey);
                sharedSecret = agreement.CalculateAgreement(publicKey).ToByteArray();
                if (sharedSecret == null)
                    return false;

                if (sharedSecret.Length > 32)
                {
                    if (sharedSecret[0] != 0x00)
                        return false;
                    sharedSecret = BinUtils.Copy(sharedSecret, 1, sharedSecret.Length - 1);
                }

                return true;
            }
        }

        #endregion
    }
}


