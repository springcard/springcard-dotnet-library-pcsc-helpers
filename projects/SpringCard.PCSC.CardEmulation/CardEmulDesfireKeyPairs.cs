using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using SpringCard.LibCs;
using SpringCard.LibCs.Crypto;
using System;
using System.Collections.Generic;
using System.Net.NetworkInformation;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using System.Xml.XPath;

namespace SpringCard.PCSC.CardEmulation
{
    public partial class CardEmulDesfire
    {
        public class DesfireECCKeyPair
        {
            private DesfireECCKeyPair() { } /* Make sure the object can't be instancied manually */

            public static string GetCurveName(byte CurveId)
            {
                switch (CurveId)
                {
                    case 0x0C:
                        return "secp256r1";

                    case 0x0D:
                        return "brainpoolP256r1";

                    default:
                        return null;
                }
            }

            private string CurveName
            {
                get
                {
                    return GetCurveName(CurveId);
                }
            }


            public byte CurveId { get; private set; }

            internal ECPrivateKeyParameters PrivateKey { get; private set; }

            public ECPublicKeyParameters PublicKey
            {
                get
                {
                    string curveName = CurveName;
                    if (curveName == null)
                        return null;

                    X9ECParameters curve = SecNamedCurves.GetByName(curveName);
                    if (curve == null)
                        return null;

                    ECDomainParameters curveSpec = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());
                    Org.BouncyCastle.Math.EC.ECPoint curvePoint = curve.G.Multiply(PrivateKey.D);
                    return new ECPublicKeyParameters("ECDSA", curvePoint, curveSpec);
                }
            }

            public byte[] PublicKeyValue
            {
                get
                {
                    return PublicKey.Q.GetEncoded(false);
                }
            }

            private bool Generate()
            {
                string curveName = CurveName;
                if (curveName == null)
                    return false;

                X9ECParameters curve = SecNamedCurves.GetByName(curveName);
                if (curve == null)
                    return false;

                ECDomainParameters domainParameters = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);
                ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();
                keyPairGenerator.Init(new ECKeyGenerationParameters(domainParameters, new SecureRandom()));

                AsymmetricCipherKeyPair keyPair = keyPairGenerator.GenerateKeyPair();

                PrivateKey = (ECPrivateKeyParameters)keyPair.Private;

                return true;
            }

            private bool Import(byte[] PrivateKeyValue)
            {
                if ((PrivateKeyValue[0] & 0x80) != 0)
                    PrivateKeyValue = BinUtils.Concat(0x00, PrivateKeyValue); /* Make sure the private key is a positive number */

                string curveName = CurveName;
                if (curveName == null)
                    return false;

                X9ECParameters curve = SecNamedCurves.GetByName(curveName);
                if (curve == null)
                    return false;

                ECDomainParameters curveSpec = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());
                PrivateKey = new ECPrivateKeyParameters("ECDSA", new BigInteger(PrivateKeyValue), curveSpec);

                return true;
            }

            public bool FreezeKUCLimit { get; private set; }
            public bool InternalAuthenticate { get; private set; }
            public bool GeneralAuthenticate { get; private set; }
            public bool TransactionSignature { get; private set; }
            public bool SecureDynamicMessaging { get; private set; }
            public bool DigitalSignature { get; private set; }

            public byte CommMode { get; private set; }
            public byte AccessCondition { get; private set; }

            public uint KUCLimit;
            public uint KUCValue;

            public bool UpdateMetaData(byte CurveId, ushort KeyPolicy, byte WriteAccess, uint KUCLimit)
            {
                if (CurveId != this.CurveId)
                    return false;
                if (!FreezeKUCLimit)
                    this.KUCLimit = KUCLimit;

                FreezeKUCLimit = ((KeyPolicy & 0x8000) != 0) ? true : false;
                InternalAuthenticate = ((KeyPolicy & 0x0100) != 0) ? true : false;
                GeneralAuthenticate = ((KeyPolicy & 0x0080) != 0) ? true : false;
                TransactionSignature = ((KeyPolicy & 0x0040) != 0) ? true : false;
                SecureDynamicMessaging = ((KeyPolicy & 0x0020) != 0) ? true : false;
                DigitalSignature = ((KeyPolicy & 0x0010) != 0) ? true : false;

                CommMode = (byte)((WriteAccess >> 4) & 0x03);
                AccessCondition = (byte)(WriteAccess & 0x0F);

                return true;
            }

            public static DesfireECCKeyPair Generate(byte CurveId, ushort KeyPolicy, byte WriteAccess, uint KUCLimit)
            {
                DesfireECCKeyPair result = new DesfireECCKeyPair();

                result.CurveId = CurveId;
                if (!result.UpdateMetaData(CurveId, KeyPolicy, WriteAccess, KUCLimit))
                    return null;

                if (!result.Generate())
                    return null;

                return result;
            }

            public static DesfireECCKeyPair Import(byte CurveId, ushort KeyPolicy, byte WriteAccess, uint KUCLimit, byte[] PrivateKey)
            {
                DesfireECCKeyPair result = new DesfireECCKeyPair();

                result.CurveId = CurveId;
                if (!result.UpdateMetaData(CurveId, KeyPolicy, WriteAccess, KUCLimit))
                    return null;

                if (!result.Import(PrivateKey))
                    return null;

                return result;
            }
        }
    }
}