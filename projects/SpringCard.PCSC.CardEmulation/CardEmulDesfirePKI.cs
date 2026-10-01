using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using SpringCard.LibCs;
using System;
using System.Collections.Generic;
using System.Text;
using System.Xml;

namespace SpringCard.PCSC.CardEmulation
{
    public partial class CardEmulDesfire
    {
        public class DesfireCARootKey
        {
            private DesfireCARootKey() { } /* Make sure the object can't be instancied manually */


            public byte CurveId { get; private set; }

            private string CurveName
            {
                get
                {
                    return DesfireECCKeyPair.GetCurveName(CurveId);
                }
            }

            public ECPublicKeyParameters PublicKey { get; private set; }

            public byte[] PublicKeyValue
            { 
                get
                {
                    return PublicKey.Q.GetEncoded(false);
                }            
            }

            public byte[] Issuer { get; private set; }

            public ushort AccessRights { get; private set; }
            public byte WriteCommMode { get; private set; }
            public byte WriteAccessCondition { get; private set; }

            public byte ReadCommMode { get; private set; }
            public byte ReadAccessCondition { get; private set; }

            public byte CrlFileId { get; private set; }
            public uint CrlFileAid { get; private set; }

            public static DesfireCARootKey Create(byte CurveId, ushort AccessRights, byte WriteAccess, byte ReadAccess, byte CrlFileId, uint CrlFileAid, byte[] PublicKeyValue, byte[] Issuer)
            {
                DesfireCARootKey result = new DesfireCARootKey();

                result.CurveId = CurveId;
                result.AccessRights = AccessRights;
                result.WriteCommMode = (byte)((WriteAccess >> 4) & 0x03);
                result.WriteAccessCondition = (byte)(WriteAccess & 0x0F);
                result.ReadCommMode = (byte)((ReadAccess >> 4) & 0x03);
                result.ReadAccessCondition = (byte)(ReadAccess & 0x0F);
                result.CrlFileId = CrlFileId;
                result.CrlFileAid = CrlFileAid;
                result.Issuer = Issuer;

                string curveName = result.CurveName;
                if (curveName == null)
                    return null;

                if ((PublicKeyValue == null) || (PublicKeyValue.Length != 65) || (PublicKeyValue[0] != 0x04))
                    return null;

                X9ECParameters curve = SecNamedCurves.GetByName(curveName);
                if (curve == null)
                    return null;

                ECDomainParameters curveSpec = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());
                Org.BouncyCastle.Math.EC.ECPoint curvePoint = curve.Curve.DecodePoint(PublicKeyValue);
                result.PublicKey = new ECPublicKeyParameters("ECDSA", curvePoint, curveSpec);

                return result;
            }
        }

    }
}