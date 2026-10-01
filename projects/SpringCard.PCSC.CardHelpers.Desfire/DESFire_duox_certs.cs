/*
 * SpringCard DESFire Library (C#)
 * Copyright (c) SpringCard SAS, 2008-2025
 *
 * This file is part of the SpringCard DESFire library.
 * See LICENSE.txt for license details and restrictions.
 *
 */
using System;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using SpringCard.LibCs;
using System.Security.Cryptography.X509Certificates;
using SpringCard.LibCs.Crypto;

namespace SpringCard.PCSC.CardHelpers
{
    public partial class Desfire
    {
        #region X509 Wrappers

        public static class X509CERT
        {
            public static byte[] Chain(byte[] parentCertificate, byte[] leafCertificate)
            {
                return BinUtils.Concat(parentCertificate, leafCertificate);
            }

            public static byte[] AddDataFilePrefix(byte[] buffer)
            {
                uint length = (uint)buffer.Length;
                byte[] header = new byte[3];
                header[0] = (byte)length;
                header[1] = (byte)(length >> 8);
                header[2] = (byte)(length >> 16);
                return BinUtils.Concat(header, buffer);
            }

            public static bool GetPublicKey(byte[] buffer, out byte[] PublicKey)
            {
                PublicKey = null;
                if (!GetPublicKey(buffer, out ECPublicKeyParameters ecPublicKey))
                    return false;
                return ECC.GetPublicBytes(ecPublicKey, out PublicKey);
            }

            public static bool GetPublicKey(byte[] buffer, out ECPublicKeyParameters ecPublicKey)
            {
                ecPublicKey = null;
                if (!Import(buffer, out Org.BouncyCastle.X509.X509Certificate x509certificate))
                    return false;
                AsymmetricKeyParameter result = x509certificate.GetPublicKey();
                if (result is ECPublicKeyParameters)
                    ecPublicKey = (ECPublicKeyParameters)result;
                return true;
            }

            public static bool Verify(byte[] buffer, byte CurveId, byte[] IssuerPublicKeyValue)
            {
                return Verify(buffer, (MifareDuoXEccCurve)CurveId, IssuerPublicKeyValue);
            }

            public static bool Verify(byte[] buffer, MifareDuoXEccCurve CurveId, byte[] IssuerPublicKeyValue)
            {
                ECC.ImportPublic(CurveId, IssuerPublicKeyValue, out ECPublicKeyParameters ecIssuerPublicKey);
                return Verify(buffer, ecIssuerPublicKey);
            }

            public static bool Verify(byte[] buffer, ECPublicKeyParameters IssuerPublicKey)
            {
                if (!Import(buffer, out Org.BouncyCastle.X509.X509Certificate x509certificate))
                    return false;
                return Verify(x509certificate, IssuerPublicKey);
            }

            public static bool Verify(Org.BouncyCastle.X509.X509Certificate x509certificate, ECPublicKeyParameters IssuerPublicKey)
            {
                try
                {
                    x509certificate.Verify(IssuerPublicKey);
                    return true;
                }
                catch (Exception ex)
                {
                    Logger.Error(ex.Message);
                    return false;
                }
            }

            public static bool Verify(System.Security.Cryptography.X509Certificates.X509Certificate x509certificate, byte CurveId, byte[] IssuerPublicKeyValue)
            {
                byte[] buffer = x509certificate.GetRawCertData();
                return Verify(buffer, CurveId, IssuerPublicKeyValue);
            }

            public static bool Verify(System.Security.Cryptography.X509Certificates.X509Certificate x509certificate, MifareDuoXEccCurve CurveId, byte[] IssuerPublicKeyValue)
            {
                byte[] buffer = x509certificate.GetRawCertData();
                return Verify(buffer, CurveId, IssuerPublicKeyValue);
            }

            public static bool Import(byte[] buffer, out Org.BouncyCastle.X509.X509Certificate x509certificate)
            {                
                try
                {
                    x509certificate = new Org.BouncyCastle.X509.X509Certificate(buffer);
                    return true;
                }
                catch (Exception ex)
                {
                    Logger.Error(ex.Message);
                    x509certificate = null;
                    return false;
                }
            }

            public static bool Import(byte[] buffer, out System.Security.Cryptography.X509Certificates.X509Certificate x509certificate)
            {
                x509certificate = null;
                if (!Import(buffer, out Org.BouncyCastle.X509.X509Certificate t))
                    return false;
                x509certificate = new System.Security.Cryptography.X509Certificates.X509Certificate(t.GetEncoded());
                return true;
            }

            public static byte[] Create(byte CurveId, string SubjectName, byte[] SubjectPublicKeyValue, string IssuerName, byte[] IssuerPrivateKeyValue)
            {
                return Create((MifareDuoXEccCurve)CurveId, SubjectName, SubjectPublicKeyValue, IssuerName, IssuerPrivateKeyValue);
            }

            public static byte[] Create(MifareDuoXEccCurve CurveId, string SubjectName, byte[] SubjectPublicKeyValue, string IssuerName, byte[] IssuerPrivateKeyValue)
            {
                ECC.ImportPublic(CurveId, SubjectPublicKeyValue, out ECPublicKeyParameters ecSubjectPublicKey);
                ECC.ImportPrivate(CurveId, IssuerPrivateKeyValue, out ECPrivateKeyParameters ecIssuerPrivateKey);
                return Create(CurveId, SubjectName, ecSubjectPublicKey, IssuerName, ecIssuerPrivateKey);
            }

            public static byte[] Create(MifareDuoXEccCurve CurveId, string SubjectName, ECPublicKeyParameters SubjectPublicKey, string IssuerName, ECPrivateKeyParameters IssuerPrivateKey)
            {
                /* We must create the certificate manually (NOT with BouncyCastle's certificate factory) because the Mifare DuoX card  */
                /* accepts only a (very) compressed form of the Public Key, with only the OID of the Curve and the compressed Q point, */
                /* where BouncyCastle puts all the Curve parameters in the Public Key sequence                                         */

                try
                {
                    DerObjectIdentifier curveOid = new DerObjectIdentifier(ECC.GetCurveOid(CurveId));

                    DerObjectIdentifier signatureAlgorithmOid = X9ObjectIdentifiers.ECDsaWithSha256;
                    AlgorithmIdentifier signatureAlgorithmIdentifier = new AlgorithmIdentifier(signatureAlgorithmOid);
                    DerObjectIdentifier uniqueIdentifierOid = new DerObjectIdentifier("2.5.4.45");

                    X509Name subjectName = new X509Name(new[] { uniqueIdentifierOid }, new[] { SubjectName });
                    X509Name issuerName = new X509Name(new[] { uniqueIdentifierOid }, new[] { IssuerName });

                    Time notBefore = new Time(DateTime.UtcNow.AddDays(-1));
                    Time notAfter = new Time(DateTime.UtcNow.AddYears(10).AddDays(1));

                    Org.BouncyCastle.Math.EC.ECPoint pubKeyPoint = SubjectPublicKey.Q.Normalize();
                    byte[] pubKeyEncoded = pubKeyPoint.GetEncoded(false);

                    /* Create a serial number on 32 bits, positive */
                    byte[] t = CRC32.Hash(BinUtils.Concat(StrUtils.ToBytes(SubjectName), StrUtils.ToBytes(IssuerName)));
                    t = CRC32.Hash(BinUtils.Concat(t, pubKeyEncoded));
                    DerInteger serialNumber = new DerInteger((int)(BinUtils.BytesToUInt32(t) & 0x7FFFFFFF));


                    AlgorithmIdentifier pubKeyAlgId = new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey, curveOid);
                    SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(pubKeyAlgId, pubKeyEncoded);

                    // X509ExtensionsGenerator extensionsGenerator = new X509ExtensionsGenerator();
                    // extensionsGenerator.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
                    // extensionsGenerator.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.KeyCertSign));

                    V3TbsCertificateGenerator certificateGenerator = new V3TbsCertificateGenerator();                    
                    certificateGenerator.SetSerialNumber(serialNumber);
                    certificateGenerator.SetSignature(signatureAlgorithmIdentifier);
                    certificateGenerator.SetIssuer(issuerName);
                    certificateGenerator.SetStartDate(notBefore);
                    certificateGenerator.SetEndDate(notAfter);
                    certificateGenerator.SetSubject(subjectName);
                    certificateGenerator.SetSubjectPublicKeyInfo(subjectPublicKeyInfo);

                    TbsCertificateStructure tbsCert = certificateGenerator.GenerateTbsCertificate();
                    byte[] tbsBytes = tbsCert.GetDerEncoded();

                    ISigner signer = SignerUtilities.GetSigner("SHA256withECDSA");
                    signer.Init(true, IssuerPrivateKey);
                    signer.BlockUpdate(tbsBytes, 0, tbsBytes.Length);
                    byte[] signature = signer.GenerateSignature();

                    X509CertificateStructure cert = new X509CertificateStructure(tbsCert, signatureAlgorithmIdentifier, new DerBitString(signature));

                    return cert.GetDerEncoded();
                }
                catch (Exception ex)
                {
                    Logger.Error(ex.Message);
                    return null;
                }
            }
        }

        #endregion
    }
}