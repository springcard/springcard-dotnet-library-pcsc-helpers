/*
 * SpringCard DESFire Library (C#)
 * Copyright (c) SpringCard SAS, 2008-2025
 *
 * This file is part of the SpringCard DESFire library.
 * See LICENSE.txt for license details and restrictions.
 *
 */
using System.Collections.Generic;
using Org.BouncyCastle.Crypto.Parameters;
using static SpringCard.PCSC.CardHelpers.Desfire;

namespace SpringCard.PCSC.CardHelpers
{
    public interface MifareDuoX
    {
        /**
         * \brief Get the list of private keys stored in the PICC
         *
         * \param PrivateKeyList List of private keys
         */
        long GetPrivateKeyList(out DesfirePrivateKeyInfo[] PrivateKeyList);

        /**
         * \brief Generate a new key pair
         *
         * \param KeyNumber Key number (0x00 to 0x1F)
         * \param CurveId Curve ID (see MifareDuoXEccCurve)
         * \param KeyPolicy Key policy (see MifareDuoXKeyPairPolicy)
         * \param WriteAccess Write access rights (see MifareDuoXAccessRights)
         * \param KucLimit Key usage control limit
         * \param PublicKey Public key (returned)
         */
        long GenerateKeyPair(byte KeyNumber, byte CurveId, ushort KeyPolicy, byte WriteAccess, ulong KucLimit, out byte[] PublicKey);

        /**
         * \brief Generate a new key pair
         *
         * \param KeyNumber Key number (0x00 to 0x1F)
         * \param CurveId Curve ID (see MifareDuoXEccCurve)
         * \param KeyPolicy Key policy (see MifareDuoXKeyPairPolicy)
         * \param WriteAccess Write access rights (see MifareDuoXAccessRights)
         * \param KucLimit Key usage control limit
         * \param PublicKey Public key (returned)
         */
        long GenerateKeyPair(byte KeyNumber, MifareDuoXEccCurve CurveId, MifareDuoXKeyPairPolicy KeyPolicy, MifareDuoXAccessRights WriteAccess, ulong KucLimit, out byte[] PublicKey);

        /**
         * \brief Generate a new key pair
         * 
         * \param KeyNumber Key number (0x00 to 0x1F)
         * \param CurveId Curve ID (see MifareDuoXEccCurve)
         * \param KeyPolicy Key policy (see MifareDuoXKeyPairPolicy)
         * \param WriteAccess Write access rights (see MifareDuoXAccessRights)
         * \param KucLimit Key usage control limit
         * \param PublicKey Public key (returned)
         */

        long GenerateKeyPair(byte KeyNumber, MifareDuoXEccCurve CurveId, MifareDuoXKeyPairPolicy KeyPolicy, MifareDuoXAccessRights WriteAccess, ulong KucLimit, out ECPublicKeyParameters PublicKey);

        /**
         * \brief Import a private key
         * 
         * \param KeyNumber Key number (0x00 to 0x1F)
         * \param CurveId Curve ID (see MifareDuoXEccCurve)
         * \param KeyPolicy Key policy (see MifareDuoXKeyPairPolicy)
         * \param WriteAccess Write access rights (see MifareDuoXAccessRights)
         * \param KucLimit Key usage control limit
         * \param PrivateKey Private key (32 bytes)
         */
        long ImportPrivateKey(byte KeyNumber, byte CurveId, ushort KeyPolicy, byte WriteAccess, ulong KucLimit, byte[] PrivateKey);

        /**
         * \brief Import a private key
         * 
         * \param KeyNumber Key number (0x00 to 0x1F)
         * \param CurveId Curve ID (see MifareDuoXEccCurve)
         * \param KeyPolicy Key policy (see MifareDuoXKeyPairPolicy)
         * \param WriteAccess Write access rights (see MifareDuoXAccessRights)
         * \param KucLimit Key usage control limit
         * \param PrivateKey Private key (32 bytes)
         */

        long ImportPrivateKey(byte KeyNumber, MifareDuoXEccCurve CurveId, MifareDuoXKeyPairPolicy KeyPolicy, MifareDuoXAccessRights WriteAccess, ulong KucLimit, byte[] PrivateKey);

        /**
         * \brief Import a private key
         * 
         * \param KeyNumber Key number (0x00 to 0x1F)
         * \param CurveId Curve ID (see MifareDuoXEccCurve)
         * \param KeyPolicy Key policy (see MifareDuoXKeyPairPolicy)
         * \param WriteAccess Write access rights (see MifareDuoXAccessRights)
         * \param KucLimit Key usage control limit
         * \param PrivateKey Private key
         */
        long ImportPrivateKey(byte KeyNumber, MifareDuoXEccCurve CurveId, MifareDuoXKeyPairPolicy KeyPolicy, MifareDuoXAccessRights WriteAccess, ulong KucLimit, ECPrivateKeyParameters PrivateKey);

        /**
         * \brief Update the metadata of a key pair
         * 
         * \param KeyNumber Key number (0x00 to 0x1F)
         * \param CurveId Curve ID (see MifareDuoXEccCurve)
         * \param KeyPolicy Key policy (see MifareDuoXKeyPairPolicy)
         * \param WriteAccess Write access rights (see MifareDuoXAccessRights)
         * \param KucLimit Key usage control limit
         */
        long UpdateKeyPairMetaData(byte KeyNumber, byte CurveId, ushort KeyPolicy, byte WriteAccess, ulong KucLimit);

        /**
         * \brief Manage a key pair (low level implementation of the card command)
         * 
         * \param KeyNumber Key number (0x00 to 0x1F)
         * \param Option 0x00=Generate, 0x01=Import, 0x02=Update
         * \param CurveId Curve ID (see MifareDuoXEccCurve)
         * \param KeyPolicy Key policy (see MifareDuoXKeyPairPolicy)
         * \param WriteAccess Write access rights (see MifareDuoXAccessRights)
         * \param KucLimit Key usage control limit
         * \param PrivateKey Private key (32 bytes)
         * \param PublicKey Public key (returned)
         */
        long ManageKeyPair(byte KeyNumber, byte Option, byte CurveId, ushort KeyPolicy, byte WriteAccess, ulong KucLimit, byte[] PrivateKey, out byte[] PublicKey);

        /**
         * \brief Manage a key pair (low level implementation of the card command)
         * 
         * \param KeyNumber Key number (0x00 to 0x1F)
         * \param Option 0x00=Generate, 0x01=Import, 0x02=Update
         * \param CurveId Curve ID (see MifareDuoXEccCurve)
         * \param KeyPolicy Key policy (see MifareDuoXKeyPairPolicy)
         * \param WriteAccess Write access rights (see MifareDuoXAccessRights)
         * \param KucLimit Key usage control limit
         * \param PrivateKey Private key (32 bytes)
         * \param PublicKey Public key (returned)
         */
        long ManageKeyPair(byte KeyNumber, byte Option, MifareDuoXEccCurve CurveId, MifareDuoXKeyPairPolicy KeyPolicy, MifareDuoXAccessRights WriteAccess, ulong KucLimit, byte[] PrivateKey, out byte[] PublicKey);

        /**
         * \brief Manage a key pair (low level implementation of the card command)
         * 
         * \param KeyNumber Key number (0x00 to 0x1F)
         * \param Option 0x00=Generate, 0x01=Import, 0x02=Update
         * \param CurveId Curve ID (see MifareDuoXEccCurve)
         * \param KeyPolicy Key policy (see MifareDuoXKeyPairPolicy)
         * \param WriteAccess Write access rights (see MifareDuoXAccessRights)
         * \param KucLimit Key usage control limit
         * \param PrivateKey Private key
         * \param PublicKey Public key (returned)
         */
        long ManageKeyPair(byte KeyNumber, byte Option, MifareDuoXEccCurve CurveId, MifareDuoXKeyPairPolicy KeyPolicy, MifareDuoXAccessRights WriteAccess, ulong KucLimit, ECPrivateKeyParameters PrivateKey, out ECPublicKeyParameters PublicKey);

        /*
         * \brief Manage the CA Root Key
         * 
         * Mode 1.A: high-level API, no CRL, no issuer
         */
        long ManageCARootKey(byte KeyNumber, MifareDuoXEccCurve CurveId, MifareDuoXCARootKeyAccessRights AccessRights, MifareDuoXAccessRights WriteAccess, MifareDuoXAccessRights ReadAccess, ECPublicKeyParameters PublicKey, DesfireCommMode CommMode);

        /*
         * \brief Manage the CA Root Key
         * 
         * Mode 1.B: high-level API, no CRL, no issuer
         */
        long ManageCARootKey(byte KeyNumber, MifareDuoXEccCurve CurveId, MifareDuoXCARootKeyAccessRights AccessRights, MifareDuoXAccessRights WriteAccess, MifareDuoXAccessRights ReadAccess, byte[] PublicKey, DesfireCommMode CommMode);

        /*
         * \brief Manage the CA Root Key
         * 
         * Mode 1.C: no CRL, no issuer
         */
        long ManageCARootKey(byte KeyNumber, byte CurveId, ushort AccessRights, byte WriteAccess, byte ReadAccess, byte[] PublicKey, byte CommMode);

        /*
         * \brief Manage the CA Root Key
         * 
         * Mode 2.A: high-level API, no CRL, with issuer
         */
        long ManageCARootKey(byte KeyNumber, MifareDuoXEccCurve CurveId, MifareDuoXCARootKeyAccessRights AccessRights, MifareDuoXAccessRights WriteAccess, MifareDuoXAccessRights ReadAccess, ECPublicKeyParameters PublicKey, byte[] Issuer, DesfireCommMode CommMode);

        /*
         * \brief Manage the CA Root Key
         * 
         * Mode 2.B: high-level API, no CRL, with issuer
         */
        long ManageCARootKey(byte KeyNumber, MifareDuoXEccCurve CurveId, MifareDuoXCARootKeyAccessRights AccessRights, MifareDuoXAccessRights WriteAccess, MifareDuoXAccessRights ReadAccess, byte[] PublicKey, byte[] Issuer, DesfireCommMode CommMode);

        /*
         * \brief Manage the CA Root Key
         * 
         * Mode 2.C: no CRL, with issuer
         */
        long ManageCARootKey(byte KeyNumber, byte CurveId, ushort AccessRights, byte WriteAccess, byte ReadAccess, byte[] PublicKey, byte[] Issuer, byte CommMode);

        /*
         * \brief Manage the CA Root Key
         * 
         * Version 3.A: high-level API, with CRL, no issuer
         */
        long ManageCARootKey(byte KeyNumber, MifareDuoXEccCurve CurveId, MifareDuoXCARootKeyAccessRights AccessRights, MifareDuoXAccessRights WriteAccess, MifareDuoXAccessRights ReadAccess, byte CrlFileId, uint CrlAid, ECPublicKeyParameters PublicKey, DesfireCommMode CommMode);

        /*
         * \brief Manage the CA Root Key
         * 
         * Version 3.B: high-level API, with CRL, no issuer
         */
        long ManageCARootKey(byte KeyNumber, MifareDuoXEccCurve CurveId, MifareDuoXCARootKeyAccessRights AccessRights, MifareDuoXAccessRights WriteAccess, MifareDuoXAccessRights ReadAccess, byte CrlFileId, uint CrlAid, byte[] PublicKey, DesfireCommMode CommMode);

        /*
         * \brief Manage the CA Root Key
         * 
         * Version 3.C: with CRL, no issuer
         */
        long ManageCARootKey(byte KeyNumber, byte CurveId, ushort AccessRights, byte WriteAccess, byte ReadAccess, byte CrlFileId, uint CrlAid, byte[] PublicKey, byte CommMode);

        /**
         * @brief Retrieves the public key of a CA Root Key
         *
         * @param KeyNumber The number of keys available.
         * @param CommMode The communication mode.
         * @param[out] PublicKey The public key.
         * @return A status code indicating the result of the operation.
         */
        long ReadCARootPublicKey(byte KeyNumber, byte CommMode, out byte[] PublicKey);

        /**
         * @brief Retrieves the public key of a CA Root Key
         *
         * @param KeyNumber The number of keys available.
         * @param CommMode The communication mode.
         * @param[out] PublicKey The public key.
         * @return A status code indicating the result of the operation.
         */
        long ReadCARootPublicKey(byte KeyNumber, DesfireCommMode CommMode, out byte[] PublicKey);

        /**
         * @brief Retrieves the public key of a CA Root Key
         *
         * @param KeyNumber The number of keys available.
         * @param CommMode The communication mode.
         * @param CurveId The ECC curve.
         * @param[out] PublicKey The public key.
         * @return A status code indicating the result of the operation.
         */
        long ReadCARootPublicKey(byte KeyNumber, DesfireCommMode CommMode, MifareDuoXEccCurve CurveId, out ECPublicKeyParameters PublicKey);

        /**
         * \brief Get the list of CA root keys known by the PICC
         *
         * \param CARootKeyList List of CA root keys
         */
        long GetCARootKeyList(out DesfireCARootKeyInfo[] CARootKeyList);

        /*
         * \brief ECC-based mutual authentication, with reader Certificate
         * 
         * \param Curve ECC curve to use
         * \param CARootKeyNo Key number of the (primary) targeted CA root key
         * \param PcdLTPriKey Long-term private key of the PCD
         * \param PcdCertificate Certificate of the PCD, corresponding to PcdLTPriKey
         * \param PrivateKeyNo Key number of the private key in the PICC
         * \param CertificateFileId File ID of the certificate in the PICC
         * \param PiccOptions Options returned by the PICC
         * \param PiccCertificate Certificated returned by the PICC (the function verifies that the Certificate actually authenticates the signature computed by the PICC, but the call shall verify that the Certificate is valid and authentic against its CA)
         */
        long IsoGeneralAuthenticateMutual(byte Curve, byte CARootKeyNo, byte[] PcdLTPriKey, byte[] PcdCertificate, byte PrivateKeyNo, byte CertificateFileId, out byte[] PiccOptions, out byte[] PiccCertificate);

        /*
         * \brief ECC-based mutual authentication, with reader Certificate
         * 
         * \param Curve ECC curve to use
         * \param CARootKeyNo Key number of the (primary) targeted CA root key
         * \param PcdLTPriKey Long-term private key of the PCD
         * \param PcdCertificate Certificate of the PCD, corresponding to PcdLTPriKey
         * \param PrivateKeyNo Key number of the private key in the PICC
         * \param CertificateFileId File ID of the certificate in the PICC
         * \param PiccOptions Options returned by the PICC
         * \param PiccCertificate Certificated returned by the PICC (the function verifies that the Certificate actually authenticates the signature computed by the PICC, but the call shall verify that the Certificate is valid and authentic against its CA)
         */
        long IsoGeneralAuthenticateMutual(MifareDuoXEccCurve Curve, byte CARootKeyNo, byte[] PcdLTPriKey, byte[] PcdCertificate, byte PrivateKeyNo, byte CertificateFileId, out byte[] PiccOptions, out byte[] PiccCertificate);

        /*
         * \brief ECC-based mutual authentication, with reader Certificate
         * 
         * \param Curve ECC curve to use
         * \param CARootKeyNo Key number of the (primary) targeted CA root key
         * \param SecCARootKeyNo If multiple application selection, Key number of the secondary targeted CA root key
         * \param PcdLTPriKey Long-term private key of the PCD
         * \param PcdCertificate Certificate of the PCD, corresponding to PcdLTPriKey
         * \param PrivateKeyNo Key number of the private key in the PICC
         * \param CertificateFileId File ID of the certificate in the PICC
         * \param PiccOptions Options returned by the PICC
         * \param PiccCertificate Certificated returned by the PICC (the function verifies that the Certificate actually authenticates the signature computed by the PICC, but the call shall verify that the Certificate is valid and authentic against its CA)
         */
        long IsoGeneralAuthenticateMutual(byte Curve, byte CARootKeyNo, byte SecCARootKeyNo, byte[] PcdLTPriKey, byte[] PcdCertificate, byte PrivateKeyNo, byte CertificateFileId, out byte[] PiccOptions, out byte[] PiccCertificate);

        /*
         * \brief ECC-based mutual authentication, with reader Certificate
         * 
         * \param Curve ECC curve to use
         * \param CARootKeyNo Key number of the (primary) targeted CA root key
         * \param SecCARootKeyNo If multiple application selection, Key number of the secondary targeted CA root key
         * \param PcdLTPriKey Long-term private key of the PCD
         * \param PcdCertificate Certificate of the PCD, corresponding to PcdLTPriKey
         * \param PrivateKeyNo Key number of the private key in the PICC
         * \param CertificateFileId File ID of the certificate in the PICC
         * \param PiccOptions Options returned by the PICC
         * \param PiccCertificate Certificated returned by the PICC (the function verifies that the Certificate actually authenticates the signature computed by the PICC, but the call shall verify that the Certificate is valid and authentic against its CA)
         */
        long IsoGeneralAuthenticateMutual(MifareDuoXEccCurve Curve, byte CARootKeyNo, byte SecCARootKeyNo, byte[] PcdLTPriKey, byte[] PcdCertificate, byte PrivateKeyNo, byte CertificateFileId, out byte[] PiccOptions, out byte[] PiccCertificate);

        /*
         * \brief ECC-based mutual authentication, with reader Certificate
         * 
         * \param Curve ECC curve to use
         * \param CARootKeyNo Key number of the (primary) targeted CA root key
         * \param SecCARootKeyNo If multiple application selection, Key number of the secondary targeted CA root key
         * \param PcdLTPriKey Long-term private key of the PCD
         * \param PcdCertificate Certificate of the PCD, corresponding to PcdLTPriKey
         * \param PrivateKeyNo Key number of the private key in the PICC
         * \param CertificateSAI Secondary Application Information for the certificate in the PICC
         * \param CertificateFileId File ID of the certificate in the PICC
         * \param PiccOptions Options returned by the PICC
         * \param PiccCertificate Certificated returned by the PICC (the function verifies that the Certificate actually authenticates the signature computed by the PICC, but the call shall verify that the Certificate is valid and authentic against its CA)
         */
        long IsoGeneralAuthenticateMutual(byte Curve, byte CARootKeyNo, byte SecCARootKeyNo, byte[] PcdLTPriKey, byte[] PcdCertificate, byte PrivateKeyNo, bool CertificateSAI, byte CertificateFileId, out byte[] PiccOptions, out byte[] PiccCertificate);

        /*
         * \brief ECC-based mutual authentication, with reader Certificate
         * 
         * \param Curve ECC curve to use
         * \param CARootKeyNo Key number of the (primary) targeted CA root key
         * \param SecCARootKeyNo If multiple application selection, Key number of the secondary targeted CA root key
         * \param PcdLTPriKey Long-term private key of the PCD
         * \param PcdCertificate Certificate of the PCD, corresponding to PcdLTPriKey
         * \param PrivateKeyNo Key number of the private key in the PICC
         * \param CertificateSAI Secondary Application Information for the certificate in the PICC
         * \param CertificateFileId File ID of the certificate in the PICC
         * \param PiccOptions Options returned by the PICC
         * \param PiccCertificate Certificated returned by the PICC (the function verifies that the Certificate actually authenticates the signature computed by the PICC, but the call shall verify that the Certificate is valid and authentic against its CA)
         */
        long IsoGeneralAuthenticateMutual(MifareDuoXEccCurve Curve, byte CARootKeyNo, byte SecCARootKeyNo, byte[] PcdLTPriKey, byte[] PcdCertificate, byte PrivateKeyNo, bool CertificateSAI, byte CertificateFileId, out byte[] PiccOptions, out byte[] PiccCertificate);

        /*
         * \brief ECC-based mutual authentication, without reader Certificate
         * 
         * \param Curve ECC curve to use
         * \param CARootKeyNo Key number of the (primary) targeted CA root key
         * \param PcdLTPriKey Long-term private key of the PCD
         * \param PrivateKeyNo Key number of the private key in the PICC
         * \param CertificateFileId File ID of the certificate in the PICC
         * \param PiccOptions Options returned by the PICC
         * \param PiccCertificate Certificated returned by the PICC (the function verifies that the Certificate actually authenticates the signature computed by the PICC, but the call shall verify that the Certificate is valid and authentic against its CA)
         */
        long IsoGeneralAuthenticateMutual(byte Curve, byte CARootKeyNo, byte[] PcdLTPriKey, byte PrivateKeyNo, byte CertificateFileId, out byte[] PiccOptions, out byte[] PiccCertificate);

        /*
         * \brief ECC-based mutual authentication, without reader Certificate
         * 
         * \param Curve ECC curve to use
         * \param CARootKeyNo Key number of the (primary) targeted CA root key
         * \param PcdLTPriKey Long-term private key of the PCD
         * \param PrivateKeyNo Key number of the private key in the PICC
         * \param CertificateFileId File ID of the certificate in the PICC
         * \param PiccOptions Options returned by the PICC
         * \param PiccCertificate Certificated returned by the PICC (the function verifies that the Certificate actually authenticates the signature computed by the PICC, but the call shall verify that the Certificate is valid and authentic against its CA)
         */
        long IsoGeneralAuthenticateMutual(MifareDuoXEccCurve Curve, byte CARootKeyNo, byte[] PcdLTPriKey, byte PrivateKeyNo, byte CertificateFileId, out byte[] PiccOptions, out byte[] PiccCertificate);

        /*
         * \brief ECC-based mutual authentication, with reader Certificate
         * 
         * \param Curve ECC curve to use
         * \param CARootKeyNo Key number of the (primary) targeted CA root key
         * \param SecCARootKeyNo If multiple application selection, Key number of the secondary targeted CA root key
         * \param PcdLTPriKey Long-term private key of the PCD
         * \param PrivateKeyNo Key number of the private key in the PICC
         * \param CertificateFileId File ID of the certificate in the PICC
         * \param PiccOptions Options returned by the PICC
         * \param PiccCertificate Certificated returned by the PICC (the function verifies that the Certificate actually authenticates the signature computed by the PICC, but the call shall verify that the Certificate is valid and authentic against its CA)
         */
        long IsoGeneralAuthenticateMutual(byte Curve, byte CARootKeyNo, byte SecCARootKeyNo, byte[] PcdLTPriKey, byte PrivateKeyNo, byte CertificateFileId, out byte[] PiccOptions, out byte[] PiccCertificate);

        /*
         * \brief ECC-based mutual authentication, with reader Certificate
         * 
         * \param Curve ECC curve to use
         * \param CARootKeyNo Key number of the (primary) targeted CA root key
         * \param SecCARootKeyNo If multiple application selection, Key number of the secondary targeted CA root key
         * \param PcdLTPriKey Long-term private key of the PCD
         * \param PrivateKeyNo Key number of the private key in the PICC
         * \param CertificateFileId File ID of the certificate in the PICC
         * \param PiccOptions Options returned by the PICC
         * \param PiccCertificate Certificated returned by the PICC (the function verifies that the Certificate actually authenticates the signature computed by the PICC, but the call shall verify that the Certificate is valid and authentic against its CA)
         */
        long IsoGeneralAuthenticateMutual(MifareDuoXEccCurve Curve, byte CARootKeyNo, byte SecCARootKeyNo, byte[] PcdLTPriKey, byte PrivateKeyNo, byte CertificateFileId, out byte[] PiccOptions, out byte[] PiccCertificate);

        /*
         * \brief ECC-based mutual authentication, with reader Certificate
         * 
         * \param Curve ECC curve to use
         * \param CARootKeyNo Key number of the (primary) targeted CA root key
         * \param SecCARootKeyNo If multiple application selection, Key number of the secondary targeted CA root key
         * \param PcdLTPriKey Long-term private key of the PCD
         * \param PrivateKeyNo Key number of the private key in the PICC
         * \param CertificateSAI Secondary Application Information for the certificate in the PICC
         * \param CertificateFileId File ID of the certificate in the PICC
         * \param PiccOptions Options returned by the PICC
         * \param PiccCertificate Certificated returned by the PICC (the function verifies that the Certificate actually authenticates the signature computed by the PICC, but the call shall verify that the Certificate is valid and authentic against its CA)
         */
        long IsoGeneralAuthenticateMutual(byte Curve, byte CARootKeyNo, byte SecCARootKeyNo, byte[] PcdLTPriKey, byte PrivateKeyNo, bool CertificateSAI, byte CertificateFileId, out byte[] PiccOptions, out byte[] PiccCertificate);

        /*
         * \brief ECC-based mutual authentication, with reader Certificate
         * 
         * \param Curve ECC curve to use
         * \param CARootKeyNo Key number of the (primary) targeted CA root key
         * \param SecCARootKeyNo If multiple application selection, Key number of the secondary targeted CA root key
         * \param PcdLTPriKey Long-term private key of the PCD
         * \param PrivateKeyNo Key number of the private key in the PICC
         * \param CertificateSAI Secondary Application Information for the certificate in the PICC
         * \param CertificateFileId File ID of the certificate in the PICC
         * \param PiccOptions Options returned by the PICC
         * \param PiccCertificate Certificated returned by the PICC (the function verifies that the Certificate actually authenticates the signature computed by the PICC, but the call shall verify that the Certificate is valid and authentic against its CA)
         */
        long IsoGeneralAuthenticateMutual(MifareDuoXEccCurve Curve, byte CARootKeyNo, byte SecCARootKeyNo, byte[] PcdLTPriKey, byte PrivateKeyNo, bool CertificateSAI, byte CertificateFileId, out byte[] PiccOptions, out byte[] PiccCertificate);

        /*
         * \brief ECC-based unilateral reader authentication, with reader Certificate
         * 
         * \param Curve ECC curve to use
         * \param CARootKeyNo Key number of the (primary) targeted CA root key
         * \param PcdLTPriKey Long-term private key of the PCD
         * \param PcdCertificate Certificate of the PCD, corresponding to PcdLTPriKey
         * \param PiccOptions Options returned by the PICC
         */
        long IsoGeneralAuthenticateReader(byte Curve, byte CARootKeyNo, byte[] PcdLTPriKey, byte[] PcdCertificate, out byte[] PiccOptions);

        /*
         * \brief ECC-based unilateral reader authentication, with reader Certificate
         * 
         * \param Curve ECC curve to use
         * \param CARootKeyNo Key number of the (primary) targeted CA root key
         * \param PcdLTPriKey Long-term private key of the PCD
         * \param PcdCertificate Certificate of the PCD, corresponding to PcdLTPriKey
         * \param PiccOptions Options returned by the PICC
         */
        long IsoGeneralAuthenticateReader(MifareDuoXEccCurve Curve, byte CARootKeyNo, byte[] PcdLTPriKey, byte[] PcdCertificate, out byte[] PiccOptions);

        /*
         * \brief ECC-based unilateral reader authentication, with reader Certificate
         * 
         * \param Curve ECC curve to use
         * \param CARootKeyNo Key number of the (primary) targeted CA root key
         * \param SecCARootKeyNo If multiple application selection, Key number of the secondary targeted CA root key
         * \param PcdLTPriKey Long-term private key of the PCD
         * \param PcdCertificate Certificate of the PCD, corresponding to PcdLTPriKey
         * \param PiccOptions Options returned by the PICC
         */
        long IsoGeneralAuthenticateReader(byte Curve, byte CARootKeyNo, byte SecCARootKeyNo, byte[] PcdLTPriKey, byte[] PcdCertificate, out byte[] PiccOptions);

        /*
         * \brief ECC-based unilateral reader authentication, with reader Certificate
         * 
         * \param Curve ECC curve to use
         * \param CARootKeyNo Key number of the (primary) targeted CA root key
         * \param SecCARootKeyNo If multiple application selection, Key number of the secondary targeted CA root key
         * \param PcdLTPriKey Long-term private key of the PCD
         * \param PcdCertificate Certificate of the PCD, corresponding to PcdLTPriKey
         * \param PiccOptions Options returned by the PICC
         */
        long IsoGeneralAuthenticateReader(MifareDuoXEccCurve Curve, byte CARootKeyNo, byte SecCARootKeyNo, byte[] PcdLTPriKey, byte[] PcdCertificate, out byte[] PiccOptions);

        /*
         * \brief ECC-based unilateral reader authentication, without reader Certificate
         * 
         * \param Curve ECC curve to use
         * \param CARootKeyNo Key number of the (primary) targeted CA root key
         * \param PcdLTPriKey Long-term private key of the PCD
         * \param PiccOptions Options returned by the PICC
         */
        long IsoGeneralAuthenticateReader(byte Curve, byte CARootKeyNo, byte[] PcdLTPriKey, out byte[] PiccOptions);

        /*
         * \brief ECC-based unilateral reader authentication, without reader Certificate
         * 
         * \param Curve ECC curve to use
         * \param CARootKeyNo Key number of the (primary) targeted CA root key
         * \param PcdLTPriKey Long-term private key of the PCD
         * \param PiccOptions Options returned by the PICC
         */
        long IsoGeneralAuthenticateReader(MifareDuoXEccCurve Curve, byte CARootKeyNo, byte[] PcdLTPriKey, out byte[] PiccOptions);

        /*
         * \brief ECC-based unilateral reader authentication, without reader Certificate
         * 
         * \param Curve ECC curve to use
         * \param CARootKeyNo Key number of the (primary) targeted CA root key
         * \param SecCARootKeyNo If multiple application selection, Key number of the secondary targeted CA root key
         * \param PcdLTPriKey Long-term private key of the PCD
         * \param PiccOptions Options returned by the PICC
         */
        long IsoGeneralAuthenticateReader(byte Curve, byte CARootKeyNo, byte SecCARootKeyNo, byte[] PcdLTPriKey, out byte[] PiccOptions);

        /*
         * \brief ECC-based unilateral reader authentication, without reader Certificate
         * 
         * \param Curve ECC curve to use
         * \param CARootKeyNo Key number of the (primary) targeted CA root key
         * \param SecCARootKeyNo If multiple application selection, Key number of the secondary targeted CA root key
         * \param PcdLTPriKey Long-term private key of the PCD
         * \param PiccOptions Options returned by the PICC
         */
        long IsoGeneralAuthenticateReader(MifareDuoXEccCurve Curve, byte CARootKeyNo, byte SecCARootKeyNo, byte[] PcdLTPriKey, out byte[] PiccOptions);

        /*
         * \brief ECC-based mutual or reader-unilateral authentication, Part 1
         * 
         * \param Curve ECC curve to use
         * \param P2 P2 parameter
         * \param PcdOptions Options for the PCD
         * \param PcdTempPubKey Ephemeral public key of the PCD
         * \param PiccTempPubKey Ephemeral public key of the PICC
         */
        long IsoGeneralAuthenticatePart1(MifareDuoXEccCurve Curve, byte P2, MifareDuoXGeneralAuthenticatePcdOptions PcdOptions, ECPublicKeyParameters ecPcdTempPubKey, out ECPublicKeyParameters ecPiccTempPubKey);

        /*
         * \brief ECC-based mutual or reader-unilateral authentication, Part 1
         * 
         * \param P2 P2 parameter
         * \param PcdOptions Options for the PCD
         * \param PcdTempPubKey Ephemeral public key of the PCD
         * \param PiccTempPubKey Ephemeral public key of the PICC
         */
        long IsoGeneralAuthenticatePart1(byte P2, byte[] PcdOptions, byte[] PcdTempPubKey, out byte[] PiccTempPubKey);

        /*
         * \brief ECC-based mutual or reader-unilateral authentication, Part 2
         * 
         * \param PcdMessage Encrypted and signed PCD Message
         * \param PiccMessage Encrypted and signed PICC Message (to be returned)
         */
        long IsoGeneralAuthenticatePart2(byte[] PcdMessage, out byte[] PiccMessage);

        /*
         * \brief ECC-based mutual or reader-unilateral authentication, session key generation and secure messaging
         * 
         * \param Curve ECC curve to use
         * \param PcdOptions Options for the PCD (sent to the PICC in IsoGeneralAuthenticatePart1)
         * \param PcdTempPriKey Ephemeral private key of the PCD (corresponding to the public key sent to the PICC in IsoGeneralAuthenticatePart1)
         * \param PiccTempPubKey Ephemeral public key of the PICC (retrieved from the PICC in response to IsoGeneralAuthenticatePart1)
         * \param PcdLTPriKey Long-term private key of the PCD (to compute the signature)
         * \param PcdCertificate Certificate of the PCD to be included in the PcdMessage
         * \param PcdMessage Encrypted and signed Message to be sent to the PICC in IsoGeneralAuthenticatePart2
         */
        long IsoGeneralAuthenticateInitSession(byte Curve, byte[] PcdOptions, byte[] PcdTempPriKey, byte[] PiccTempPubKey, byte[] PcdLTPriKey, byte[] PcdCertificate, out byte[] PcdMessage);

        /*
         * \brief ECC-based mutual or reader-unilateral authentication, session key generation and secure messaging
         * 
         * \param Curve ECC curve to use
         * \param PcdOptions Options for the PCD (sent to the PICC in IsoGeneralAuthenticatePart1)
         * \param PcdTempPriKey Ephemeral private key of the PCD (corresponding to the public key sent to the PICC in IsoGeneralAuthenticatePart1)
         * \param PiccTempPubKey Ephemeral public key of the PICC (retrieved from the PICC in response to IsoGeneralAuthenticatePart1)
         * \param PcdLTPriKey Long-term private key of the PCD (to compute the signature)
         * \param PcdCertificate Certificate of the PCD to be included in the PcdMessage
         * \param PcdMessage Encrypted and signed Message to be sent to the PICC in IsoGeneralAuthenticatePart2
         */
        long IsoGeneralAuthenticateInitSession(MifareDuoXEccCurve Curve, byte[] PcdOptions, byte[] PcdTempPriKey, byte[] PiccTempPubKey, byte[] PcdLTPriKey, byte[] PcdCertificate, out byte[] PcdMessage);

        /*
         * \brief ECC-based mutual or reader-unilateral authentication, session key generation and secure messaging
         * 
         * \param Curve ECC curve to use
         * \param PcdOptions Options for the PCD (sent to the PICC in IsoGeneralAuthenticatePart1)
         * \param PcdTempPriKey Ephemeral private key of the PCD (corresponding to the public key sent to the PICC in IsoGeneralAuthenticatePart1)
         * \param PiccTempPubKey Ephemeral public key of the PICC (retrieved from the PICC in response to IsoGeneralAuthenticatePart1)
         * \param PcdLTPriKey Long-term private key of the PCD (to compute the signature)
         * \param PcdCertificate Certificate of the PCD to be included in the PcdMessage
         * \param PcdMessage Encrypted and signed Message to be sent to the PICC in IsoGeneralAuthenticatePart2
         */
        long IsoGeneralAuthenticateInitSession(MifareDuoXEccCurve Curve, MifareDuoXGeneralAuthenticatePcdOptions PcdOptions, byte[] PcdTempPriKey, byte[] PiccTempPubKey, byte[] PcdLTPriKey, byte[] PcdCertificate, out byte[] PcdMessage);

        /*
         * \brief ECC-based mutual or reader-unilateral authentication, session key generation and secure messaging
         * 
         * \param Curve ECC curve to use
         * \param PcdOptions Options for the PCD (sent to the PICC in IsoGeneralAuthenticatePart1)
         * \param PcdTempPriKey Ephemeral private key of the PCD (corresponding to the public key sent to the PICC in IsoGeneralAuthenticatePart1)
         * \param PiccTempPubKey Ephemeral public key of the PICC (retrieved from the PICC in response to IsoGeneralAuthenticatePart1)
         * \param PcdLTPriKey Long-term private key of the PCD (to compute the signature)
         * \param PcdCertificate Certificate of the PCD to be included in the PcdMessage
         * \param PcdMessage Encrypted and signed Message to be sent to the PICC in IsoGeneralAuthenticatePart2
         */
        long IsoGeneralAuthenticateInitSession(MifareDuoXEccCurve Curve, MifareDuoXGeneralAuthenticatePcdOptions PcdOptions, ECPrivateKeyParameters ecPcdTempPriKey, ECPublicKeyParameters ecPiccTempPubKey, ECPrivateKeyParameters ecPcdLTPriKey, byte[] PcdCertificate, out byte[] PcdMessage);

        /*
         * \brief ECC-based mutual or reader-unilateral authentication, verification of the PICC response
         * 
         * \param Curve ECC curve to use
         * \param PcdOptions Options for the PCD (sent to the PICC in IsoGeneralAuthenticatePart1)
         * \param PcdTempPubKey Ephemeral public key of the PCD (sent to the PICC in IsoGeneralAuthenticatePart1)
         * \param PiccTempPubKey Ephemeral public key of the PICC (retrieved from the PICC in response to IsoGeneralAuthenticatePart1)
         * \param PiccLTPubKey Long-term public key of the PICC (to verify the signature) if already know; otherwise null
         * \param PiccMessage Encrypted and signed Message sent by the PICC in response to IsoGeneralAuthenticatePart2
         * \param PiccOptions Options of the PICC
         * \param PiccCertificate Certificate of the PICC (null if the PICC does not provide one)
         */
        long IsoGeneralAuthenticateConfirmSession(byte Curve, byte[] PcdTempPubKey, byte[] PiccTempPubKey, byte[] PiccLTPubKey, byte[] PiccMessage, out byte[] PiccOptions, out byte[] PiccCertificate);

        /*
         * \brief ECC-based mutual or reader-unilateral authentication, verification of the PICC response
         * 
         * \param Curve ECC curve to use
         * \param PcdOptions Options for the PCD (sent to the PICC in IsoGeneralAuthenticatePart1)
         * \param PcdTempPubKey Ephemeral public key of the PCD (sent to the PICC in IsoGeneralAuthenticatePart1)
         * \param PiccTempPubKey Ephemeral public key of the PICC (retrieved from the PICC in response to IsoGeneralAuthenticatePart1)
         * \param PiccLTPubKey Long-term public key of the PICC (to verify the signature) if already know; otherwise null
         * \param PiccMessage Encrypted and signed Message sent by the PICC in response to IsoGeneralAuthenticatePart2
         * \param PiccOptions Options of the PICC
         * \param PiccCertificate Certificate of the PICC (null if the PICC does not provide one)
         */
        long IsoGeneralAuthenticateConfirmSession(MifareDuoXEccCurve Curve, byte[] PcdTempPubKey, byte[] PiccTempPubKey, byte[] PiccLTPubKey, byte[] PiccMessage, out byte[] PiccOptions, out byte[] PiccCertificate);

        /*
         * \brief ECC-based mutual or reader-unilateral authentication, verification of the PICC response
         * 
         * \param Curve ECC curve to use
         * \param PcdOptions Options for the PCD (sent to the PICC in IsoGeneralAuthenticatePart1)
         * \param PcdTempPubKey Ephemeral public key of the PCD (sent to the PICC in IsoGeneralAuthenticatePart1)
         * \param PiccTempPubKey Ephemeral public key of the PICC (retrieved from the PICC in response to IsoGeneralAuthenticatePart1)
         * \param PiccLTPubKey Long-term public key of the PICC (to verify the signature) if already know; otherwise null
         * \param PiccMessage Encrypted and signed Message sent by the PICC in response to IsoGeneralAuthenticatePart2
         * \param PiccOptions Options of the PICC
         * \param PiccCertificate Certificate of the PICC (null if the PICC does not provide one)
         */
        long IsoGeneralAuthenticateConfirmSession(MifareDuoXEccCurve Curve, ECPublicKeyParameters ecPcdTempPubKey, ECPublicKeyParameters ecPiccTempPubKey, ECPublicKeyParameters ecPiccLTPubKey, byte[] PiccMessage, out byte[] PiccOptions, out byte[] PiccCertificate);

        /*
         * \brief ECC-based card authentication
         *
         * \param Curve ECC curve to use
         * \param PrivateKeyNo Private key number
         * \param PcdOptions Options to send to the PICC (can be null)
         * \param PiccLTPubKey Long term PICC public key, to be used to verify the PICC signature
         */
        long IsoInternalAuthenticate(byte Curve, byte PrivateKeyNo, byte[] PcdOptions, byte[] PiccLTPubKey);

        /*
         * \brief ECC-based card authentication
         *
         * \param Curve ECC curve to use
         * \param PrivateKeyNo Private key number
         * \param PcdOptions Options to send to the PICC (can be null)
         * \param PiccLTPubKey Long term PICC public key, to be used to verify the PICC signature
         */
        long IsoInternalAuthenticate(MifareDuoXEccCurve Curve, byte PrivateKeyNo, byte[] PcdOptions, byte[] PiccLTPubKey);

        /*
         * \brief ECC-based card authentication
         *
         * \param Curve ECC curve to use
         * \param PrivateKeyNo Private key number
         * \param PcdOptions Options to send to the PICC (can be null)
         * \param PiccLTPubKey Long term PICC public key, to be used to verify the PICC signature
         */
        long IsoInternalAuthenticate(MifareDuoXEccCurve Curve, byte PrivateKeyNo, byte[] PcdOptions, ECPublicKeyParameters ecPiccLTPubKey);

        /*
         * \brief ECC-based card authentication
         *
         * \param Curve ECC curve to use
         * \param PrivateKeyNo Private key number
         * \param PcdOptions Options to send to the PICC (can be null)
         * \param Challenge Complete challenge (F0F0 || OptA || RndB || RndA) to be verified
         * \param PiccSignature PICC signature to be verified
         */
        long IsoInternalAuthenticate(byte Curve, byte PrivateKeyNo, byte[] PcdOptions, out byte[] Challenge, out byte[] PiccSignature);

        /*
         * \brief ECC-based card authentication
         *
         * \param Curve ECC curve to use
         * \param PrivateKeyNo Private key number
         * \param PcdOptions Options to send to the PICC (can be null)
         * \param Challenge Complete challenge (F0F0 || OptA || RndB || RndA) to be verified
         * \param PiccSignature PICC signature to be verified
         */
        long IsoInternalAuthenticate(MifareDuoXEccCurve Curve, byte PrivateKeyNo, byte[] PcdOptions, out byte[] Challenge, out byte[] PiccSignature);

        /*
         * \brief ECC-based card authentication
         *
         * \param PrivateKeyNo Private key number
         * \param PcdOptions Options to send to the PICC (can be null)
         * \param PcdChallenge Random number of the PCD
         * \param PiccChallenge Random number of the PICC
         * \param PiccSignature PICC signature to be verified
         */
        long IsoInternalAuthenticate(byte PrivateKeyNo, byte[] PcdOptions, byte[] PcdChallenge, out byte[] PiccChallenge, out byte[] PiccSignature);

        /* Security related commandes */

        /**
         * @brief Changes the key settings of the DESFire chip.
         *
         * @param bKeySettings The new key settings.
         * @return A status code indicating the result of the operation.
         */
        long ChangeKeySettings(byte bKeySettings);

        /**
         * @brief Retrieves the current key settings and key count.
         *
         * @param[out] bKeySettings The current key settings.
         * @param[out] bKeyCount The number of keys available.
         * @return A status code indicating the result of the operation.
         */
        long GetKeySettings(out byte bKeySettings, out byte bKeyCount);

        /**
         * @brief Changes a key on the DESFire chip, providing the version (required for AES keys).
         *
         * @param KeyNumber The key number to change.
         * @param KeyVersion The version of the new key.
         * @param NewKeyValue The new key value.
         * @param OldKeyValue The old key value.
         * @return A status code indicating the result of the operation.
         */
        long ChangeKey(byte KeyNumber, byte KeyVersion, byte[] NewKeyValue, byte[] OldKeyValue);

        /**
         * @brief Retrieves the version of a specific key.
         *
         * @param KeyNumber The key number to query.
         * @param[out] KeyVersion The version of the key.
         * @return A status code indicating the result of the operation.
         */
        long GetKeyVersion(byte KeyNumber, out byte KeyVersion);

        /* PICC level commands */

        /**
         * @brief Creates a new application on the DESFire chip.
         *
         * @param Aid The application identifier (AID).
         * @param KeySetting1 The first key setting byte.
         * @param KeySetting2 The second key setting byte.
         * @return A status code indicating the result of the operation.
         */
        long CreateApplication(uint Aid, byte KeySetting1, byte KeySetting2);

        /**
         * @brief Creates a new ISO application on the DESFire chip.
         *
         * @param Aid The application identifier (AID).
         * @param KeySetting1 The first key setting byte.
         * @param KeySetting2 The second key setting byte.
         * @param DFID The ISO DF identifier.
         * @param DFName The ISO DF name.
         * @param DFNameLen The length of the ISO DF name.
         * @return A status code indicating the result of the operation.
         */
        long CreateApplication(uint Aid, byte KeySetting1, byte KeySetting2, ushort DFID, byte[] DFName, int DFNameLen);

        /**
         * @brief Creates a new ISO application on the DESFire chip.
         *
         * @param Aid The application identifier (AID).
         * @param KeySetting1 The first key setting byte.
         * @param KeySetting2 The second key setting byte.
         * @param DFID The ISO DF identifier.
         * @param DFName The ISO DF name.
         * @return A status code indicating the result of the operation.
         */
        long CreateApplication(uint Aid, byte KeySetting1, byte KeySetting2, ushort DFID, byte[] DFName);

        /**
         * @brief Creates a new ISO application on the DESFire chip.
         *
         * @param Aid The application identifier (AID).
         * @param KeySetting1 The first key setting byte.
         * @param KeySetting2 The second key setting byte.
         * @param DFID The ISO DF identifier.
         * @param DFName The ISO DF name.
         * @return A status code indicating the result of the operation.
         */
        long CreateApplication(uint Aid, byte KeySetting1, byte KeySetting2, ushort DFID, string DFName);

        /**
         * @brief Creates a new application on the DESFire chip with advanced settings.
         *
         * @param Aid The application identifier (AID).
         * @param KeySetting1 The first key setting byte.
         * @param KeySetting2 The second key setting byte.
         * @param KeySetting3 The third key setting byte.
         * @param AksVersion The version of the Application Key Set.
         * @param NoKeySets The number of key sets.
         * @param MaxKeySize The maximum key size.
         * @param AppKeySetSetting The application key set settings.
         * @param DFID The ISO DF identifier.
         * @param DFName The name of the application (array of bytes).
         * @param DFNameLen The length of the application name.
         * @return A status code indicating the result of the operation.
         */
        long CreateApplication(uint Aid, byte KeySetting1, byte KeySetting2, byte KeySetting3, byte AksVersion, byte NoKeySets, byte MaxKeySize, byte AppKeySetSetting, ushort DFID, byte[] DFName, int DFNameLen);

        /**
         * @brief Creates a new application on the DESFire chip with advanced settings.
         *
         * @param Aid The application identifier (AID).
         * @param KeySetting1 The first key setting byte.
         * @param KeySetting2 The second key setting byte.
         * @param KeySetting3 The third key setting byte.
         * @param AksVersion The version of the Application Key Set.
         * @param NoKeySets The number of key sets.
         * @param MaxKeySize The maximum key size.
         * @param AppKeySetSetting The application key set settings.
         * @param DFID The ISO DF identifier.
         * @param DFName The name of the application (array of bytes).
         * @return A status code indicating the result of the operation.
         */
        long CreateApplication(uint Aid, byte KeySetting1, byte KeySetting2, byte KeySetting3, byte AksVersion, byte NoKeySets, byte MaxKeySize, byte AppKeySetSetting, ushort DFID, byte[] DFName);

        /**
         * @brief Creates a new application on the DESFire chip with advanced settings.
         *
         * @param Aid The application identifier (AID).
         * @param KeySetting1 The first key setting byte.
         * @param KeySetting2 The second key setting byte.
         * @param KeySetting3 The third key setting byte.
         * @param AksVersion The version of the Application Key Set.
         * @param NoKeySets The number of key sets.
         * @param MaxKeySize The maximum key size.
         * @param AppKeySetSetting The application key set settings.
         * @param DFID The ISO DF identifier.
         * @param DFName The name of the application (string).
         * @return A status code indicating the result of the operation.
         */
        long CreateApplication(uint Aid, byte KeySetting1, byte KeySetting2, byte KeySetting3, byte AksVersion, byte NoKeySets, byte MaxKeySize, byte AppKeySetSetting, ushort DFID, string DFName);

        /**
         * @brief Deletes an application from the DESFire chip.
         *
         * @param Aid The application identifier (AID) to delete.
         * @return A status code indicating the result of the operation.
         */
        long DeleteApplication(uint Aid);

        /**
         * @brief Retrieves the list of application IDs on the DESFire chip.
         *
         * @param[out] AidList An array containing the application IDs.
         * @return A status code indicating the result of the operation.
         */
        long GetApplicationIDs(out uint[] AidList);

        /**
         * @brief Selects an application on the DESFire chip.
         *
         * @param Aid The application identifier (AID) to select.
         * @return A status code indicating the result of the operation.
         */
        long SelectApplication(uint Aid);

        /**
         * @brief Formats the entire DESFire chip, deleting all applications.
         *
         * @return A status code indicating the result of the operation.
         */
        long FormatPICC();

        /**
         * @brief Retrieves the version information of the DESFire chip.
         *
         * @param[out] VersionInfo A byte array containing the version information.
         * @return A status code indicating the result of the operation.
         */
        long GetVersion(out byte[] VersionInfo);

        /**
         * @brief Retrieves the version information of the DESFire chip.
         *
         * @param[out] VersionInfo A DesfireCommand.VERSION_INFO structure containing the version information.
         * @return A status code indicating the result of the operation.
         */
        long GetVersion(out DesfireVersionInfo VersionInfo);

        /**
         * @brief Retrieves the list of ISO applications on the DESFire chip.
         *
         * @param[out] AidList An array of DesfireCommand.ISO_APPLICATION structures containing the application details.
         * @return A status code indicating the result of the operation.
         */
        long GetDFNames(out DesfireIsoApplication[] AidList);

        /**
         * @brief Retrieves the amount of free memory on the DESFire chip.
         *
         * @param[out] FreeBytes The amount of free memory in bytes.
         * @return A status code indicating the result of the operation.
         */
        long GetFreeMemory(out uint FreeBytes);

        /**
         * @brief Configures the DESFire chip with the specified settings.
         *
         * @param Option The configuration option.
         * @param Data The configuration data.
         * @return A status code indicating the result of the operation.
         */
        long SetConfiguration(byte Option, byte[] Data);

        /**
         * @brief Disable the Format command inside the DESFire chip.
         *
         * @return A status code indicating the result of the operation.
         */
        long DisableCommandFormat();

        /**
         * @brief Enable the Random ID feature of the DESFire chip.
         *
         * @return A status code indicating the result of the operation.
         */
        long EnableRandomID();

        /**
         * @brief Configures the new applications of the DESFire chip with the specified default key (value and version).
         *
         * @param KeyValue The default key.
         * @param KeyVersion The default version.
         * @return A status code indicating the result of the operation.
         */

        long SetAppDefaultKey(byte[] KeyValue, byte KeyVersion);

        /**
         * @brief Configures the DESFire chip with the specified ATS.
         *
         * Only the length of the string is checked by the card.
         * No other verification of the ATS string is performed by the card nor the library. 
         * Therefore the data string must be formatted in the following: TL T0 TA TB TC + Historical bytes.
         *
         * @param Ats The new ATS.
         * @return A status code indicating the result of the operation.
         */
        long SetUserATS(byte[] Ats);

        /**
         * @brief Retrieves the UID of the DESFire chip.
         *
         * @param[out] CardUid A byte array containing the UID.
         * @return A status code indicating the result of the operation.
         */
        long GetCardUID(out byte[] CardUid);

        /* Application level commands */

        /**
         * @brief Retrieves the list of ISO file IDs in the currently selected application.
         *
         * @param[out] EfIsList An array of ISO EF IDs.
         * @return A status code indicating the result of the operation.
         */
        long GetIsoFileIDs(out ushort[] EfIsList);

        /**
         * @brief Retrieves the settings of a specific file.
         *
         * @param FileId The file ID to query.
         * @param[out] FileType The type of the file.
         * @param[out] CommMode The communication mode of the file.
         * @param[out] AccessRights The access rights of the file.
         * @param[out] AdditionnalSettings Additional settings specific to the file type.
         * @return A status code indicating the result of the operation.
         */
        long GetFileSettings(byte FileId, out byte FileType, out byte CommMode, out ushort AccessRights, out DesfireFileSettings AdditionnalSettings);

        /**
         * @brief Retrieves the settings of a specific file.
         *
         * @param FileId The file ID to query.
         * @param[out] FileType The type of the file.
         * @param[out] CommMode The communication mode of the file.
         * @param[out] AccessRights The access rights of the file.
         * @param[out] AdditionnalSettings Additional settings specific to the file type.
         * @return A status code indicating the result of the operation.
         */
        long GetFileSettings(byte FileId, out DesfireFileType FileType, out DesfireCommMode CommMode, out DesfireAccessRights AccessRights, out DesfireFileSettings AdditionnalSettings);

        /**
         * @brief Changes the settings of a specific file.
         *
         * @param FileId The file ID to modify.
         * @param CommMode The new communication mode.
         * @param AccessRights The new access rights.
         * @return A status code indicating the result of the operation.
         */
        long ChangeFileSettings(byte FileId, byte CommMode, ushort AccessRights);

        /**
         * @brief Changes the settings of a specific file.
         *
         * @param FileId The file ID to modify.
         * @param CommMode The new communication mode.
         * @param AccessRights The new access rights.
         * @return A status code indicating the result of the operation.
         */
        long ChangeFileSettings(byte FileId, DesfireCommMode CommMode, DesfireAccessRights AccessRights);

        /**
         * @brief Creates a standard data file in the currently selected application.
         *
         * @param FileId The file ID to create.
         * @param CommMode The communication mode of the file.
         * @param AccessRights The access rights of the file.
         * @param FileSize The size of the file in bytes.
         * @return A status code indicating the result of the operation.
         */
        long CreateStdDataFile(byte FileId, byte CommMode, ushort AccessRights, int FileSize);

        /**
         * @brief Creates a standard data file in the currently selected application.
         *
         * @param FileId The file ID to create.
         * @param CommMode The communication mode of the file.
         * @param AccessRights The access rights of the file.
         * @param FileSize The size of the file in bytes.
         * @return A status code indicating the result of the operation.
         */
        long CreateStdDataFile(byte FileId, DesfireCommMode CommMode, DesfireAccessRights AccessRights, int FileSize);

        /**
         * @brief Creates a backup data file in the currently selected application.
         *
         * @param FileId The file ID to create.
         * @param CommMode The communication mode of the file.
         * @param AccessRights The access rights of the file.
         * @param FileSize The size of the file in bytes.
         * @return A status code indicating the result of the operation.
         */
        long CreateBackupDataFile(byte FileId, byte CommMode, ushort AccessRights, int FileSize);

        /**
         * @brief Creates a backup data file in the currently selected application.
         *
         * @param FileId The file ID to create.
         * @param CommMode The communication mode of the file.
         * @param AccessRights The access rights of the file.
         * @param FileSize The size of the file in bytes.
         * @return A status code indicating the result of the operation.
         */
        long CreateBackupDataFile(byte FileId, DesfireCommMode CommMode, DesfireAccessRights AccessRights, int FileSize);

        /**
         * @brief Creates a value file in the currently selected application with limited credit enabled.
         *
         * @param FileId The file ID to create.
         * @param CommMode The communication mode of the file.
         * @param AccessRights The access rights of the file.
         * @param LowerLimit The lower limit of the value file.
         * @param UpperLimit The upper limit of the value file.
         * @param InitialValue The initial value of the file.
         * @param LimitedCreditEnabled Whether limited credit is enabled.
         * @return A status code indicating the result of the operation.
         */
        long CreateValueFile(byte FileId, byte CommMode, ushort AccessRights, long LowerLimit, long UpperLimit, long InitialValue, bool LimitedCreditEnabled);

        /**
         * @brief Creates a value file in the currently selected application with limited credit enabled.
         *
         * @param FileId The file ID to create.
         * @param CommMode The communication mode of the file.
         * @param AccessRights The access rights of the file.
         * @param LowerLimit The lower limit of the value file.
         * @param UpperLimit The upper limit of the value file.
         * @param InitialValue The initial value of the file.
         * @param LimitedCreditEnabled Whether limited credit is enabled.
         * @return A status code indicating the result of the operation.
         */
        long CreateValueFile(byte FileId, DesfireCommMode CommMode, DesfireAccessRights AccessRights, long LowerLimit, long UpperLimit, long InitialValue, bool LimitedCreditEnabled);

        /**
         * @brief Creates a linear record file in the currently selected application.
         *
         * @param FileId The file ID to create.
         * @param CommMode The communication mode of the file.
         * @param AccessRights The access rights of the file.
         * @param RecordSize The size of each record in bytes.
         * @param MaxRecords The maximum number of records.
         * @return A status code indicating the result of the operation.
         */
        long CreateLinearRecordFile(byte FileId, byte CommMode, ushort AccessRights, int RecordSize, int MaxRecords);

        /**
         * @brief Creates a linear record file in the currently selected application.
         *
         * @param FileId The file ID to create.
         * @param CommMode The communication mode of the file.
         * @param AccessRights The access rights of the file.
         * @param RecordSize The size of each record in bytes.
         * @param MaxRecords The maximum number of records.
         * @return A status code indicating the result of the operation.
         */
        long CreateLinearRecordFile(byte FileId, DesfireCommMode CommMode, DesfireAccessRights AccessRights, int RecordSize, int MaxRecords);

        /**
         * @brief Creates a cyclic record file in the currently selected application.
         *
         * @param FileId The file ID to create.
         * @param CommMode The communication mode of the file.
         * @param AccessRights The access rights of the file.
         * @param RecordSize The size of each record in bytes.
         * @param MaxRecords The maximum number of records.
         * @return A status code indicating the result of the operation.
         */
        long CreateCyclicRecordFile(byte FileId, byte CommMode, ushort AccessRights, int RecordSize, int MaxRecords);

        /**
         * @brief Creates a cyclic record file in the currently selected application.
         *
         * @param FileId The file ID to create.
         * @param CommMode The communication mode of the file.
         * @param AccessRights The access rights of the file.
         * @param RecordSize The size of each record in bytes.
         * @param MaxRecords The maximum number of records.
         * @return A status code indicating the result of the operation.
         */
        long CreateCyclicRecordFile(byte FileId, DesfireCommMode CommMode, DesfireAccessRights AccessRights, int RecordSize, int MaxRecords);

        /**
         * @brief Creates a standard ISO data file in the currently selected application.
         *
         * @param FileId The file ID to create.
         * @param IsoEfId The ISO EF identifier.
         * @param CommMode The communication mode of the file.
         * @param AccessRights The access rights of the file.
         * @param FileSize The size of the file in bytes.
         * @return A status code indicating the result of the operation.
         */
        long CreateIsoStdDataFile(byte FileId, ushort IsoEfId, byte CommMode, ushort AccessRights, int FileSize);

        /**
         * @brief Creates a backup ISO data file in the currently selected application.
         *
         * @param FileId The file ID to create.
         * @param IsoEfId The ISO EF identifier.
         * @param CommMode The communication mode of the file.
         * @param AccessRights The access rights of the file.
         * @param FileSize The size of the file in bytes.
         * @return A status code indicating the result of the operation.
         */
        long CreateIsoBackupDataFile(byte FileId, ushort IsoEfId, byte CommMode, ushort AccessRights, int FileSize);

        /**
         * @brief Creates a linear ISO record file in the currently selected application.
         *
         * @param FileId The file ID to create.
         * @param IsoEfId The ISO EF identifier.
         * @param CommMode The communication mode of the file.
         * @param AccessRights The access rights of the file.
         * @param RecordSize The size of each record in bytes.
         * @param MaxRecords The maximum number of records.
         * @return A status code indicating the result of the operation.
         */
        long CreateIsoLinearRecordFile(byte FileId, ushort IsoEfId, byte CommMode, ushort AccessRights, int RecordSize, int MaxRecords);

        /**
         * @brief Creates a cyclic ISO record file in the currently selected application.
         *
         * @param FileId The file ID to create.
         * @param IsoEfId The ISO EF identifier.
         * @param CommMode The communication mode of the file.
         * @param AccessRights The access rights of the file.
         * @param RecordSize The size of each record in bytes.
         * @param MaxRecords The maximum number of records.
         * @return A status code indicating the result of the operation.
         */
        long CreateIsoCyclicRecordFile(byte FileId, ushort IsoEfId, byte CommMode, ushort AccessRights, int RecordSize, int MaxRecords);

        /* Desfire EV2 authentication */

        /**
         * @brief Performs the first step of EV2 authentication with the DESFire chip.
         *
         * @param KeyNumber The key number to use for authentication.
         * @param KeyValue The key value (16 bytes for AES keys).
         * @return A status code indicating the result of the operation.
         */
        long AuthenticateEV2First(byte KeyNumber, byte[] KeyValue);

        /**
         * @brief Performs the first step of EV2 authentication with the DESFire chip, including PCD capabilities.
         *
         * @param KeyNumber The key number to use for authentication.
         * @param KeyValue The key value (16 bytes for AES keys).
         * @param PcdCaps2 The PCD capabilities (6 bytes).
         * @return A status code indicating the result of the operation.
         */
        long AuthenticateEV2First(byte KeyNumber, byte[] KeyValue, byte[] PcdCaps2);

        /**
         * @brief Performs the first step of EV2 authentication with the DESFire chip, including PICC capabilities.
         *
         * @param KeyNumber The key number to use for authentication.
         * @param KeyValue The key value (16 bytes for AES keys).
         * @param[out] PiccCaps2 The PICC capabilities (6 bytes).
         * @return A status code indicating the result of the operation.
         */
        long AuthenticateEV2First(byte KeyNumber, byte[] KeyValue, out byte[] PiccCaps2);

        /**
         * @brief Performs the first step of EV2 authentication with the DESFire chip, including PCD and PICC capabilities.
         *
         * @param KeyNumber The key number to use for authentication.
         * @param KeyValue The key value (16 bytes for AES keys).
         * @param PcdCaps2 The PCD capabilities (6 bytes).
         * @param[out] PiccCaps2 The PICC capabilities (6 bytes).
         * @return A status code indicating the result of the operation.
         */
        long AuthenticateEV2First(byte KeyNumber, byte[] KeyValue, byte[] PcdCaps2, out byte[] PiccCaps2);

        /**
         * @brief Performs the first step of EV2 authentication with the DESFire chip, including PCD and PICC capabilities.
         *
         * @param KeyNumber The key number to use for authentication.
         * @param KeyValue The key value (16 bytes for AES keys).
         * @param PcdCaps2 The PCD capabilities (6 bytes).
         * @param[out] PiccCaps2 The PICC capabilities (6 bytes).
         * @param[out] TransactionIdentifier The transaction identifier provided by the PICC (4 bytes).* 
         * @return A status code indicating the result of the operation.
         */
        long AuthenticateEV2First(byte KeyNumber, byte[] KeyValue, byte[] PcdCaps2, out byte[] PiccCaps2, out byte[] TransactionIdentifier);

        /**
         * @brief Performs the first step of EV2 authentication with the DESFire chip, including PCD and PICC capabilities.
         *
         * @param KeyNumber The key number to use for authentication.
         * @param KeyValue The key value (16 bytes for AES keys).
         * @param PcdCaps2 The PCD capabilities (6 bytes).
         * @param[out] PcdCaps2 The PCD capabilities echoed by the PICC (6 bytes).
         * @param[out] PiccCaps2 The PICC capabilities (6 bytes).
         * @param[out] TransactionIdentifier The transaction identifier provided by the PICC (4 bytes).* 
         * @return A status code indicating the result of the operation.
         */
        long AuthenticateEV2First(byte KeyNumber, byte[] KeyValue, byte[] PcdCaps2, out byte[] PcdCaps2_echo, out byte[] PiccCaps2, out byte[] TransactionIdentifier);

        /**
         * @brief Performs the non-first step of EV2 authentication with the DESFire chip.
         *
         * @param KeyNumber The key number to use for authentication.
         * @param KeyValue The key value (16 bytes for AES keys).
         * @return A status code indicating the result of the operation.
         */
        long AuthenticateEV2NonFirst(byte KeyNumber, byte[] KeyValue);

        /* Key Management Commands */

        /**
         * @brief Changes a key on the DESFire chip, supporting key versioning and key sets.
         *
         * @param KeySetNumber The key set number to use.
         * @param KeyNumber The key number to change.
         * @param KeyVersion The version of the new key.
         * @param NewKeyValue The new key value.
         * @param OldKeyValue The old key value.
         * @return A status code indicating the result of the operation.
         */
        long ChangeKeyEV2(byte KeySetNumber, byte KeyNumber, byte KeyVersion, byte[] NewKeyValue, byte[] OldKeyValue);

        /**
         * @brief Initializes a key set on the DESFire chip.
         *
         * @param KeySetNumber The key set number to initialize.
         * @param KeySetType The type of the key set.
         * @return A status code indicating the result of the operation.
         */
        long InitializeKeySet(byte KeySetNumber, byte KeySetType);

        /**
         * @brief Finalizes a key set on the DESFire chip.
         *
         * @param KeySetNumber The key set number to finalize.
         * @param KeySetVersion The version of the key set.
         * @return A status code indicating the result of the operation.
         */
        long FinalizeKeySet(byte KeySetNumber, byte KeySetVersion);

        /**
         * @brief Rolls a key set on the DESFire chip.
         *
         * This method activates a new key set version and deactivates the current one.
         *
         * @param KeySetNumber The key set number to roll.
         * @return A status code indicating the result of the operation.
         */
        long RollKeySet(byte KeySetNumber);

        /* Application level commands */

        /**
         * @brief Retrieves the list of file IDs in the currently selected application.
         *
         * @param[out] ListData A byte array containing the file IDs.
         * @return A status code indicating the result of the operation.
         */
        long GetFileIDs(out byte[] ListData);

        /**
         * @brief Deletes a file in the currently selected application.
         *
         * @param FileId The file ID to delete.
         * @return A status code indicating the result of the operation.
         */
        long DeleteFile(byte FileId);

        /* Data manipulation commands -- linear files */

        /**
         * @brief Reads data from a standard or backup file.
         *
         * @param FileId The file ID to read from.
         * @param CommMode The communication mode of the file.
         * @param FromOffset The starting offset to read from.
         * @param MaxCount The maximum number of bytes to read.
         * @param[out] Data A byte array containing the read data.
         * @return A status code indicating the result of the operation.
         */
        long ReadData(byte FileId, byte CommMode, int FromOffset, int MaxCount, out byte[] Data);

        /**
         * @brief Reads data from a standard or backup file.
         *
         * @param FileId The file ID to read from.
         * @param CommMode The communication mode of the file.
         * @param FromOffset The starting offset to read from.
         * @param MaxCount The maximum number of bytes to read.
         * @param[out] Data A byte array containing the read data.
         * @return A status code indicating the result of the operation.
         */
        long ReadData(byte FileId, DesfireCommMode CommMode, int FromOffset, int MaxCount, out byte[] Data);

        /**
         * @brief Reads data from a standard or backup file.
         *
         * Offset is set to 0.
         *
         * @param FileId The file ID to read from.
         * @param CommMode The communication mode of the file.
         * @param MaxCount The maximum number of bytes to read.
         * @param[out] Data A byte array containing the read data.
         * @return A status code indicating the result of the operation.
         */
        long ReadData(byte FileId, byte CommMode, int MaxCount, out byte[] Data);

        /**
         * @brief Reads data from a standard or backup file.
         *
         * Offset is set to 0.
         *
         * @param FileId The file ID to read from.
         * @param CommMode The communication mode of the file.
         * @param MaxCount The maximum number of bytes to read.
         * @param[out] Data A byte array containing the read data.
         * @return A status code indicating the result of the operation.
         */
        long ReadData(byte FileId, DesfireCommMode CommMode, int MaxCount, out byte[] Data);

        /**
         * @brief Reads data from a standard or backup file.
         *
         * Offset is set to 0.
         * All the bytes in the file are read.
         *
         * @param FileId The file ID to read from.
         * @param CommMode The communication mode of the file.
         * @param[out] Data A byte array containing the read data.
         * @return A status code indicating the result of the operation.
         */
        long ReadData(byte FileId, byte CommMode, out byte[] Data);

        /**
         * @brief Reads data from a standard or backup file.
         *
         * Offset is set to 0.
         * All the bytes in the file are read.
         *
         * @param FileId The file ID to read from.
         * @param CommMode The communication mode of the file.
         * @param[out] Data A byte array containing the read data.
         * @return A status code indicating the result of the operation.
         */
        long ReadData(byte FileId, DesfireCommMode CommMode, out byte[] Data);

        /**
         * @brief Reads data from a standard or backup file.
         * 
         * CommMode is determined by querying GetFileSettings beforehand.
         *
         * @param FileId The file ID to read from.
         * @param FromOffset The starting offset to read from.
         * @param MaxCount The maximum number of bytes to read.
         * @param[out] Data A byte array containing the read data.
         * @return A status code indicating the result of the operation.
         */
        long ReadData2(byte FileId, int FromOffset, int MaxCount, out byte[] Data);

        /**
         * @brief Reads data from a standard or backup file.
         * 
         * CommMode is determined by querying GetFileSettings beforehand.
         * Offset is set to 0.
         *
         * @param FileId The file ID to read from.
         * @param MaxCount The maximum number of bytes to read.
         * @param[out] Data A byte array containing the read data.
         * @return A status code indicating the result of the operation.
         */
        long ReadData2(byte FileId, int MaxCount, out byte[] Data);

        /**
         * @brief Reads data from a standard or backup file.
         * 
         * CommMode is determined by querying GetFileSettings beforehand.
         * Offset is set to 0.
         * All the bytes in the file are read.
         *
         * @param FileId The file ID to read from.
         * @param[out] Data A byte array containing the read data.
         * @return A status code indicating the result of the operation.
         */
        long ReadData2(byte FileId, out byte[] Data);

        /**
         * @brief Writes data to a standard or backup file.
         *
         * @param FileId The file ID to write to.
         * @param CommMode The communication mode of the file.
         * @param FromOffset The starting offset to write to.
         * @param Size The number of bytes to write.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        long WriteData(byte FileId, byte CommMode, int FromOffset, int Size, byte[] Data);

        /**
         * @brief Writes data to a standard or backup file.
         *
         * @param FileId The file ID to write to.
         * @param CommMode The communication mode of the file.
         * @param FromOffset The starting offset to write to.
         * @param Size The number of bytes to write.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        long WriteData(byte FileId, DesfireCommMode CommMode, int FromOffset, int Size, byte[] Data);

        /**
         * @brief Writes data to a standard or backup file.
         * 
         * Size is automatically calculated based on the length of the Data array.
         *
         * @param FileId The file ID to write to.
         * @param CommMode The communication mode of the file.
         * @param FromOffset The starting offset to write to.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        long WriteData(byte FileId, byte CommMode, int FromOffset, byte[] Data);

        /**
         * @brief Writes data to a standard or backup file.
         * 
         * Size is automatically calculated based on the length of the Data array.
         *
         * @param FileId The file ID to write to.
         * @param CommMode The communication mode of the file.
         * @param FromOffset The starting offset to write to.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        long WriteData(byte FileId, DesfireCommMode CommMode, int FromOffset, byte[] Data);

        /**
         * @brief Writes data to a standard or backup file.
         * 
         * Size is automatically calculated based on the length of the Data array.
         * Offset is set to 0.
         *
         * @param FileId The file ID to write to.
         * @param CommMode The communication mode of the file.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        long WriteData(byte FileId, byte CommMode, byte[] Data);

        /**
         * @brief Writes data to a standard or backup file.
         * 
         * Size is automatically calculated based on the length of the Data array.
         * Offset is set to 0.
         *
         * @param FileId The file ID to write to.
         * @param CommMode The communication mode of the file.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        long WriteData(byte FileId, DesfireCommMode CommMode, byte[] Data);

        /**
         * @brief Writes data to a standard or backup file.
         * 
         * CommMode is determined by querying GetFileSettings beforehand.
         *
         * @param FileId The file ID to write to.
         * @param FromOffset The starting offset to write to.
         * @param Size The number of bytes to write.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        long WriteData2(byte FileId, int FromOffset, int Size, byte[] Data);

        /**
         * @brief Writes data to a standard or backup file.
         * 
         * CommMode is determined by querying GetFileSettings beforehand.
         * Size is automatically calculated based on the length of the Data array.
         *
         * @param FileId The file ID to write to.
         * @param FromOffset The starting offset to write to.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        long WriteData2(byte FileId, int FromOffset, byte[] Data);

        /**
         * @brief Writes data to a standard or backup file.
         * 
         * CommMode is determined by querying GetFileSettings beforehand.
         * Size is automatically calculated based on the length of the Data array.
         * Offset is set to 0.
         *
         * @param FileId The file ID to write to.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        long WriteData2(byte FileId, byte[] Data);

        /* Data manipulation commands -- value files */

        /**
         * @brief Retrieves the current value of a value file.
         *
         * @param FileId The file ID to query.
         * @param CommMode The communication mode of the file.
         * @param[out] Value The current value of the file.
         * @return A status code indicating the result of the operation.
         */
        long GetValue(byte FileId, byte CommMode, out long Value);

        /**
         * @brief Retrieves the current value of a value file.
         *
         * @param FileId The file ID to query.
         * @param CommMode The communication mode of the file.
         * @param[out] Value The current value of the file.
         * @return A status code indicating the result of the operation.
         */
        long GetValue(byte FileId, DesfireCommMode CommMode, out long Value);

        /**
         * @brief Retrieves the current value of a value file.
         *
         * CommMode is determined by querying GetFileSettings beforehand.
         *
         * @param FileId The file ID to query.
         * @param[out] Value The current value of the file.
         * @return A status code indicating the result of the operation.
         */
        long GetValue2(byte FileId, out long Value);

        /**
         * @brief Credits a value file with a specified amount.
         *
         * @param FileId The file ID to credit.
         * @param CommMode The communication mode of the file.
         * @param Amount The amount to credit.
         * @return A status code indicating the result of the operation.
         */
        long Credit(byte FileId, byte CommMode, long Amount);

        /**
         * @brief Credits a value file with a specified amount.
         *
         * @param FileId The file ID to credit.
         * @param CommMode The communication mode of the file.
         * @param Amount The amount to credit.
         * @return A status code indicating the result of the operation.
         */
        long Credit(byte FileId, DesfireCommMode CommMode, long Amount);

        /**
         * @brief Credits a value file with a specified amount.
         *
         * CommMode is determined by querying GetFileSettings beforehand.
         *
         * @param FileId The file ID to credit.
         * @param Amount The amount to credit.
         * @return A status code indicating the result of the operation.
         */
        long Credit2(byte FileId, long Amount);

        /**
         * @brief Debits a value file by a specified amount.
         *
         * @param FileId The file ID to debit.
         * @param CommMode The communication mode of the file.
         * @param Amount The amount to debit.
         * @return A status code indicating the result of the operation.
         */
        long Debit(byte FileId, byte CommMode, long Amount);

        /**
         * @brief Debits a value file by a specified amount.
         *
         * @param FileId The file ID to debit.
         * @param CommMode The communication mode of the file.
         * @param Amount The amount to debit.
         * @return A status code indicating the result of the operation.
         */
        long Debit(byte FileId, DesfireCommMode CommMode, long Amount);

        /**
         * @brief Debits a value file by a specified amount.
         *
         * CommMode is determined by querying GetFileSettings beforehand.
         *
         * @param FileId The file ID to debit.
         * @param Amount The amount to debit.
         * @return A status code indicating the result of the operation.
         */
        long Debit2(byte FileId, long Amount);

        /**
         * @brief Credits a value file with a limited amount.
         *
         * @param FileId The file ID to credit.
         * @param CommMode The communication mode of the file.
         * @param Amount The amount to credit.
         * @return A status code indicating the result of the operation.
         */
        long LimitedCredit(byte FileId, byte CommMode, long Amount);

        /**
         * @brief Credits a value file with a limited amount.
         *
         * @param FileId The file ID to credit.
         * @param CommMode The communication mode of the file.
         * @param Amount The amount to credit.
         * @return A status code indicating the result of the operation.
         */
        long LimitedCredit(byte FileId, DesfireCommMode CommMode, long Amount);

        /**
         * @brief Credits a value file with a limited amount.
         *
         * CommMode is determined by querying GetFileSettings beforehand.
         *
         * @param FileId The file ID to credit.
         * @param Amount The amount to credit.
         * @return A status code indicating the result of the operation.
         */
        long LimitedCredit2(byte FileId, long Amount);

        /* Data manipulation commands -- record files */

        /**
         * @brief Reads a specific record from a record file.
         *
         * @param FileId The file ID to read from.
         * @param CommMode The communication mode of the file.
         * @param RecordNumber The record number to read.
         * @param RecordSize The size of the record in bytes.
         * @param[out] Data A byte array containing the read record data.
         * @return A status code indicating the result of the operation.
         */
        long ReadRecord(byte FileId, byte CommMode, int RecordNumber, int RecordSize, out byte[] Data);

        /**
         * @brief Reads a specific record from a record file.
         *
         * @param FileId The file ID to read from.
         * @param CommMode The communication mode of the file.
         * @param RecordNumber The record number to read.
         * @param RecordSize The size of the record in bytes.
         * @param[out] Data A byte array containing the read record data.
         * @return A status code indicating the result of the operation.
         */
        long ReadRecord(byte FileId, DesfireCommMode CommMode, int RecordNumber, int RecordSize, out byte[] Data);

        /**
         * @brief Reads multiple records from a record file.
         *
         * @param FileId The file ID to read from.
         * @param CommMode The communication mode of the file.
         * @param FromRecord The starting record number to read from.
         * @param MaxCount The maximum number of records to read.
         * @param RecordSize The size of each record in bytes.
         * @param[out] Data A list of byte arrays containing the read records.
         * @return A status code indicating the result of the operation.
         */
        long ReadRecords(byte FileId, byte CommMode, int FromRecord, int MaxCount, int RecordSize, out List<byte[]> Data);

        /**
         * @brief Reads multiple records from a record file.
         *
         * @param FileId The file ID to read from.
         * @param CommMode The communication mode of the file.
         * @param FromRecord The starting record number to read from.
         * @param MaxCount The maximum number of records to read.
         * @param RecordSize The size of each record in bytes.
         * @param[out] Data A list of byte arrays containing the read records.
         * @return A status code indicating the result of the operation.
         */
        long ReadRecords(byte FileId, DesfireCommMode CommMode, int FromRecord, int MaxCount, int RecordSize, out List<byte[]> Data);

        /**
         * @brief Reads multiple records from a record file.
         *
         * @param FileId The file ID to read from.
         * @param CommMode The communication mode of the file.
         * @param FromRecord The starting record number to read from.
         * @param MaxCount The maximum number of records to read.
         * @param RecordSize The size of each record in bytes.
         * @param[out] Data A byte array containing the concatenated read records.
         * @return A status code indicating the result of the operation.
         */
        long ReadRecords(byte FileId, byte CommMode, int FromRecord, int MaxCount, int RecordSize, out byte[] Data);

        /**
         * @brief Reads multiple records from a record file.
         *
         * @param FileId The file ID to read from.
         * @param CommMode The communication mode of the file.
         * @param FromRecord The starting record number to read from.
         * @param MaxCount The maximum number of records to read.
         * @param RecordSize The size of each record in bytes.
         * @param[out] Data A byte array containing the concatenated read records.
         * @return A status code indicating the result of the operation.
         */
        long ReadRecords(byte FileId, DesfireCommMode CommMode, int FromRecord, int MaxCount, int RecordSize, out byte[] Data);

        /**
         * @brief Reads multiple records from a record file and retrieves the actual count of records read.
         *
         * @param FileId The file ID to read from.
         * @param CommMode The communication mode of the file.
         * @param FromRecord The starting record number to read from.
         * @param MaxCount The maximum number of records to read.
         * @param RecordSize The size of each record in bytes.
         * @param[out] Data A byte array containing the concatenated read records.
         * @param[out] ActualCount The actual number of records read.
         * @return A status code indicating the result of the operation.
         */
        long ReadRecords(byte FileId, byte CommMode, int FromRecord, int MaxCount, int RecordSize, out byte[] Data, out int ActualCount);

        /**
         * @brief Reads multiple records from a record file and retrieves the actual count of records read.
         *
         * @param FileId The file ID to read from.
         * @param CommMode The communication mode of the file.
         * @param FromRecord The starting record number to read from.
         * @param MaxCount The maximum number of records to read.
         * @param RecordSize The size of each record in bytes.
         * @param[out] Data A byte array containing the concatenated read records.
         * @param[out] ActualCount The actual number of records read.
         * @return A status code indicating the result of the operation.
         */
        long ReadRecords(byte FileId, DesfireCommMode CommMode, int FromRecord, int MaxCount, int RecordSize, out byte[] Data, out int ActualCount);

        /**
         * @brief Reads a specific record from a record file.
         *
         * CommMode is determined by querying GetFileSettings beforehand.
         *
         * @param FileId The file ID to read from.
         * @param RecordNumber The record number to read.
         * @param[out] Data A byte array containing the read record data.
         * @return A status code indicating the result of the operation.
         */
        long ReadRecord2(byte FileId, int RecordNumber, out byte[] Data);

        /**
         * @brief Reads multiple records from a record file.
         *
         * CommMode is determined by querying GetFileSettings beforehand.
         *
         * @param FileId The file ID to read from.
         * @param FromRecord The starting record number to read from.
         * @param MaxCount The maximum number of records to read.
         * @param[out] Data A list of byte arrays containing the read records.
         * @return A status code indicating the result of the operation.
         */
        long ReadRecords2(byte FileId, int FromRecord, int MaxCount, out List<byte[]> Data);

        /**
         * @brief Reads multiple records from a record file and retrieves the record size and actual count of records read.
         *
         * CommMode is determined by querying GetFileSettings beforehand.
         *
         * @param FileId The file ID to read from.
         * @param FromRecord The starting record number to read from.
         * @param MaxCount The maximum number of records to read.
         * @param[out] Data A byte array containing the concatenated read records.
         * @param[out] RecordSize The size of each record in bytes.
         * @param[out] ActualCount The actual number of records read.
         * @return A status code indicating the result of the operation.
         */
        long ReadRecords2(byte FileId, int FromRecord, int MaxCount, out byte[] Data, out int RecordSize, out int ActualCount);

        /**
         * @brief Writes a specific record to a record file.
         *
         * @param FileId The file ID to write to.
         * @param CommMode The communication mode of the file.
         * @param FromOffset The starting offset within the record to write to.
         * @param Size The number of bytes to write.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        long WriteRecord(byte FileId, byte CommMode, int FromOffset, int Size, byte[] Data);

        /**
         * @brief Writes a specific record to a record file.
         *
         * @param FileId The file ID to write to.
         * @param CommMode The communication mode of the file.
         * @param FromOffset The starting offset within the record to write to.
         * @param Size The number of bytes to write.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        long WriteRecord(byte FileId, DesfireCommMode CommMode, int FromOffset, int Size, byte[] Data);

        /**
         * @brief Writes a specific record to a record file.
         *
         * Size is automatically calculated based on the length of the Data array.
         *
         * @param FileId The file ID to write to.
         * @param CommMode The communication mode of the file.
         * @param FromOffset The starting offset within the record to write to.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        long WriteRecord(byte FileId, byte CommMode, int FromOffset, byte[] Data);

        /**
         * @brief Writes a specific record to a record file.
         *
         * Size is automatically calculated based on the length of the Data array.
         *
         * @param FileId The file ID to write to.
         * @param CommMode The communication mode of the file.
         * @param FromOffset The starting offset within the record to write to.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        long WriteRecord(byte FileId, DesfireCommMode CommMode, int FromOffset, byte[] Data);

        /**
         * @brief Writes a specific record to a record file.
         *
         * Offset is 0
         * Size is automatically calculated based on the length of the Data array.
         *
         * @param FileId The file ID to write to.
         * @param CommMode The communication mode of the file.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        long WriteRecord(byte FileId, byte CommMode, byte[] Data);

        /**
         * @brief Writes a specific record to a record file.
         *
         * Offset is 0
         * Size is automatically calculated based on the length of the Data array.
         *
         * @param FileId The file ID to write to.
         * @param CommMode The communication mode of the file.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        long WriteRecord(byte FileId, DesfireCommMode CommMode, byte[] Data);

        /**
         * @brief Writes a specific record to a record file.
         *
         * CommMode is determined by querying GetFileSettings beforehand.
         *
         * @param FileId The file ID to write to.
         * @param FromOffset The starting offset within the record to write to.
         * @param Size The number of bytes to write.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        long WriteRecord2(byte FileId, int FromOffset, int Size, byte[] Data);

        /**
         * @brief Writes a specific record to a record file.
         *
         * CommMode is determined by querying GetFileSettings beforehand.
         * Size is automatically calculated based on the length of the Data array.
         *
         * @param FileId The file ID to write to.
         * @param FromOffset The starting offset within the record to write to.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        long WriteRecord2(byte FileId, int FromOffset, byte[] Data);

        /**
         * @brief Writes a specific record to a record file.
         *
         * CommMode is determined by querying GetFileSettings beforehand.
         * Offset is 0.
         * Size is automatically calculated based on the length of the Data array.
         *
         * @param FileId The file ID to write to.
         * @param Data The data to write.
         * @return A status code indicating the result of the operation.
         */
        long WriteRecord2(byte FileId, byte[] Data);

        /**
         * @brief Clears all records in a record file.
         *
         * @param FileId The file ID to clear.
         * @return A status code indicating the result of the operation.
         */
        long ClearRecordFile(byte FileId);

        /* Transactions */

        /**
         * @brief Commits all pending transactions on the DESFire chip.
         *
         * @return A status code indicating the result of the operation.
         */
        long CommitTransaction();

        /**
         * @brief Aborts all pending transactions on the DESFire chip.
         *
         * @return A status code indicating the result of the operation.
         */
        long AbortTransaction();





    }
}
