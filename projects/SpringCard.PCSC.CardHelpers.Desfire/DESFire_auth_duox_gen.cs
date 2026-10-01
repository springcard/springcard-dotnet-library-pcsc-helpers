/*
 * SpringCard DESFire Library (C#)
 * Copyright (c) SpringCard SAS, 2008-2025
 *
 * This file is part of the SpringCard DESFire library.
 * See LICENSE.txt for license details and restrictions.
 *
 */
using Org.BouncyCastle.Crypto.Parameters;
using SpringCard.LibCs;

namespace SpringCard.PCSC.CardHelpers
{
    public partial class Desfire
    {
        #region Mutual authentication with reader Certificate

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
        public long IsoGeneralAuthenticateMutual(byte Curve, byte CARootKeyNo, byte[] PcdLTPriKey, byte[] PcdCertificate, byte PrivateKeyNo, byte CertificateFileId, out byte[] PiccOptions, out byte[] PiccCertificate)
        {
            return IsoGeneralAuthenticateMutual((MifareDuoXEccCurve)Curve, CARootKeyNo, PcdLTPriKey, PcdCertificate, PrivateKeyNo, CertificateFileId, out PiccOptions, out PiccCertificate);
        }

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
        public long IsoGeneralAuthenticateMutual(MifareDuoXEccCurve Curve, byte CARootKeyNo, byte[] PcdLTPriKey, byte[] PcdCertificate, byte PrivateKeyNo, byte CertificateFileId, out byte[] PiccOptions, out byte[] PiccCertificate)
        {
            return IsoGeneralAuthenticateMutual(Curve, CARootKeyNo, 0, PcdLTPriKey, PcdCertificate, PrivateKeyNo, false, CertificateFileId, out PiccOptions, out PiccCertificate);
        }

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
        public long IsoGeneralAuthenticateMutual(byte Curve, byte CARootKeyNo, byte SecCARootKeyNo, byte[] PcdLTPriKey, byte[] PcdCertificate, byte PrivateKeyNo, byte CertificateFileId, out byte[] PiccOptions, out byte[] PiccCertificate)
        {
            return IsoGeneralAuthenticateMutual((MifareDuoXEccCurve)Curve, CARootKeyNo, SecCARootKeyNo, PcdLTPriKey, PcdCertificate, PrivateKeyNo, CertificateFileId, out PiccOptions, out PiccCertificate);
        }

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
        public long IsoGeneralAuthenticateMutual(MifareDuoXEccCurve Curve, byte CARootKeyNo, byte SecCARootKeyNo, byte[] PcdLTPriKey, byte[] PcdCertificate, byte PrivateKeyNo, byte CertificateFileId, out byte[] PiccOptions, out byte[] PiccCertificate)
        {
            return IsoGeneralAuthenticateMutual(Curve, CARootKeyNo, SecCARootKeyNo, PcdLTPriKey, PcdCertificate, PrivateKeyNo, false, CertificateFileId, out PiccOptions, out PiccCertificate);
        }

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
        public long IsoGeneralAuthenticateMutual(byte Curve, byte CARootKeyNo, byte SecCARootKeyNo, byte[] PcdLTPriKey, byte[] PcdCertificate, byte PrivateKeyNo, bool CertificateSAI, byte CertificateFileId, out byte[] PiccOptions, out byte[] PiccCertificate)
        {
            return IsoGeneralAuthenticateMutual((MifareDuoXEccCurve)Curve, CARootKeyNo, SecCARootKeyNo, PcdLTPriKey, PcdCertificate, PrivateKeyNo, CertificateSAI, CertificateFileId, out PiccOptions, out PiccCertificate);
        }

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
        public long IsoGeneralAuthenticateMutual(MifareDuoXEccCurve Curve, byte CARootKeyNo, byte SecCARootKeyNo, byte[] PcdLTPriKey, byte[] PcdCertificate, byte PrivateKeyNo, bool CertificateSAI, byte CertificateFileId, out byte[] PiccOptions, out byte[] PiccCertificate)
        {
            byte P2 = 0x00;
            P2 |= (byte)(CARootKeyNo & 0x03);
            P2 |= (byte)((SecCARootKeyNo << 4) & 0x30);

            MifareDuoXGeneralAuthenticatePcdOptions PcdOptions = MifareDuoXGeneralAuthenticatePcdOptions.Create(MifareDuoXGeneralAuthenticatePcdOptions.EAuthMethod.MutualWithPcdCertificate);
            PcdOptions.PrivateKeyNo = PrivateKeyNo;
            PcdOptions.CertificateSAI = CertificateSAI;
            PcdOptions.CertificateFileId = CertificateFileId;

            return IsoGeneralAuthenticate(Curve, P2, PcdOptions, PcdLTPriKey, PcdCertificate, out PiccOptions, out PiccCertificate);
        }

        #endregion

        #region Mutual authentication without reader Certificate

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
        public long IsoGeneralAuthenticateMutual(byte Curve, byte CARootKeyNo, byte[] PcdLTPriKey, byte PrivateKeyNo, byte CertificateFileId, out byte[] PiccOptions, out byte[] PiccCertificate)
        {
            return IsoGeneralAuthenticateMutual((MifareDuoXEccCurve)Curve, CARootKeyNo, PcdLTPriKey, PrivateKeyNo, CertificateFileId, out PiccOptions, out PiccCertificate);
        }

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
        public long IsoGeneralAuthenticateMutual(MifareDuoXEccCurve Curve, byte CARootKeyNo, byte[] PcdLTPriKey, byte PrivateKeyNo, byte CertificateFileId, out byte[] PiccOptions, out byte[] PiccCertificate)
        {
            return IsoGeneralAuthenticateMutual(Curve, CARootKeyNo, 0, PcdLTPriKey, PrivateKeyNo, false, CertificateFileId, out PiccOptions, out PiccCertificate);
        }

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
        public long IsoGeneralAuthenticateMutual(byte Curve, byte CARootKeyNo, byte SecCARootKeyNo, byte[] PcdLTPriKey, byte PrivateKeyNo, byte CertificateFileId, out byte[] PiccOptions, out byte[] PiccCertificate)
        {
            return IsoGeneralAuthenticateMutual((MifareDuoXEccCurve)Curve, CARootKeyNo, SecCARootKeyNo, PcdLTPriKey, PrivateKeyNo, CertificateFileId, out PiccOptions, out PiccCertificate);
        }

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
        public long IsoGeneralAuthenticateMutual(MifareDuoXEccCurve Curve, byte CARootKeyNo, byte SecCARootKeyNo, byte[] PcdLTPriKey, byte PrivateKeyNo, byte CertificateFileId, out byte[] PiccOptions, out byte[] PiccCertificate)
        {
            return IsoGeneralAuthenticateMutual(Curve, CARootKeyNo, SecCARootKeyNo, PcdLTPriKey, PrivateKeyNo, false, CertificateFileId, out PiccOptions, out PiccCertificate);
        }

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
        public long IsoGeneralAuthenticateMutual(byte Curve, byte CARootKeyNo, byte SecCARootKeyNo, byte[] PcdLTPriKey, byte PrivateKeyNo, bool CertificateSAI, byte CertificateFileId, out byte[] PiccOptions, out byte[] PiccCertificate)
        {
            return IsoGeneralAuthenticateMutual((MifareDuoXEccCurve)Curve, CARootKeyNo, SecCARootKeyNo, PcdLTPriKey, PrivateKeyNo, CertificateSAI, CertificateFileId, out PiccOptions, out PiccCertificate);
        }

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
        public long IsoGeneralAuthenticateMutual(MifareDuoXEccCurve Curve, byte CARootKeyNo, byte SecCARootKeyNo, byte[] PcdLTPriKey, byte PrivateKeyNo, bool CertificateSAI, byte CertificateFileId, out byte[] PiccOptions, out byte[] PiccCertificate)
        {
            byte P2 = 0x00;
            P2 |= (byte)(CARootKeyNo & 0x03);
            P2 |= (byte)((SecCARootKeyNo << 4) & 0x30);

            MifareDuoXGeneralAuthenticatePcdOptions PcdOptions = MifareDuoXGeneralAuthenticatePcdOptions.Create(MifareDuoXGeneralAuthenticatePcdOptions.EAuthMethod.MutualWithoutPcdCertificate);
            PcdOptions.PrivateKeyNo = PrivateKeyNo;
            PcdOptions.CertificateSAI = CertificateSAI;
            PcdOptions.CertificateFileId = CertificateFileId;

            return IsoGeneralAuthenticate(Curve, P2, PcdOptions, PcdLTPriKey, null, out PiccOptions, out PiccCertificate);
        }

        #endregion

        #region Unilateral reader authentication with reader Certificate

        /*
         * \brief ECC-based unilateral reader authentication, with reader Certificate
         * 
         * \param Curve ECC curve to use
         * \param CARootKeyNo Key number of the (primary) targeted CA root key
         * \param PcdLTPriKey Long-term private key of the PCD
         * \param PcdCertificate Certificate of the PCD, corresponding to PcdLTPriKey
         * \param PiccOptions Options returned by the PICC
         */
        public long IsoGeneralAuthenticateReader(byte Curve, byte CARootKeyNo, byte[] PcdLTPriKey, byte[] PcdCertificate, out byte[] PiccOptions)
        {
            return IsoGeneralAuthenticateReader((MifareDuoXEccCurve)Curve, CARootKeyNo, PcdLTPriKey, PcdCertificate, out PiccOptions);
        }

        /*
         * \brief ECC-based unilateral reader authentication, with reader Certificate
         * 
         * \param Curve ECC curve to use
         * \param CARootKeyNo Key number of the (primary) targeted CA root key
         * \param PcdLTPriKey Long-term private key of the PCD
         * \param PcdCertificate Certificate of the PCD, corresponding to PcdLTPriKey
         * \param PiccOptions Options returned by the PICC
         */
        public long IsoGeneralAuthenticateReader(MifareDuoXEccCurve Curve, byte CARootKeyNo, byte[] PcdLTPriKey, byte[] PcdCertificate, out byte[] PiccOptions)
        {
            return IsoGeneralAuthenticateReader(Curve, CARootKeyNo, 0, PcdLTPriKey, PcdCertificate, out PiccOptions);
        }

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
        public long IsoGeneralAuthenticateReader(byte Curve, byte CARootKeyNo, byte SecCARootKeyNo, byte[] PcdLTPriKey, byte[] PcdCertificate, out byte[] PiccOptions)
        {
            return IsoGeneralAuthenticateReader((MifareDuoXEccCurve)Curve, CARootKeyNo, SecCARootKeyNo, PcdLTPriKey, PcdCertificate, out PiccOptions);
        }

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
        public long IsoGeneralAuthenticateReader(MifareDuoXEccCurve Curve, byte CARootKeyNo, byte SecCARootKeyNo, byte[] PcdLTPriKey, byte[] PcdCertificate, out byte[] PiccOptions)
        {
            byte P2 = 0x00;
            P2 |= (byte)(CARootKeyNo & 0x03);
            P2 |= (byte)((SecCARootKeyNo << 4) & 0x30);

            MifareDuoXGeneralAuthenticatePcdOptions PcdOptions = MifareDuoXGeneralAuthenticatePcdOptions.Create(MifareDuoXGeneralAuthenticatePcdOptions.EAuthMethod.PcdUnilateralWithPcdCertificate);

            return IsoGeneralAuthenticate(Curve, P2, PcdOptions, PcdLTPriKey, PcdCertificate, out PiccOptions, out byte[] dummy);
        }

        #endregion

        #region Unilateral reader authentication without reader Certificate

        /*
         * \brief ECC-based unilateral reader authentication, without reader Certificate
         * 
         * \param Curve ECC curve to use
         * \param CARootKeyNo Key number of the (primary) targeted CA root key
         * \param PcdLTPriKey Long-term private key of the PCD
         * \param PiccOptions Options returned by the PICC
         */
        public long IsoGeneralAuthenticateReader(byte Curve, byte CARootKeyNo, byte[] PcdLTPriKey, out byte[] PiccOptions)
        {
            return IsoGeneralAuthenticateReader((MifareDuoXEccCurve)Curve, CARootKeyNo, PcdLTPriKey, out PiccOptions);
        }

        /*
         * \brief ECC-based unilateral reader authentication, without reader Certificate
         * 
         * \param Curve ECC curve to use
         * \param CARootKeyNo Key number of the (primary) targeted CA root key
         * \param PcdLTPriKey Long-term private key of the PCD
         * \param PiccOptions Options returned by the PICC
         */
        public long IsoGeneralAuthenticateReader(MifareDuoXEccCurve Curve, byte CARootKeyNo, byte[] PcdLTPriKey, out byte[] PiccOptions)
        {
            return IsoGeneralAuthenticateReader(Curve, CARootKeyNo, 0, PcdLTPriKey, out PiccOptions);
        }

        /*
         * \brief ECC-based unilateral reader authentication, without reader Certificate
         * 
         * \param Curve ECC curve to use
         * \param CARootKeyNo Key number of the (primary) targeted CA root key
         * \param SecCARootKeyNo If multiple application selection, Key number of the secondary targeted CA root key
         * \param PcdLTPriKey Long-term private key of the PCD
         * \param PiccOptions Options returned by the PICC
         */
        public long IsoGeneralAuthenticateReader(byte Curve, byte CARootKeyNo, byte SecCARootKeyNo, byte[] PcdLTPriKey, out byte[] PiccOptions)
        {
            return IsoGeneralAuthenticateReader((MifareDuoXEccCurve)Curve, CARootKeyNo, SecCARootKeyNo, PcdLTPriKey, out PiccOptions);
        }

        /*
         * \brief ECC-based unilateral reader authentication, without reader Certificate
         * 
         * \param Curve ECC curve to use
         * \param CARootKeyNo Key number of the (primary) targeted CA root key
         * \param SecCARootKeyNo If multiple application selection, Key number of the secondary targeted CA root key
         * \param PcdLTPriKey Long-term private key of the PCD
         * \param PiccOptions Options returned by the PICC
         */
        public long IsoGeneralAuthenticateReader(MifareDuoXEccCurve Curve, byte CARootKeyNo, byte SecCARootKeyNo, byte[] PcdLTPriKey, out byte[] PiccOptions)
        {
            byte P2 = 0x00;
            P2 |= (byte)(CARootKeyNo & 0x03);
            P2 |= (byte)((SecCARootKeyNo << 4) & 0x30);

            MifareDuoXGeneralAuthenticatePcdOptions PcdOptions = MifareDuoXGeneralAuthenticatePcdOptions.Create(MifareDuoXGeneralAuthenticatePcdOptions.EAuthMethod.PcdUnilateralWithoutPcdCertificate);

            return IsoGeneralAuthenticate(Curve, P2, PcdOptions, PcdLTPriKey, null, out PiccOptions, out byte[] dummy);
        }

        #endregion

        #region "Low level" implementation of General Authenticate

        private long IsoGeneralAuthenticate(MifareDuoXEccCurve Curve, byte P2, MifareDuoXGeneralAuthenticatePcdOptions PcdOptions, byte[] PcdLTPriKey, byte[] PcdCertificate, out byte[] PiccOptions, out byte[] PiccCertificate)
        {
            long status;
            PiccOptions = null;
            PiccCertificate = null;

            if (!ECC.GenerateKeyPair(Curve, out byte[] PcdTempPriKey, out byte[] PcdTempPubKey))
                return LibraryError(DesfireLibraryError.ExecutionFailed);

            status = IsoGeneralAuthenticatePart1(P2, PcdOptions.Value, PcdTempPubKey, out byte[] PiccTempPubKey);
            if (status != Success)
                return status;

            status = IsoGeneralAuthenticateInitSession(Curve, PcdOptions, PcdTempPriKey, PiccTempPubKey, PcdLTPriKey, PcdCertificate, out byte[] PcdMessage);
            if (status != Success)
                return status;

            status = IsoGeneralAuthenticatePart2(PcdMessage, out byte[] PiccMessage);
            if (status != Success)
                return status;

            status = IsoGeneralAuthenticateConfirmSession(Curve, PcdTempPubKey, PiccTempPubKey, null, PiccMessage, out PiccOptions, out PiccCertificate);
            if (status != Success)
                return status;

            return Success;
        }

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
        public long IsoGeneralAuthenticateInitSession(byte Curve, byte[] PcdOptions, byte[] PcdTempPriKey, byte[] PiccTempPubKey, byte[] PcdLTPriKey, byte[] PcdCertificate, out byte[] PcdMessage)
        {
            return IsoGeneralAuthenticateInitSession((MifareDuoXEccCurve)Curve, PcdOptions, PcdTempPriKey, PiccTempPubKey, PcdLTPriKey, PcdCertificate, out PcdMessage);
        }

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
        public long IsoGeneralAuthenticateInitSession(MifareDuoXEccCurve Curve, byte[] PcdOptions, byte[] PcdTempPriKey, byte[] PiccTempPubKey, byte[] PcdLTPriKey, byte[] PcdCertificate, out byte[] PcdMessage)
        {
            return IsoGeneralAuthenticateInitSession(Curve, MifareDuoXGeneralAuthenticatePcdOptions.Create(PcdOptions), PcdTempPriKey, PiccTempPubKey, PcdLTPriKey, PcdCertificate, out PcdMessage);
        }

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
        public long IsoGeneralAuthenticateInitSession(MifareDuoXEccCurve Curve, MifareDuoXGeneralAuthenticatePcdOptions PcdOptions, byte[] PcdTempPriKey, byte[] PiccTempPubKey, byte[] PcdLTPriKey, byte[] PcdCertificate, out byte[] PcdMessage)
        {
            PcdMessage = null;
            logger.debug("Importing Ephemeral PCD private key");
            if (!ECC.ImportPrivate(Curve, PcdTempPriKey, out ECPrivateKeyParameters ecPcdTempPriKey))
                return LibraryError(DesfireLibraryError.InvalidKeyValue);
            logger.debug("Importing Long Term PCD private key");
            if (!ECC.ImportPrivate(Curve, PcdLTPriKey, out ECPrivateKeyParameters ecPcdLTPriKey))
                return LibraryError(DesfireLibraryError.InvalidKeyValue);
            logger.debug("Importing Ephemeral PICC public key");
            if (!ECC.ImportPublic(Curve, PiccTempPubKey, out ECPublicKeyParameters ecPiccTempPubKey))
                return LibraryError(DesfireLibraryError.InvalidKeyValue);
            return IsoGeneralAuthenticateInitSession(Curve, PcdOptions, ecPcdTempPriKey, ecPiccTempPubKey, ecPcdLTPriKey, PcdCertificate, out PcdMessage);
        }

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
        public long IsoGeneralAuthenticateInitSession(MifareDuoXEccCurve Curve, MifareDuoXGeneralAuthenticatePcdOptions PcdOptions, ECPrivateKeyParameters ecPcdTempPriKey, ECPublicKeyParameters ecPiccTempPubKey, ECPrivateKeyParameters ecPcdLTPriKey, byte[] PcdCertificate, out byte[] PcdMessage)
        {
            PcdMessage = null;

            logger.trace("IsoGeneralAuthenticateInitSession");

            if (!ECC.PrivateToPublic(Curve, ecPcdTempPriKey, out byte[] PcdTempPubKey))
                return LibraryError(DesfireLibraryError.InvalidKeyValue);
            if (!ECC.GetPublicBytes(ecPiccTempPubKey, out byte[] PiccTempPubKey))
                return LibraryError(DesfireLibraryError.InvalidKeyValue);

            if (!ECC.PrivateToPublic(Curve, ecPcdLTPriKey, out byte[] PcdLTPubKey))
                return LibraryError(DesfireLibraryError.InvalidKeyValue);

            logger.debug("Running ECDH");

            if (logSecrets)
                logger.debug("E.PriA = {0}", BinConvert.ToHex(ecPcdTempPriKey.D.ToByteArray()));

            logger.debug("E.PubA = {0}", BinConvert.ToHex(PcdTempPubKey));
            logger.debug("E.PubB = {0}", BinConvert.ToHex(PiccTempPubKey));

            if (!ECC.Derive(Curve, ecPcdTempPriKey, ecPiccTempPubKey, out byte[] SharedSecret))
                return LibraryError(DesfireLibraryError.ExecutionFailed);

            if (logSecrets)
                logger.debug("SHS = {0}", BinConvert.ToHex(SharedSecret));

            logger.debug("Generating EV2 Session Keys using E.PubA, E.PubB and SHS");

            SessionCryptoContext = new DesfireCryptoContextDuoX(this);
            (SessionCryptoContext as DesfireCryptoContextDuoX).GenerateSessionKeysDuoX(PcdTempPubKey, PiccTempPubKey, SharedSecret);

            byte[] SigAMsg = new byte[] { 0xE0, 0xE0 };
            SigAMsg = BinUtils.Concat(SigAMsg, PcdOptions.GetTLV());
            SigAMsg = BinUtils.Concat(SigAMsg, PcdTempPubKey);
            SigAMsg = BinUtils.Concat(SigAMsg, PiccTempPubKey);

            if (logCrypto)
                logger.debug("               E0E0 || OptA || E.PubA || E.PubB   = {0}", BinConvert.ToHex(SigAMsg));

            if (logCrypto && logSecrets)
                logger.debug("Signing with LT.PriA {0}", BinConvert.ToHex(ecPcdLTPriKey.D.ToByteArray()));
            logger.debug("Signing with LT.PubA {0}", BinConvert.ToHex(PcdLTPubKey));
            if (!ECC.Sign(Curve, ecPcdLTPriKey, SigAMsg, out byte[] SigA))
                return LibraryError(DesfireLibraryError.ExecutionFailed);

            if (logCrypto)
                logger.debug("SigA = ECDSA ( E0E0 || OptA || E.PubA || E.PubB ) = {0}", BinConvert.ToHex(SigA));

            if (true)
            {
                /* Verification */
                if (!ECC.Verify(Curve, PcdLTPubKey, SigAMsg, SigA))
                {
                    logger.error("Internal signature verification failed");
                    return LibraryError(DesfireLibraryError.ExecutionFailed);
                }
            }

            byte[] MsgA = new byte[] { 0xE0, 0xE0 };
            if (PcdCertificate != null)
            {
                logger.debug("CertA:\n{0}", BinConvert.ToHex(PcdCertificate));
                logger.debug("CertA:\n{0}", BinConvert.HexDump(PcdCertificate));
                MsgA = BinUtils.Concat(MsgA, PcdCertificate);
            }
            MsgA = BinUtils.Concat(MsgA, SigA);

            if (logCrypto)
                logger.debug("               E0E0 [ || CertA ] || SigA   = {0}", BinConvert.ToHex(MsgA));

            logger.debug("MsgA={0}", BinConvert.ToHex(MsgA));

            byte[] buffer = BinUtils.Copy(MsgA);
            (SessionCryptoContext as DesfireCryptoContextDuoX).Padd(ref buffer);
            if (logCrypto)
                logger.trace("                                    (padded) {0}", BinConvert.ToHex(buffer));
            (SessionCryptoContext as DesfireCryptoContextDuoX).CipherSendEx(ref buffer, true);
            PcdMessage = BinUtils.Copy(buffer);

            if (logCrypto)
                logger.debug("E ( Kses_enc , E0E0 [ || CertA ] || SigA ) = {0}", BinConvert.ToHex(PcdMessage));

            return Success;
        }

        /*
         * \brief ECC-based mutual or reader-unilateral authentication, Part 1
         * 
         * \param Curve ECC curve to use
         * \param P2 P2 parameter
         * \param PcdOptions Options for the PCD
         * \param PcdTempPubKey Ephemeral public key of the PCD
         * \param PiccTempPubKey Ephemeral public key of the PICC
         */
        public long IsoGeneralAuthenticatePart1(MifareDuoXEccCurve Curve, byte P2, MifareDuoXGeneralAuthenticatePcdOptions PcdOptions, ECPublicKeyParameters ecPcdTempPubKey, out ECPublicKeyParameters ecPiccTempPubKey)
        {
            long status;
            ecPiccTempPubKey = null;

            if (!ECC.GetPublicBytes(ecPcdTempPubKey, out byte[] PcdTempPubKey))
                return LibraryError(DesfireLibraryError.InvalidKeyValue);

            status = IsoGeneralAuthenticatePart1(P2, PcdOptions.Value, PcdTempPubKey, out byte[] PiccTempPubKey);
            if (status != Success)
                return status;

            if (!ECC.ImportPublic(Curve, PiccTempPubKey, out ecPiccTempPubKey))
                return LibraryError(DesfireLibraryError.WrongData);

            return status;
        }

        /*
         * \brief ECC-based mutual or reader-unilateral authentication, Part 1
         * 
         * \param P2 P2 parameter
         * \param PcdOptions Options for the PCD
         * \param PcdTempPubKey Ephemeral public key of the PCD
         * \param PiccTempPubKey Ephemeral public key of the PICC
         */
        public long IsoGeneralAuthenticatePart1(byte P2, byte[] PcdOptions, byte[] PcdTempPubKey, out byte[] PiccTempPubKey)
        {
            long status;

            PiccTempPubKey = null;

            logger.trace("IsoGeneralAuthenticatePart1#1({0:X02},{1},{2})", P2, BinConvert.ToHex(PcdOptions), BinConvert.ToHex(PcdTempPubKey));

            if ((PcdOptions == null) || ((PcdOptions.Length != 2) && (PcdOptions.Length != 4)))
                return LibraryError(DesfireLibraryError.InvalidParameter);
            if ((PcdTempPubKey == null) || (PcdTempPubKey.Length != 65))
                return LibraryError(DesfireLibraryError.InvalidParameter);

            /* Each new Authenticate must invalidate the current authentication status. */
            EndSecureSession();

            /* Assemble TLV structure */
            Asn1Tlv tlvPcdOptions = new Asn1Tlv(0x80, PcdOptions);
            Asn1Tlv tlvPcdTempPubKey = new Asn1Tlv(0x85, PcdTempPubKey);
            Asn1Tlv tlvAuthentificationDataObjects = new Asn1Tlv(0x7C, tlvPcdTempPubKey);

            /* Assemble command data */
            byte[] data_in = new byte[0];
            data_in = BinUtils.Concat(data_in, tlvPcdOptions.Serialize());
            data_in = BinUtils.Concat(data_in, tlvAuthentificationDataObjects.Serialize());

            /* Send the APDU */
            status = IsoApdu(0x00, (byte)DesfireCommand.ISO_GENERAL_AUTHENTICATE, 0x00, P2, data_in, 0x00, out byte[] data_out, out ushort SW);
            if (status != Success)
                return status;

            /* Check the response */
            if ((data_out == null) || (data_out.Length < 2))
                return LibraryError(DesfireLibraryError.WrongLength);
            Asn1Tlv tlvResponse = Asn1Tlv.Deserialize(data_out);
            if (tlvResponse == null)
                return LibraryError(DesfireLibraryError.WrongTLV);
            tlvResponse.DeserializeChildren();

            /* Get PubKey */
            PiccTempPubKey = tlvResponse.FindValue(new byte[] { 0x7C, 0x85 }, true);
            if (PiccTempPubKey == null)
                return LibraryError(DesfireLibraryError.WrongTLV);
            if (PiccTempPubKey.Length != 65)
                return LibraryError(DesfireLibraryError.WrongLength);

            logger.trace("\tPiccTempPubKey={0}", BinConvert.ToHex(PiccTempPubKey));

            /* Success. */
            return Success;
        }

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
        public long IsoGeneralAuthenticateConfirmSession(byte Curve, byte[] PcdTempPubKey, byte[] PiccTempPubKey, byte[] PiccLTPubKey, byte[] PiccMessage, out byte[] PiccOptions, out byte[] PiccCertificate)
        {
            return IsoGeneralAuthenticateConfirmSession((MifareDuoXEccCurve)Curve, PcdTempPubKey, PiccTempPubKey, PiccLTPubKey, PiccMessage, out PiccOptions, out PiccCertificate);
        }

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
        public long IsoGeneralAuthenticateConfirmSession(MifareDuoXEccCurve Curve, byte[] PcdTempPubKey, byte[] PiccTempPubKey, byte[] PiccLTPubKey, byte[] PiccMessage, out byte[] PiccOptions, out byte[] PiccCertificate)
        {
            PiccOptions = null;
            PiccCertificate = null;
            if (!ECC.ImportPublic(Curve, PcdTempPubKey, out ECPublicKeyParameters ecPcdTempPubKey))
                return LibraryError(DesfireLibraryError.InvalidKeyValue);
            if (!ECC.ImportPublic(Curve, PiccTempPubKey, out ECPublicKeyParameters ecPiccTempPubKey))
                return LibraryError(DesfireLibraryError.InvalidKeyValue);
            ECPublicKeyParameters ecPiccLTPubKey = null;
            if (PiccLTPubKey != null)
            {
                if (!ECC.ImportPublic(Curve, PiccLTPubKey, out ecPiccLTPubKey))
                    return LibraryError(DesfireLibraryError.InvalidKeyValue);
            }
            return IsoGeneralAuthenticateConfirmSession(Curve, ecPcdTempPubKey, ecPiccTempPubKey, ecPiccLTPubKey, PiccMessage, out PiccOptions, out PiccCertificate);
        }

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
        public long IsoGeneralAuthenticateConfirmSession(MifareDuoXEccCurve Curve, ECPublicKeyParameters ecPcdTempPubKey, ECPublicKeyParameters ecPiccTempPubKey, ECPublicKeyParameters ecPiccLTPubKey, byte[] PiccMessage, out byte[] PiccOptions, out byte[] PiccCertificate)
        {
            PiccOptions = null;
            PiccCertificate = null;

            logger.trace("IsoGeneralAuthenticateConfirmSession");

            /* Check the session is alive */
            if ((SessionCryptoContext == null) || !(SessionCryptoContext is DesfireCryptoContextDuoX))
                return LibraryError(DesfireLibraryError.WrongSessionState);

            /* Check the parameters */
            if (PiccMessage == null)
                return LibraryError(DesfireLibraryError.InvalidParameter);
            if (ecPcdTempPubKey == null)
                return LibraryError(DesfireLibraryError.InvalidParameter);
            if (ecPiccTempPubKey == null)
                return LibraryError(DesfireLibraryError.InvalidParameter);

            /* Extract the public keys */
            if (!ECC.GetPublicBytes(ecPcdTempPubKey, out byte[] EPubA))
                return LibraryError(DesfireLibraryError.InvalidKeyValue);
            if (!ECC.GetPublicBytes(ecPiccTempPubKey, out byte[] EPubB))
                return LibraryError(DesfireLibraryError.InvalidKeyValue);

            /* Decrypt the message received from the PICC */
            byte[] buffer = BinUtils.Copy(PiccMessage);

            if (logCrypto)
                logger.debug("E ( Kses_enc , E1E1 [ || CertB ] || SigB ) = {0}", BinConvert.ToHex(buffer));

            if ((buffer.Length % 16) != 0) /* AES block size */
                return LibraryError(DesfireLibraryError.WrongLength);
            (SessionCryptoContext as DesfireCryptoContextDuoX).CipherRecvEx(ref buffer, true);

            if (!(SessionCryptoContext as DesfireCryptoContextDuoX).Unpadd(ref buffer))
                return LibraryError(DesfireLibraryError.WrongPadding);

            if (logCrypto)
                logger.debug("               E1E1 [ || CertB ] || SigB   = {0}", BinConvert.ToHex(buffer));

            byte[] MsgB = BinUtils.Copy(buffer);

            logger.debug("MsgB={0}", BinConvert.ToHex(MsgB));

            if (MsgB.Length < 2)
            {
                logger.debug("MsgB is too short to have the header");
                return LibraryError(DesfireLibraryError.WrongLength);
            }

            if ((MsgB[0] != 0xE1) || (MsgB[1] != 0xE1))
            {
                logger.debug("MsgB does not start with E1E1");
                return LibraryError(DesfireLibraryError.WrongData);
            }

            /* Remove the header */
            MsgB = BinUtils.Copy(MsgB, 2, MsgB.Length - 2);

            /* OptionsB is a L,V field */
            byte lenOptionsB = MsgB[0];
            if (MsgB.Length < 1 + lenOptionsB)
            {
                logger.debug("MsgB is too short to hold OptionsB");
                return LibraryError(DesfireLibraryError.WrongLength);
            }
            byte[] OptionsB = BinUtils.Copy(MsgB, 0, 1 + lenOptionsB);
            logger.debug("OptionsB: {0}", BinConvert.ToHex(OptionsB));
            /* Gather PiccOptions, which is only the V part */
            PiccOptions = BinUtils.Copy(MsgB, 1, lenOptionsB);
            /* Remove OptionsB from MsgB */
            MsgB = BinUtils.Copy(MsgB, 1 + lenOptionsB, MsgB.Length - 1 - lenOptionsB);

            if (MsgB.Length == 0)
            {
                /* No PiccCertificate (and no PiccSignature) */
                logger.debug("MsgB is empty after removing OptionsB");
            }
            else
            {
                /* MsgB shall contain CertB and SigB */
                if (MsgB.Length < 64 + 4)
                {
                    logger.debug("MsgB is too short to hold CertB and SigB");
                    return LibraryError(DesfireLibraryError.WrongLength);
                }

                /* SigB is the last 64 bytes of MsgB */
                byte[] SigB = BinUtils.Copy(MsgB, MsgB.Length - 64, 64);
                logger.debug("SigB: {0}", BinConvert.ToHex(SigB));

                /* Remove SigB from MsgB */
                MsgB = BinUtils.Copy(MsgB, 0, MsgB.Length - 64);

                /* Gather CertB */
                PiccCertificate = BinUtils.Copy(MsgB);
                logger.debug("CertB:\n{0}", BinConvert.ToHex(PiccCertificate));
                logger.debug("CertB:\n{0}", BinConvert.HexDump(PiccCertificate));

                /* Now we can verify the signature */
                if (logCrypto)
                    logger.debug("SigB = ECDSA ( E1E1 || OptB || E.PubB || E.PubA ) = {0}", BinConvert.ToHex(SigB));

                /* Try to verify the signature */
                byte[] SigBMsg = new byte[] { 0xE1, 0xE1 };
                SigBMsg = BinUtils.Concat(SigBMsg, OptionsB);
                SigBMsg = BinUtils.Concat(SigBMsg, EPubB);
                SigBMsg = BinUtils.Concat(SigBMsg, EPubA);

                if (logCrypto)
                    logger.debug("               E1E1 || OptB || E.PubB || E.PubA   = {0}", BinConvert.ToHex(SigBMsg));

                /* Verify the signature with the LT public key */
                if (ecPiccLTPubKey != null)
                {
                    logger.debug("Verifying SigB with LT.PubB {0}", BinConvert.ToHex(ecPiccLTPubKey.Q.GetEncoded(false)));
                    logger.debug("SigBMsg={0}", BinConvert.ToHex(SigBMsg));

                    if (!ECC.Verify(Curve, ecPiccLTPubKey, SigBMsg, SigB))
                    {
                        logger.debug("Verify SigB with LT.PubB failed");
                        return LibraryError(DesfireLibraryError.WrongSignature);
                    }

                    logger.debug("PICC signature is OK (LT key)");
                }

                /* Verify the signature with the certificate itself */
                if (PiccCertificate != null)
                {
                    logger.debug("Processing PiccCertificate {0}", BinConvert.ToHex(PiccCertificate));

                    if (!X509CERT.Import(PiccCertificate, out Org.BouncyCastle.X509.X509Certificate x509certificate))
                    {
                        logger.debug("PiccCertificate is invalid");
                        return LibraryError(DesfireLibraryError.WrongData);
                    }
                    if (!X509CERT.GetPublicKey(PiccCertificate, out byte[] CertPubKey))
                    {
                        logger.debug("PiccCertificate has no ECC public key");
                        return LibraryError(DesfireLibraryError.WrongData);
                    }

                    logger.debug("Verifying SigB with CertB.Pub {0}", BinConvert.ToHex(CertPubKey));
                    logger.debug("SigBMsg={0}", BinConvert.ToHex(SigBMsg));

                    if (!ECC.Verify(Curve, CertPubKey, SigBMsg, SigB))
                    {
                        logger.debug("Verify SigB with PiccCertificate failed");
                        return LibraryError(DesfireLibraryError.WrongSignature);
                    }

                    logger.debug("PICC signature is OK (certificate)");
                }
            }

            return Success;
        }

        /*
         * \brief ECC-based mutual or reader-unilateral authentication, Part 2
         * 
         * \param PcdMessage Encrypted and signed PCD Message
         * \param PiccMessage Encrypted and signed PICC Message (to be returned)
         */
        public long IsoGeneralAuthenticatePart2(byte[] PcdMessage, out byte[] PiccMessage)
        {
            long status;

            PiccMessage = null;

            logger.trace("IsoGeneralAuthenticate#2({0})", BinConvert.ToHex(PcdMessage));

            if (PcdMessage == null)
                return LibraryError(DesfireLibraryError.InvalidParameter);

            /* Assemble TLV structure */
            Asn1Tlv tlvPcdEncMessage = new Asn1Tlv(0x86, PcdMessage);
            Asn1Tlv tlvAuthentificationDataObjects = new Asn1Tlv(0x7C, tlvPcdEncMessage);

            /* Assemble command data */
            byte[] data_in = tlvAuthentificationDataObjects.Serialize();

            /* Send the APDU (must be extended, even if data_in is short, because data_out can be long) */
            status = IsoApdu(0x00, (byte)DesfireCommand.ISO_GENERAL_AUTHENTICATE, 0x00, 0x00, data_in, 0x00, out byte[] data_out, out ushort SW, true);
            if (status != Success)
                return status;

            /* Check the response */
            if ((data_out == null) || (data_out.Length < 2))
                return LibraryError(DesfireLibraryError.WrongLength);
            Asn1Tlv tlvResponse = Asn1Tlv.Deserialize(data_out);
            if (tlvResponse == null)
                return LibraryError(DesfireLibraryError.WrongTLV);
            tlvResponse.DeserializeChildren();

            /* Get PiccEncMessage */
            PiccMessage = tlvResponse.FindValue(new byte[] { 0x7C, 0x82 }, true);
            if (PiccMessage == null)
                return LibraryError(DesfireLibraryError.WrongTLV);

            logger.trace("\tPiccEncMessage={0}", BinConvert.ToHex(PiccMessage));

            /* Success. */
            return Success;
        }

        #endregion
    }
}