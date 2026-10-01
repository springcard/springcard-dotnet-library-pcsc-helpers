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
        /*
         * \brief ECC-based card authentication
         *
         * \param Curve ECC curve to use
         * \param PrivateKeyNo Private key number
         * \param PcdOptions Options to send to the PICC (can be null)
         * \param PiccLTPubKey Long term PICC public key, to be used to verify the PICC signature
         */
        public long IsoInternalAuthenticate(byte Curve, byte PrivateKeyNo, byte[] PcdOptions, byte[] PiccLTPubKey)
        {
            return IsoInternalAuthenticate((MifareDuoXEccCurve)Curve, PrivateKeyNo, PcdOptions, PiccLTPubKey);
        }

        /*
         * \brief ECC-based card authentication
         *
         * \param Curve ECC curve to use
         * \param PrivateKeyNo Private key number
         * \param PcdOptions Options to send to the PICC (can be null)
         * \param PiccLTPubKey Long term PICC public key, to be used to verify the PICC signature
         */
        public long IsoInternalAuthenticate(MifareDuoXEccCurve Curve, byte PrivateKeyNo, byte[] PcdOptions, byte[] PiccLTPubKey)
        {
            ECPublicKeyParameters ecPiccLTPubKey = null;
            if (PiccLTPubKey != null)
                if (!ECC.ImportPublic(Curve, PiccLTPubKey, out ecPiccLTPubKey))
                    return LibraryError(DesfireLibraryError.InvalidKeyValue);
            return IsoInternalAuthenticate(Curve, PrivateKeyNo, PcdOptions, ecPiccLTPubKey);
        }

        /*
         * \brief ECC-based card authentication
         *
         * \param Curve ECC curve to use
         * \param PrivateKeyNo Private key number
         * \param PcdOptions Options to send to the PICC (can be null)
         * \param PiccLTPubKey Long term PICC public key, to be used to verify the PICC signature
         */
        public long IsoInternalAuthenticate(MifareDuoXEccCurve Curve, byte PrivateKeyNo, byte[] PcdOptions, ECPublicKeyParameters ecPiccLTPubKey)
        {
            long status;

            status = IsoInternalAuthenticate(Curve, PrivateKeyNo, PcdOptions, out byte[] Challenge, out byte[] PiccSignature);
            if (status != Success)
                return status;

            /* Verify the signature with the LT public key */
            if (ecPiccLTPubKey != null)
            {
                if (logCrypto)
                    logger.debug("Verifying SigB with LT.PubB {0}", BinConvert.ToHex(ecPiccLTPubKey.Q.GetEncoded(false)));

                if (!ECC.Verify(Curve, ecPiccLTPubKey, Challenge, PiccSignature))
                {
                    logger.debug("Verify SigB with LT.PubB failed");
                    return LibraryError(DesfireLibraryError.WrongSignature);
                }
                else
                {
                    logger.debug("PICC signature is OK");
                }
            }

            return Success;
        }

        /*
         * \brief ECC-based card authentication
         *
         * \param Curve ECC curve to use
         * \param PrivateKeyNo Private key number
         * \param PcdOptions Options to send to the PICC (can be null)
         * \param Challenge Complete challenge (F0F0 || OptA || RndB || RndA) to be verified
         * \param PiccSignature PICC signature to be verified
         */
        public long IsoInternalAuthenticate(byte Curve, byte PrivateKeyNo, byte[] PcdOptions, out byte[] Challenge, out byte[] PiccSignature)
        {
            return IsoInternalAuthenticate((MifareDuoXEccCurve)Curve, PrivateKeyNo, PcdOptions, out Challenge, out PiccSignature);
        }

        /*
         * \brief ECC-based card authentication
         *
         * \param Curve ECC curve to use
         * \param PrivateKeyNo Private key number
         * \param PcdOptions Options to send to the PICC (can be null)
         * \param Challenge Complete challenge (F0F0 || OptA || RndB || RndA) to be verified
         * \param PiccSignature PICC signature to be verified
         */
        public long IsoInternalAuthenticate(MifareDuoXEccCurve Curve, byte PrivateKeyNo, byte[] PcdOptions, out byte[] Challenge, out byte[] PiccSignature)
        {
            long status;

            Challenge = null;

            byte[] PcdChallenge = randomGenerator.Get(16);

            status = IsoInternalAuthenticate(PrivateKeyNo, PcdOptions, PcdChallenge, out byte[] PiccChallenge, out PiccSignature);
            if (status != Success)
                return status;

            /* Check the response */
            logger.debug("SigB = ECDSA ( F0F0 || OptA || RndB || RndA ) = {0}", BinConvert.ToHex(PiccSignature));

            Challenge = new byte[] { 0xF0, 0xF0 };

            if (PcdOptions != null)
            {
                Challenge = BinUtils.Concat(Challenge, 0x80);
                Challenge = BinUtils.Concat(Challenge, (byte)PcdOptions.Length);
                Challenge = BinUtils.Concat(Challenge, PcdOptions);
            }

            Challenge = BinUtils.Concat(Challenge, PiccChallenge);
            Challenge = BinUtils.Concat(Challenge, PcdChallenge);

            logger.debug("               F0F0 || OptA || RndB || RndA   = {0}", BinConvert.ToHex(Challenge));

            return Success;
        }

        /*
         * \brief ECC-based card authentication
         *
         * \param PrivateKeyNo Private key number
         * \param PcdOptions Options to send to the PICC (can be null)
         * \param PcdChallenge Random number of the PCD
         * \param PiccChallenge Random number of the PICC
         * \param PiccSignature PICC signature to be verified
         */
        public long IsoInternalAuthenticate(byte PrivateKeyNo, byte[] PcdOptions, byte[] PcdChallenge, out byte[] PiccChallenge, out byte[] PiccSignature)
        {
            long status;

            PiccChallenge = null;
            PiccSignature = null;

            logger.trace("IsoInternalAuthenticate({0:X02},{1},{2})", PrivateKeyNo, BinConvert.ToHex(PcdOptions), BinConvert.ToHex(PcdChallenge));

            if ((PcdOptions != null) && (PcdOptions.Length > 0xE8))
                return LibraryError(DesfireLibraryError.InvalidParameter);
            if ((PcdChallenge == null) || (PcdChallenge.Length != 16))
                return LibraryError(DesfireLibraryError.InvalidParameter);

            /* Assemble TLV structure */
            Asn1Tlv tlvPcdOptions = null;
            if (PcdOptions != null)
                tlvPcdOptions = new Asn1Tlv(0x80, PcdOptions);
            Asn1Tlv tlvPcdChallenge = new Asn1Tlv(0x81, PcdChallenge);
            Asn1Tlv tlvAuthentificationDataObjects = new Asn1Tlv(0x7C, tlvPcdChallenge);

            /* Assemble command data */
            byte[] data_in = new byte[0];
            if (tlvPcdOptions != null)
                data_in = BinUtils.Concat(data_in, tlvPcdOptions.Serialize());
            data_in = BinUtils.Concat(data_in, tlvAuthentificationDataObjects.Serialize());

            /* Send the APDU */
            status = IsoApdu(0x00, (byte)DesfireCommand.ISO_INTERNAL_AUTHENTICATE, 0x00, PrivateKeyNo, data_in, 0x00, out byte[] data_out, out ushort SW);
            if (status != Success)
                return status;

            /* Check the response */
            if ((data_out == null) || (data_out.Length < 2))
                return LibraryError(DesfireLibraryError.WrongLength);
            Asn1Tlv tlvResponse = Asn1Tlv.Deserialize(data_out);
            if (tlvResponse == null)
                return LibraryError(DesfireLibraryError.WrongTLV);
            tlvResponse.DeserializeChildren();

            /* Get RndB */
            PiccChallenge = tlvResponse.FindValue(new byte[] { 0x7C, 0x81 }, true);
            if (PiccChallenge == null)
                return LibraryError(DesfireLibraryError.WrongTLV);
            if (PiccChallenge.Length != 16)
                return LibraryError(DesfireLibraryError.WrongLength);

            logger.trace("\tPiccChallenge={0}", BinConvert.ToHex(PiccChallenge));

            /* Get SigB */
            PiccSignature = tlvResponse.FindValue(new byte[] { 0x7C, 0x82 }, true);
            if (PiccSignature == null)
                return LibraryError(DesfireLibraryError.WrongTLV);
            if (PiccSignature.Length != 64)
                return LibraryError(DesfireLibraryError.WrongLength);

            logger.trace("\tPiccSignature={0}", BinConvert.ToHex(PiccSignature));

            /* Success. */
            return Success;
        }
    }
}

