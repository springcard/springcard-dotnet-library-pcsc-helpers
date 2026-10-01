/*
 * SpringCard DESFire Library (C#)
 * Copyright (c) SpringCard SAS, 2008-2025
 *
 * This file is part of the SpringCard DESFire library.
 * See LICENSE.txt for license details and restrictions.
 *
 */
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Tls.Crypto;
using SpringCard.LibCs;


namespace SpringCard.PCSC.CardHelpers
{
    public partial class Desfire
    {
        #region Asymmetric Key Management
        private long GetKeySettings(byte Option, out byte[] KeySettings)
        {
            logger.trace("GetKeySettings({0:X02})", Option);

            long status;

            KeySettings = null;

            /* Create the info block containing the command code */
            xfer_buffer[INF + 0] = (byte)DesfireCommand.GET_KEY_SETTINGS;
            xfer_buffer[INF + 1] = Option;
            xfer_length = 2;

            status = Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            if (status != Success)
                return status;

            /* Return the requested key settings bytes. */
            KeySettings = BinUtils.Copy(xfer_buffer, 1, xfer_length - 1);

            /* Success */
            return status;
        }

        #endregion



        public long ExportKey(byte Option, byte KeyNumber, out byte[] pbPublicKey)
        {
            long status;

            logger.trace("ExportKey({0:X02})", KeyNumber);

            pbPublicKey = null;

            xfer_buffer[INF + 0] = (byte)DesfireCommand.EXPORT_KEY;
            xfer_buffer[INF + 1] = Option; 
            xfer_buffer[INF + 2] = KeyNumber;
            xfer_length = 3;

            status = Command(65, DesfireCommandFlag.WANTS_OPERATION_OK);
            if (status != Success)
                return status;

            pbPublicKey = BinUtils.Copy(xfer_buffer, INF, 65);

            logger.trace("\tPublic Key: {0}", BinConvert.ToHex(pbPublicKey));

            return status;
        }

        public long ExportKey(byte KeyNumber, out byte[] pbPublicKey)
        {
            /* Targetting KeyID.CARootKey */
            return ExportKey(0x01, KeyNumber, out pbPublicKey);
        }



        #region Echo

        public long CryptoRequestEcho(int length)
        {
            byte[] Data = randomGenerator.Get(length);
            return CryptoRequestEcho(Data);
        }

        public long CryptoRequestEcho(byte[] Data)
        {
            long status;

            logger.trace("Echo({0})", BinConvert.ToHex(Data));

            if (Data == null)
                Data = new byte[0];
            if (Data.Length > 254)
                return LibraryError(DesfireLibraryError.InvalidParameter);

            xfer_length = 0;

            xfer_buffer[xfer_length++] = (byte)DesfireCommand.CRYPTO_REQUEST;
            xfer_buffer[xfer_length++] = 0xFD;

            for (int i = 0; i < Data.Length; i++)
                xfer_buffer[xfer_length++] = Data[i];

            status = Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            if (status != Success)
                return status;

            if (xfer_length != Data.Length + 2)
                return LibraryError(DesfireLibraryError.WrongLength);

            if (xfer_buffer[1] != 0xFD)
                return LibraryError(DesfireLibraryError.WrongTLV);

            for (int i = 0; i < Data.Length; i++)
                if (xfer_buffer[i + 2] != Data[i])
                    return LibraryError(DesfireLibraryError.WrongData);

            /* Success. */
            return Success;
        }

        #endregion

        #region Signature

        private enum ECC_SIGNATURE_OPERATION
        {
            INIT = 0x01,
            UPDATE = 0x02,
            FINAL = 0x03,
            ONE_SHOT_ROW = 0x04,
            ONE_SHOT_HASH = 0x05
        }

        private long CryptoRequestEccSign(ECC_SIGNATURE_OPERATION operation, byte KeyNumber, byte[] Data, out byte[] Signature)
        {
            return CryptoRequestEccSign(operation, 0, KeyNumber, Data, out Signature);
        }

        private long CryptoRequestEccSign(ECC_SIGNATURE_OPERATION operation, byte Algorithm, byte KeyNumber, byte[] Data, out byte[] Signature)
        {
            long status;

            Signature = null;

            logger.trace("EccSignCommand({0},{1},{2},{3})", operation, Algorithm, KeyNumber, BinConvert.ToHex(Data));

            if (Data == null)
                Data = new byte[0];
            if (Data.Length > 0xEA)
                return LibraryError(DesfireLibraryError.InvalidParameter);

            xfer_length = 0;

            xfer_buffer[xfer_length++] = (byte)DesfireCommand.CRYPTO_REQUEST;

            byte[] data = new byte[0];
            data = BinUtils.Concat(data, 0x03); /* Action */
            data = BinUtils.Concat(data, (byte)operation);

            switch (operation)
            {
                case ECC_SIGNATURE_OPERATION.INIT:
                case ECC_SIGNATURE_OPERATION.ONE_SHOT_ROW:
                case ECC_SIGNATURE_OPERATION.ONE_SHOT_HASH:
                    /* Algorithm and KeyNo specified in first block */
                    data = BinUtils.Concat(data, Algorithm);
                    data = BinUtils.Concat(data, KeyNumber);
                break;

                default:
                    /* Algorithm and KeyNo not specified in subsequence blocks */
                break;
            }
            data = BinUtils.Concat(data, 0xF0); /* Input source */
            data = BinUtils.Concat(data, (byte)(Data.Length));
            data = BinUtils.Concat(data, Data);

            if (false)
            {
                /* Encrypt and append the data */
                byte[] cipher = BinUtils.Copy(data);
                SessionCryptoContext.CipherSend(ref cipher);

                for (int i = 0; i < cipher.Length; i++)
                    xfer_buffer[xfer_length++] = cipher[i];
            }
            else
            {
                for (int i = 0; i < data.Length; i++)
                    xfer_buffer[xfer_length++] = data[i];
            }

            status = Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            if (status != Success)
                return status;

            switch (operation)
            {
                case ECC_SIGNATURE_OPERATION.FINAL:
                case ECC_SIGNATURE_OPERATION.ONE_SHOT_ROW:
                case ECC_SIGNATURE_OPERATION.ONE_SHOT_HASH:
                    Signature = BinUtils.Copy(xfer_buffer, 1, xfer_length - 1);

                    if (Signature.Length != 64)
                        return LibraryError(DesfireLibraryError.WrongLength);

                    logger.trace("\tSignature: {0}", BinConvert.ToHex(Signature));
                break;

                default:
                    /* No signature expected... yet */
                break;
            }


            /* Success. */
            return Success;
        }

        private long EccSignInit(byte KeyNumber, byte[] Data)
        {
            return CryptoRequestEccSign(ECC_SIGNATURE_OPERATION.INIT, KeyNumber, Data, out byte[] dummy);
        }

        private long EccSignUpdate(byte[] Data)
        {
            return CryptoRequestEccSign(ECC_SIGNATURE_OPERATION.UPDATE, 0, Data, out byte[] dummy);
        }

        private long EccSignFinal(byte[] Data, out byte[] Signature)
        {
            return CryptoRequestEccSign(ECC_SIGNATURE_OPERATION.FINAL, 0, Data, out Signature);
        }

        private long EccSignSingle(byte KeyNumber, byte[] Data, out byte[] Signature)
        {
            return CryptoRequestEccSign(ECC_SIGNATURE_OPERATION.ONE_SHOT_ROW, KeyNumber, Data, out Signature);
        }

        public long EccSign(byte KeyNumber, byte[] Data, out byte[] Signature)
        {
            long status;

            Signature = null;

            if (Data == null)
                Data = new byte[0];

            if (Data.Length <= 185)
            {
                status = EccSignSingle(KeyNumber, Data, out Signature);
                if (status != Success)
                    return status;
            }
            else
            {
                int offset = 0;

                byte[] DataI = BinUtils.Copy(Data, offset, 185);
                offset += 185;

                status = EccSignInit(KeyNumber, DataI);
                if (status != Success)
                    return status;

                while (offset + 187 < Data.Length)
                {
                    byte[] DataU = BinUtils.Copy(Data, offset, 187);
                    offset += 187;

                    status = EccSignUpdate(DataU);
                    if (status != Success)
                        return status;
                }

                byte[] DataF = BinUtils.Copy(Data, offset, Data.Length - offset);

                status = EccSignFinal(DataF, out Signature);
                if (status != Success)
                    return status;
            }

            return Success;
        }

        public long EccSign(MifareDuoXEccCurve CurveId, byte KeyNumber, byte[] Data, out byte[] Signature, byte[] PublicKey)
        {
            Signature = null;

            if ((PublicKey == null) || (PublicKey.Length != 65))
                return LibraryError(DesfireLibraryError.InvalidParameter);

            long status = EccSign(KeyNumber, Data, out Signature);
            if (status != Success)
                return status;

            if (Desfire.ECC.Verify(CurveId, PublicKey, Data, Signature))
                return Success;

            return LibraryError(DesfireLibraryError.WrongSignature);
        }

        public long EccSignHashed(byte KeyNumber, byte[] Hash, out byte[] Signature)
        {
            Signature = null;

            if ((Hash == null) || (Hash.Length != 32))
                return LibraryError(DesfireLibraryError.InvalidParameter);

            return CryptoRequestEccSign(ECC_SIGNATURE_OPERATION.ONE_SHOT_HASH, KeyNumber, Hash, out Signature);
        }

        #endregion
    }
}


