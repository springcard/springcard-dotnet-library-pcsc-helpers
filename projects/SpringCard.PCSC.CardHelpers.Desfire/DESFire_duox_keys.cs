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
        /**
         * \brief Information regarding a Key pair stored in the PICC
         */
        public struct DesfirePrivateKeyInfo
        {
            public byte KeyNumber;
            public byte CurveId;
            public ushort KeyPolicy;
            public byte WriteAccess;
            public uint KeyUsageCtrlLimit;
            public uint KeyUsageCtrlValue;

            public override string ToString()
            {
                return string.Format("{0:X02} Curve={1:X02} Policy={2:X04} WriteAccess={3:X02} KUC={4}/{5}",
                    KeyNumber,
                    CurveId,
                    KeyPolicy,
                    WriteAccess,
                    KeyUsageCtrlValue,
                    KeyUsageCtrlLimit);
            }
        }

        /**
         * \brief Get the list of private keys stored in the PICC
         *
         * \param PrivateKeyList List of private keys
         */
        public long GetPrivateKeyList(out DesfirePrivateKeyInfo[] PrivateKeyList)
        {
            long status;

            PrivateKeyList = null;

            status = GetKeySettings(0x01, out byte[] KeySettings);
            if (status != Success)
                return status;

            if ((KeySettings == null) || (KeySettings.Length < 1))
                return LibraryError(DesfireLibraryError.WrongLength);

            byte count = KeySettings[0];
            if (KeySettings.Length != 1 + 13 * count)
                return LibraryError(DesfireLibraryError.WrongLength);

            PrivateKeyList = new DesfirePrivateKeyInfo[count];

            int offset = 1;
            for (int i = 0; i < count; i++)
            {
                PrivateKeyList[i].KeyNumber = KeySettings[offset++];
                PrivateKeyList[i].CurveId = KeySettings[offset++];
                PrivateKeyList[i].KeyPolicy = 0;
                PrivateKeyList[i].KeyPolicy |= KeySettings[offset++];
                PrivateKeyList[i].KeyPolicy |= (ushort)(KeySettings[offset++] << 8);
                PrivateKeyList[i].WriteAccess = KeySettings[offset++];
                PrivateKeyList[i].KeyUsageCtrlLimit = 0;
                PrivateKeyList[i].KeyUsageCtrlLimit |= KeySettings[offset++];
                PrivateKeyList[i].KeyUsageCtrlLimit |= (uint)(KeySettings[offset++] << 8);
                PrivateKeyList[i].KeyUsageCtrlLimit |= (uint)(KeySettings[offset++] << 16);
                PrivateKeyList[i].KeyUsageCtrlLimit |= (uint)(KeySettings[offset++] << 24);
                PrivateKeyList[i].KeyUsageCtrlValue = 0;
                PrivateKeyList[i].KeyUsageCtrlValue |= KeySettings[offset++];
                PrivateKeyList[i].KeyUsageCtrlValue |= (uint)(KeySettings[offset++] << 8);
                PrivateKeyList[i].KeyUsageCtrlValue |= (uint)(KeySettings[offset++] << 16);
                PrivateKeyList[i].KeyUsageCtrlValue |= (uint)(KeySettings[offset++] << 24);

                logger.trace("\t{0:X02}={1:X02},{2:X04},{3:X02},{4:X08},{5:X08}",
                    PrivateKeyList[i].KeyNumber,
                    PrivateKeyList[i].CurveId,
                    PrivateKeyList[i].KeyPolicy,
                    PrivateKeyList[i].WriteAccess,
                    PrivateKeyList[i].KeyUsageCtrlLimit,
                    PrivateKeyList[i].KeyUsageCtrlValue);
            }

            return status;
        }

        #region ManageKeyPair

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
        public long GenerateKeyPair(byte KeyNumber, byte CurveId, ushort KeyPolicy, byte WriteAccess, ulong KucLimit, out byte[] PublicKey)
        {
            return ManageKeyPair(KeyNumber, 0x00, CurveId, KeyPolicy, WriteAccess, KucLimit, null, out PublicKey);
        }

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
        public long GenerateKeyPair(byte KeyNumber, MifareDuoXEccCurve CurveId, MifareDuoXKeyPairPolicy KeyPolicy, MifareDuoXAccessRights WriteAccess, ulong KucLimit, out byte[] PublicKey)
        {
            return ManageKeyPair(KeyNumber, 0x00, CurveId, KeyPolicy, WriteAccess, KucLimit, null, out PublicKey);
        }

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

        public long GenerateKeyPair(byte KeyNumber, MifareDuoXEccCurve CurveId, MifareDuoXKeyPairPolicy KeyPolicy, MifareDuoXAccessRights WriteAccess, ulong KucLimit, out ECPublicKeyParameters PublicKey)
        {
            return ManageKeyPair(KeyNumber, 0x00, CurveId, KeyPolicy, WriteAccess, KucLimit, null, out PublicKey);
        }

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
        public long ImportPrivateKey(byte KeyNumber, byte CurveId, ushort KeyPolicy, byte WriteAccess, ulong KucLimit, byte[] PrivateKey)
        {
            return ManageKeyPair(KeyNumber, 0x01, CurveId, KeyPolicy, WriteAccess, KucLimit, PrivateKey, out byte[] dummy);
        }

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

        public long ImportPrivateKey(byte KeyNumber, MifareDuoXEccCurve CurveId, MifareDuoXKeyPairPolicy KeyPolicy, MifareDuoXAccessRights WriteAccess, ulong KucLimit, byte[] PrivateKey)
        {
            return ManageKeyPair(KeyNumber, 0x01, CurveId, KeyPolicy, WriteAccess, KucLimit, PrivateKey, out byte[] dummy);
        }

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
        public long ImportPrivateKey(byte KeyNumber, MifareDuoXEccCurve CurveId, MifareDuoXKeyPairPolicy KeyPolicy, MifareDuoXAccessRights WriteAccess, ulong KucLimit, ECPrivateKeyParameters PrivateKey)
        {
            return ManageKeyPair(KeyNumber, 0x01, CurveId, KeyPolicy, WriteAccess, KucLimit, PrivateKey, out ECPublicKeyParameters dummy);
        }

        /**
         * \brief Update the metadata of a key pair
         * 
         * \param KeyNumber Key number (0x00 to 0x1F)
         * \param CurveId Curve ID (see MifareDuoXEccCurve)
         * \param KeyPolicy Key policy (see MifareDuoXKeyPairPolicy)
         * \param WriteAccess Write access rights (see MifareDuoXAccessRights)
         * \param KucLimit Key usage control limit
         */
        public long UpdateKeyPairMetaData(byte KeyNumber, byte CurveId, ushort KeyPolicy, byte WriteAccess, ulong KucLimit)
        {
            return ManageKeyPair(KeyNumber, 0x02, CurveId, KeyPolicy, WriteAccess, KucLimit, null, out byte[] dummy);
        }

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
        public long ManageKeyPair(byte KeyNumber, byte Option, MifareDuoXEccCurve CurveId, MifareDuoXKeyPairPolicy KeyPolicy, MifareDuoXAccessRights WriteAccess, ulong KucLimit, ECPrivateKeyParameters PrivateKey, out ECPublicKeyParameters PublicKey)
        {
            long status;
            byte[] abPublicKey;
            PublicKey = null;

            if (PrivateKey != null)
            {
                if (!ECC.GetPrivateBytes(CurveId, PrivateKey, out byte[] abPrivateKey))
                    return LibraryError(DesfireLibraryError.InvalidKeyValue);
                status = ManageKeyPair(KeyNumber, Option, CurveId, KeyPolicy, WriteAccess, KucLimit, abPrivateKey, out abPublicKey);
            }
            else
            {
                status = ManageKeyPair(KeyNumber, Option, CurveId, KeyPolicy, WriteAccess, KucLimit, null, out abPublicKey);
            }

            if ((status == Success) && (abPublicKey != null))
            {
                ECC.ImportPublic(CurveId, abPublicKey, out PublicKey);
            }

            return status;
        }

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
        public long ManageKeyPair(byte KeyNumber, byte Option, MifareDuoXEccCurve CurveId, MifareDuoXKeyPairPolicy KeyPolicy, MifareDuoXAccessRights WriteAccess, ulong KucLimit, byte[] PrivateKey, out byte[] PublicKey)
        {
            return ManageKeyPair(KeyNumber, Option, (byte)CurveId, (ushort)KeyPolicy, WriteAccess.Value, KucLimit, PrivateKey, out PublicKey);
        }

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
        public long ManageKeyPair(byte KeyNumber, byte Option, byte CurveId, ushort KeyPolicy, byte WriteAccess, ulong KucLimit, byte[] PrivateKey, out byte[] PublicKey)
        {
            long status;

            if (PrivateKey == null)
            {
                logger.trace("ManageKeyPair({0:X02},{1:X02},{2:X02},{3:X04},{4:X02},{5:X08})",
                    KeyNumber,
                    Option,
                    CurveId,
                    KeyPolicy,
                    WriteAccess,
                    KucLimit);
            }
            else
            {
                logger.trace("ManageKeyPair({0:X02},{1:X02},{2:X02},{3:X04},{4:X02},{5:X08},...)",
                    KeyNumber,
                    Option,
                    CurveId,
                    KeyPolicy,
                    WriteAccess,
                    KucLimit);
            }

            PublicKey = null;

            if ((PrivateKey != null) && (PrivateKey.Length != 32))
                return LibraryError(DesfireLibraryError.WrongResponseToChallenge);

            xfer_length = 0;

            xfer_buffer[xfer_length++] = (byte)DesfireCommand.MANAGE_KEY_PAIR;
            xfer_buffer[xfer_length++] = KeyNumber;
            xfer_buffer[xfer_length++] = Option;
            xfer_buffer[xfer_length++] = CurveId;
            xfer_buffer[xfer_length++] = (byte)(KeyPolicy);
            xfer_buffer[xfer_length++] = (byte)(KeyPolicy >> 8);
            xfer_buffer[xfer_length++] = WriteAccess;
            xfer_buffer[xfer_length++] = (byte)(KucLimit);
            xfer_buffer[xfer_length++] = (byte)(KucLimit >> 8);
            xfer_buffer[xfer_length++] = (byte)(KucLimit >> 16);
            xfer_buffer[xfer_length++] = (byte)(KucLimit >> 24);


            if (PrivateKey != null)
            {
                /* Remember the length of the header */
                int header_length = xfer_length;

                /* Append the private key */
                for (int i = 0; i < PrivateKey.Length; i++)
                    xfer_buffer[xfer_length++] = PrivateKey[i];

                /* Cipher the private key */
                Xfer_Padd_CipherSend(header_length);
            }

            /* Be careful: it seems we don't have to increment the counter??? */
            status = Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            if (status != Success)
                return status;

            int length = xfer_length - 1;
            byte[] buffer = BinUtils.Copy(xfer_buffer, 1, length);

            SessionCryptoContext.CipherRecv(ref buffer, ref length);

            while (length > 0)
            {
                length--;
                if (buffer[length] == 0x80)
                {
                    break;
                }
                if (buffer[length] != 0x00)
                {
                    return LibraryError(DesfireLibraryError.WrongPadding);
                }
            }

            if (length > 0)
            {
                PublicKey = BinUtils.Copy(buffer, 0, length);
            }

            return status;
        }

        #endregion
    }
}
