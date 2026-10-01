/*
 * SpringCard DESFire Library (C#)
 * Copyright (c) SpringCard SAS, 2008-2025
 *
 * This file is part of the SpringCard DESFire library.
 * See LICENSE.txt for license details and restrictions.
 *
 */
using System;
using Org.BouncyCastle.Crypto.Parameters;
using SpringCard.LibCs;
using SpringCard.LibCs.Crypto;

namespace SpringCard.PCSC.CardHelpers
{
    public partial class Desfire
    {
        /**
         * \brief Information regarding a CA root key stored in the PICC
         */
        public struct DesfireCARootKeyInfo
        {
            public byte KeyNumber;
            public byte CurveId;
            public ushort KeyPolicy;
            public byte WriteAccess;
            public byte ReadAccess;
            public uint CrlAid;
            public byte CrlFileId;

            public byte WriteKeyNo { get { return (byte)(WriteAccess & 0x0F); } }
            public DesfireCommMode WriteCommMode { get { return (DesfireCommMode)((WriteAccess >> 4) & 0x03); } }
            public byte ReadKeyNo { get { return (byte)(ReadAccess & 0x0F); } }
            public DesfireCommMode ReadCommMode { get { return (DesfireCommMode)((ReadAccess >> 4) & 0x03); } }

            public override string ToString()
            {
                return string.Format("{0:X02} Curve={1:X02} Policy={2:X04} WriteAccess={3:X02} ReadAccess={4:X02} CrlAid={5:X06} CrlFileId={6:X02}",
                    KeyNumber,
                    CurveId,
                    KeyPolicy,
                    WriteAccess,
                    ReadAccess,
                    CrlAid,
                    CrlFileId);
            }
        }

        /**
         * \brief Get the list of CA root keys known by the PICC
         *
         * \param CARootKeyList List of CA root keys
         */
        public long GetCARootKeyList(out DesfireCARootKeyInfo[] CARootKeyList)
        {
            long status;

            CARootKeyList = null;

            status = GetKeySettings(0x02, out byte[] KeySettings);
            if (status != Success)
                return status;

            if ((KeySettings == null) || (KeySettings.Length < 1))
                return LibraryError(DesfireLibraryError.WrongLength);

            byte count = KeySettings[0];
            if (KeySettings.Length != 1 + 10 * count)
                return LibraryError(DesfireLibraryError.WrongLength);

            CARootKeyList = new DesfireCARootKeyInfo[count];

            int offset = 1;
            for (int i = 0; i < count; i++)
            {
                CARootKeyList[i].KeyNumber = KeySettings[offset++];
                CARootKeyList[i].CurveId = KeySettings[offset++];
                CARootKeyList[i].KeyPolicy = 0;
                CARootKeyList[i].KeyPolicy |= KeySettings[offset++];
                CARootKeyList[i].KeyPolicy |= (ushort)(KeySettings[offset++] << 8);
                CARootKeyList[i].WriteAccess = KeySettings[offset++];
                CARootKeyList[i].ReadAccess = KeySettings[offset++];
                CARootKeyList[i].CrlFileId = KeySettings[offset++];
                CARootKeyList[i].CrlAid = 0;
                CARootKeyList[i].CrlAid |= KeySettings[offset++];
                CARootKeyList[i].CrlAid |= (uint)(KeySettings[offset++] << 8);
                CARootKeyList[i].CrlAid |= (uint)(KeySettings[offset++] << 16);

                logger.trace("\t{0:X02}={1:X02},{2:X04},{3:X02},{4:X02},{5:X02},{6:X06}",
                    CARootKeyList[i].KeyNumber,
                    CARootKeyList[i].CurveId,
                    CARootKeyList[i].KeyPolicy,
                    CARootKeyList[i].WriteAccess,
                    CARootKeyList[i].ReadAccess,
                    CARootKeyList[i].CrlFileId,
                    CARootKeyList[i].CrlAid);
            }

            return status;
        }

        #region ManageCARootKey

        /*
         * \brief Manage the CA Root Key
         * 
         * Mode 1.A: high-level API, no CRL, no issuer
         */
        public long ManageCARootKey(byte KeyNumber, MifareDuoXEccCurve CurveId, MifareDuoXCARootKeyAccessRights AccessRights, MifareDuoXAccessRights WriteAccess, MifareDuoXAccessRights ReadAccess, ECPublicKeyParameters PublicKey, DesfireCommMode CommMode)
        {
            if (!ECC.GetPublicBytes(PublicKey, out byte[] abPublicKey))
                return LibraryError(DesfireLibraryError.InvalidKeyValue);
            return ManageCARootKey(KeyNumber, CurveId, AccessRights, WriteAccess, ReadAccess, abPublicKey, CommMode); /* Call 1.B */
        }

        /*
         * \brief Manage the CA Root Key
         * 
         * Mode 1.B: high-level API, no CRL, no issuer
         */
        public long ManageCARootKey(byte KeyNumber, MifareDuoXEccCurve CurveId, MifareDuoXCARootKeyAccessRights AccessRights, MifareDuoXAccessRights WriteAccess, MifareDuoXAccessRights ReadAccess, byte[] PublicKey, DesfireCommMode CommMode)
        {
            return ManageCARootKey(KeyNumber, (byte)CurveId, AccessRights.Value, WriteAccess.Value, ReadAccess.Value, PublicKey, (byte)CommMode); /* Call 1.C */
        }

        /*
         * \brief Manage the CA Root Key
         * 
         * Mode 1.C: no CRL, no issuer
         */
        public long ManageCARootKey(byte KeyNumber, byte CurveId, ushort AccessRights, byte WriteAccess, byte ReadAccess, byte[] PublicKey, byte CommMode)
        {
            return ManageCARootKey(KeyNumber, CurveId, AccessRights, WriteAccess, ReadAccess, false, 0, 0, PublicKey, null, CommMode); /* Call 5 */
        }

        /*
         * \brief Manage the CA Root Key
         * 
         * Mode 2.A: high-level API, no CRL, with issuer
         */
        public long ManageCARootKey(byte KeyNumber, MifareDuoXEccCurve CurveId, MifareDuoXCARootKeyAccessRights AccessRights, MifareDuoXAccessRights WriteAccess, MifareDuoXAccessRights ReadAccess, ECPublicKeyParameters PublicKey, byte[] Issuer, DesfireCommMode CommMode)
        {
            if (!ECC.GetPublicBytes(PublicKey, out byte[] abPublicKey))
                return LibraryError(DesfireLibraryError.InvalidKeyValue);
            return ManageCARootKey(KeyNumber, CurveId, AccessRights, WriteAccess, ReadAccess, abPublicKey, Issuer, CommMode); /* Call 2.B */
        }

        /*
         * \brief Manage the CA Root Key
         * 
         * Mode 2.B: high-level API, no CRL, with issuer
         */
        public long ManageCARootKey(byte KeyNumber, MifareDuoXEccCurve CurveId, MifareDuoXCARootKeyAccessRights AccessRights, MifareDuoXAccessRights WriteAccess, MifareDuoXAccessRights ReadAccess, byte[] PublicKey, byte[] Issuer, DesfireCommMode CommMode)
        {
            return ManageCARootKey(KeyNumber, (byte)CurveId, AccessRights.Value, WriteAccess.Value, ReadAccess.Value, PublicKey, Issuer, (byte)CommMode); /* Call 2.C */
        }

        /*
         * \brief Manage the CA Root Key
         * 
         * Mode 2.C: no CRL, with issuer
         */
        public long ManageCARootKey(byte KeyNumber, byte CurveId, ushort AccessRights, byte WriteAccess, byte ReadAccess, byte[] PublicKey, byte[] Issuer, byte CommMode)
        {
            return ManageCARootKey(KeyNumber, CurveId, AccessRights, WriteAccess, ReadAccess, false, 0, 0, PublicKey, Issuer, CommMode); /* Call 5 */
        }

        /*
         * \brief Manage the CA Root Key
         * 
         * Version 3.A: high-level API, with CRL, no issuer
         */
        public long ManageCARootKey(byte KeyNumber, MifareDuoXEccCurve CurveId, MifareDuoXCARootKeyAccessRights AccessRights, MifareDuoXAccessRights WriteAccess, MifareDuoXAccessRights ReadAccess, byte CrlFileId, uint CrlAid, ECPublicKeyParameters PublicKey, DesfireCommMode CommMode)
        {
            if (!ECC.GetPublicBytes(PublicKey, out byte[] abPublicKey))
                return LibraryError(DesfireLibraryError.InvalidKeyValue);
            return ManageCARootKey(KeyNumber, CurveId, AccessRights, WriteAccess, ReadAccess, CrlFileId, CrlAid, abPublicKey, CommMode); /* Call 3.B */
        }

        /*
         * \brief Manage the CA Root Key
         * 
         * Version 3.B: high-level API, with CRL, no issuer
         */
        public long ManageCARootKey(byte KeyNumber, MifareDuoXEccCurve CurveId, MifareDuoXCARootKeyAccessRights AccessRights, MifareDuoXAccessRights WriteAccess, MifareDuoXAccessRights ReadAccess, byte CrlFileId, uint CrlAid, byte[] PublicKey, DesfireCommMode CommMode)
        {
            return ManageCARootKey(KeyNumber, (byte)CurveId, AccessRights.Value, WriteAccess.Value, ReadAccess.Value, CrlFileId, CrlAid, PublicKey, (byte)CommMode); /* Call 3.C */
        }

        /*
         * \brief Manage the CA Root Key
         * 
         * Version 3.C: with CRL, no issuer
         */
        public long ManageCARootKey(byte KeyNumber, byte CurveId, ushort AccessRights, byte WriteAccess, byte ReadAccess, byte CrlFileId, uint CrlAid, byte[] PublicKey, byte CommMode)
        {
            return ManageCARootKey(KeyNumber, CurveId, AccessRights, WriteAccess, ReadAccess, true, CrlFileId, CrlAid, PublicKey, null, CommMode); /* Call 5 */
        }

        /*
         * \brief Manage the CA Root Key
         * 
         * Version 4.A: high-level API, with CRL, with issuer
         */
        public long ManageCARootKey(byte KeyNumber, MifareDuoXEccCurve CurveId, MifareDuoXCARootKeyAccessRights AccessRights, MifareDuoXAccessRights WriteAccess, MifareDuoXAccessRights ReadAccess, byte CrlFileId, uint CrlAid, ECPublicKeyParameters PublicKey, byte[] Issuer, DesfireCommMode CommMode)
        {
            if (!ECC.GetPublicBytes(PublicKey, out byte[] abPublicKey))
                return LibraryError(DesfireLibraryError.InvalidKeyValue);
            return ManageCARootKey(KeyNumber, CurveId, AccessRights, WriteAccess, ReadAccess, CrlFileId, CrlAid, abPublicKey, Issuer, CommMode); /* Call 4.B */
        }

        /*
         * \brief Manage the CA Root Key
         * 
         * Version 4.B: high-level API, with CRL, with issuer
         */
        public long ManageCARootKey(byte KeyNumber, MifareDuoXEccCurve CurveId, MifareDuoXCARootKeyAccessRights AccessRights, MifareDuoXAccessRights WriteAccess, MifareDuoXAccessRights ReadAccess, byte CrlFileId, uint CrlAid, byte[] PublicKey, byte[] Issuer, DesfireCommMode CommMode)
        {
            return ManageCARootKey(KeyNumber, (byte)CurveId, AccessRights.Value, WriteAccess.Value, ReadAccess.Value, CrlFileId, CrlAid, PublicKey, Issuer, (byte)CommMode); /* Call 4.C */
        }

        /*
         * \brief Manage the CA Root Key
         * 
         * Version 4.C: with CRL, with issuer
         */
        public long ManageCARootKey(byte KeyNumber, byte CurveId, ushort AccessRights, byte WriteAccess, byte ReadAccess, byte CrlFileId, uint CrlAid, byte[] PublicKey, byte[] Issuer, byte CommMode)
        {
            return ManageCARootKey(KeyNumber, CurveId, AccessRights, WriteAccess, ReadAccess, true, CrlFileId, CrlAid, PublicKey, Issuer, CommMode); /* Call 5 */
        }

        /*
         * \brief Manage the CA Root Key
         * 
         * Version 5
         */
        public long ManageCARootKey(byte KeyNumber, byte CurveId, ushort AccessRights, byte WriteAccess, byte ReadAccess, bool CrlEnabled, byte CrlFileId, uint CrlAid, byte[] PublicKey, byte[] Issuer, byte CommMode)
        {
            long status;

            logger.trace("ManageCARootKey({0:X02},{1:X02},{2:X04},{3:X02},{4:X02},{5},{6:X02},{7:X06},{8},{9})",
                KeyNumber,
                CurveId,
                AccessRights,
                WriteAccess,
                ReadAccess,
                CrlEnabled.ToString().ToLower(),
                CrlFileId,
                CrlAid,
                BinConvert.ToHex(PublicKey),
                BinConvert.ToHex(Issuer));

            if ((PublicKey == null) || (PublicKey.Length != 65))
            {
                if (PublicKey != null)
                    logger.error("Size of public key is {0} (should be 65)", PublicKey.Length);
                return LibraryError(DesfireLibraryError.WrongResponseToChallenge);
            }
            if ((Issuer != null) && (Issuer.Length > 0xFF))
                return LibraryError(DesfireLibraryError.InvalidParameter);

            xfer_length = 0;

            xfer_buffer[xfer_length++] = (byte)DesfireCommand.MANAGE_CA_ROOT_KEY;
            xfer_buffer[xfer_length++] = KeyNumber;
            xfer_buffer[xfer_length++] = CurveId;
            xfer_buffer[xfer_length++] = (byte)(AccessRights);
            xfer_buffer[xfer_length++] = (byte)(AccessRights >> 8);
            xfer_buffer[xfer_length++] = WriteAccess;
            xfer_buffer[xfer_length++] = ReadAccess;
            if (CrlEnabled)
            {
                xfer_buffer[xfer_length++] = (byte)(0x80 | CrlFileId);
                xfer_buffer[xfer_length++] = (byte)(CrlAid);
                xfer_buffer[xfer_length++] = (byte)(CrlAid >> 8);
                xfer_buffer[xfer_length++] = (byte)(CrlAid >> 16);
            }
            else
            {
                xfer_buffer[xfer_length++] = 0x00;
                xfer_buffer[xfer_length++] = 0x00;
                xfer_buffer[xfer_length++] = 0x00;
                xfer_buffer[xfer_length++] = 0x00;
            }

            byte[] data = BinUtils.Copy(PublicKey);
            if (Issuer == null)
            {
                data = BinUtils.Concat(data, 0x00);
            }
            else
            {
                data = BinUtils.Concat(data, (byte)Issuer.Length);
                data = BinUtils.Concat(data, Issuer);
            }

            if ((DesfireCommMode)CommMode == DesfireCommMode.Full)
            {
                /* Remember the length of the header */
                int header_length = xfer_length;

                /* Append the data */
                for (int i = 0; i < data.Length; i++)
                    xfer_buffer[xfer_length++] = data[i];

                /* Encrypt the data */
                Xfer_Padd_CipherSend(header_length);
            }
            else
            {
                /* Append the data without encryption */
                for (int i = 0; i < data.Length; i++)
                    xfer_buffer[xfer_length++] = data[i];
            }

            /* Be careful: it seems we don't have to increment the counter??? */
            status = Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            if (status != Success)
                return status;

            return status;
        }

        public long ExportKey(byte Option, byte KeyNumber, DesfireCommMode CommMode, out byte[] PublicKey)
        {
            long status;
            PublicKey = null;


            logger.trace("ExportKey({0:X02},{1:X02},{2})", Option, KeyNumber, CommMode);

            if ((CommMode != DesfireCommMode.Plain) && (SessionCryptoContext == null))
                return LibraryError(DesfireLibraryError.WrongSessionState);

            xfer_length = 0;

            xfer_buffer[xfer_length++] = (byte)DesfireCommand.EXPORT_KEY;
            xfer_buffer[xfer_length++] = Option;
            xfer_buffer[xfer_length++] = KeyNumber;

            if (CommMode == DesfireCommMode.Plain)
            {
                status = Command(0, DesfireCommandFlag.INCREMENT_COUNTER | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
            else
            {
                status = Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
            if (status != Success)
                return status;

            int length = xfer_length - 1;
            byte[] buffer = BinUtils.Copy(xfer_buffer, 1, length);

            if (CommMode == DesfireCommMode.Full)
            {
                SessionCryptoContext.CipherRecv(ref buffer, ref length);
                if (!SessionCryptoContext.Unpadd(ref buffer))
                    return LibraryError(DesfireLibraryError.WrongPadding);
            }

            PublicKey = BinUtils.Copy(buffer);
            return status;
        }

        public long ReadCARootPublicKey(byte KeyNumber, byte CommMode, out byte[] PublicKey)
        {
            return ReadCARootPublicKey(KeyNumber, (DesfireCommMode)CommMode, out PublicKey);
        }

        public long ReadCARootPublicKey(byte KeyNumber, DesfireCommMode CommMode, out byte[] PublicKey)
        {
            return ExportKey(0x01, KeyNumber, CommMode, out PublicKey);
        }

        public long ReadCARootPublicKey(byte KeyNumber, DesfireCommMode CommMode, MifareDuoXEccCurve CurveId, out ECPublicKeyParameters PublicKey)
        {
            long status;

            PublicKey = null;

            status = ReadCARootPublicKey(KeyNumber, CommMode, out byte[] PublicKeyValue);
            if (status != Success)
                return status;

            if (!ECC.ImportPublic(CurveId, PublicKeyValue, out PublicKey))
                return LibraryError(DesfireLibraryError.ExecutionFailed);

            return status;
        }


        #endregion
    }
}
