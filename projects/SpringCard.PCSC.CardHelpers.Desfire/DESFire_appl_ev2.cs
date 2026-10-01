/*
 * SpringCard DESFire Library (C#)
 * Copyright (c) SpringCard SAS, 2008-2025
 *
 * This file is part of the SpringCard DESFire library.
 * See LICENSE.txt for license details and restrictions.
 *
 */
using SpringCard.LibCs;
using System;

namespace SpringCard.PCSC.CardHelpers
{
    /// <summary>
    /// Description of DESFire_mgmt.
    /// </summary>
    public partial class Desfire
    {
        public long GetDelegatedInfo(ushort DamSlotNumber, out byte DamSlotVersion, out ushort QuotaLimit, out ushort FreeBlocks, out uint Aid)
        {
            Aid = 0xFFFFFFFF;
            DamSlotVersion = 0;
            QuotaLimit = 0;
            FreeBlocks = 0;

            long status;

            /* Begin the info block with the command code and the number of the key to be changed. */
            xfer_length = 0;
            xfer_buffer[xfer_length++] = (byte)DesfireCommand.GET_DELEGATED_INFO;
            xfer_buffer[xfer_length++] = (byte)(DamSlotNumber & 0x0FF);
            xfer_buffer[xfer_length++] = (byte)((DamSlotNumber >> 8) & 0x0FF);

            /* EV2 secure mode */
            if (SessionIsEV2OrGreater())
            {
                status = Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
            else
            {
                /* Communicate the info block to the card and check the operation's return status. */
                status = Command(9, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }

            if (status != Success)
                return status;

            if (xfer_buffer[INF + 0] != Success)
                return (byte) DesfireCardError.AdditionalFrame;


            /* Dam slot version. */
            DamSlotVersion = xfer_buffer[INF + 1];

            /* QuotaLimit. */
            QuotaLimit = 0;
            QuotaLimit += xfer_buffer[INF + 3];
            QuotaLimit <<= 8;
            QuotaLimit += xfer_buffer[INF + 2];

            /* FreeBlocks. */
            FreeBlocks = 0;
            FreeBlocks += xfer_buffer[INF + 5];
            FreeBlocks <<= 8;
            FreeBlocks += xfer_buffer[INF + 4];

            /* AID. */
            Aid = xfer_buffer[INF + 8];
            Aid <<= 8;
            Aid += xfer_buffer[INF + 7];
            Aid <<= 8;
            Aid += xfer_buffer[INF + 6];

            return Success;
        }

        #region CreateDelegatedApplication

        private class DesfireCreateDelegatedApplicationParameters : DesfireCreateApplicationParameters
        {
            public ushort DAMSlotNumber;
            public byte DAMSlotVersion;
            public ushort QuotaLimit;
            public byte[] DefaultAppKeyEnc;
            public byte[] DamMac;

            public override string Message()
            {
                string result = base.Message();
                result += string.Format(" DAMSlot Number:{0:X04} Version:{1:X02} QuotaLimit:{2:X04}\n", DAMSlotNumber, DAMSlotVersion, QuotaLimit);
                return result;
            }
        }

        public long CreateDelegatedApplication(byte[] Cryptogram)
        {
            long status;

            if ((Cryptogram == null) || (Cryptogram.Length < 10 + 32 + 8))
                return LibraryError(DesfireLibraryError.InvalidParameter);

            if (!SessionIsEV2OrGreater())
                return LibraryError(DesfireLibraryError.WrongSessionState);

            /* We know the cryptogram is split before EnK and DamMac, which makes 32 + 8 */
            int pivot = Cryptogram.Length - 32 - 8;
            byte[] part1 = BinUtils.Copy(Cryptogram, 0, pivot);
            byte[] part2 = BinUtils.Copy(Cryptogram, pivot, Cryptogram.Length - pivot);

            logger.trace("CreateDelegatedApplication({0} {1])", BinConvert.ToHex(part1), BinConvert.ToHex(part2));

            /* Create the info block containing the command code and the given parameters. */
            xfer_length = 0;
            xfer_buffer[xfer_length++] = (byte)DesfireCommand.CREATE_DELEGATED_APPLICATION;
            for (int i=0; i<Cryptogram.Length; i++)
                xfer_buffer[xfer_length++] = Cryptogram[i];

            pivot += 1; /* Since we have added the command code */

            /* If secure messaging is active, the secure messaging is applied as if the command or
            response would have been sent in a single large frame. The 0xAF command and
            response codes are ignored for these calculations. If a MAC is appended to the command
            or response, this may result in an additional frame if necessary. */
            Xfer_AppendCmac();

            /* OK, now we have the two commands in the buffer, time to split them. */

            part1 = BinUtils.Copy(xfer_buffer, 0, pivot);
            part2 = BinUtils.Concat((byte)DesfireCommand.ADDITIONAL_FRAME, BinUtils.Copy(xfer_buffer, pivot, xfer_length - pivot));

            /* Send Part1 to the card */
            Array.ConstrainedCopy(part1, 0, xfer_buffer, 0, part1.Length);
            xfer_length = part1.Length;

            status = Command(0, DesfireCommandFlag.WANTS_ADDITIONAL_FRAME);
            if (status != Success)
                return status;

            /* Send Part2 to the card */
            Array.ConstrainedCopy(part2, 0, xfer_buffer, 0, part2.Length);
            xfer_length = part2.Length;

            status = Command(0, DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            if (status != Success)
                return status;

            return Success;
        }

        private long CreateDelegatedApplication(DesfireCreateDelegatedApplicationParameters p)
        {
            long status;

            logger.trace("CreateDelegatedApplication({0})", p.Message());
            if (logCrypto)
            {
                if (logSecrets)
                    logger.debug("\tDefaultAppKeyEnc: {0}", BinConvert.ToHex(p.DefaultAppKeyEnc));
                logger.debug("\tDamMac: {0}", BinConvert.ToHex(p.DamMac));
            }

            if ((p.DefaultAppKeyEnc == null) || (p.DefaultAppKeyEnc.Length != 32))
                return LibraryError(DesfireLibraryError.InvalidParameter);
            if ((p.DamMac == null) || (p.DamMac.Length != 8))
                return LibraryError(DesfireLibraryError.InvalidParameter);

            if (!SessionIsEV2OrGreater())
                return LibraryError(DesfireLibraryError.WrongSessionState);

            /* Create the info block containing the command code and the given parameters. */
            xfer_length = 0;
            xfer_buffer[xfer_length++] = (byte)DesfireCommand.CREATE_DELEGATED_APPLICATION;
            xfer_buffer[xfer_length++] = (byte)(p.Aid & 0x000000FF);
            xfer_buffer[xfer_length++] = (byte)((p.Aid >> 8) & 0x000000FF);
            xfer_buffer[xfer_length++] = (byte)((p.Aid >> 16) & 0x000000FF);
            xfer_buffer[xfer_length++] = (byte)(p.DAMSlotNumber & 0x00FF);
            xfer_buffer[xfer_length++] = (byte)((p.DAMSlotNumber >> 8) & 0x00FF);
            xfer_buffer[xfer_length++] = p.DAMSlotVersion;
            xfer_buffer[xfer_length++] = (byte)(p.QuotaLimit & 0x00FF);
            xfer_buffer[xfer_length++] = (byte)((p.QuotaLimit >> 8) & 0x00FF);
            xfer_buffer[xfer_length++] = p.KeySetting1;
            xfer_buffer[xfer_length++] = p.KeySetting2;
            if (p.HasKeySetting)
            {
                xfer_buffer[xfer_length++] = p.KeySetting3;
                xfer_buffer[xfer_length++] = p.AksVersion;
                xfer_buffer[xfer_length++] = p.NoKeySets;
                xfer_buffer[xfer_length++] = p.MaxKeySize;
                xfer_buffer[xfer_length++] = p.AppKeySetSetting;
            }
            if (p.HasIso)
            {
                xfer_buffer[xfer_length++] = (byte)(p.IsoDFId & 0x00FF);
                xfer_buffer[xfer_length++] = (byte)((p.IsoDFId >> 8) & 0x00FF);
                if (p.IsoDFName != null)
                {
                    if (p.IsoDFName.Length > 16)
                        return LibraryError(DesfireLibraryError.InvalidParameter);
                    Array.ConstrainedCopy(p.IsoDFName, 0, xfer_buffer, xfer_length, p.IsoDFName.Length);
                    xfer_length += p.IsoDFName.Length;
                }
            }

            int pivot = xfer_length;

            for (int i=0; i < p.DefaultAppKeyEnc.Length; i++)
            {
                xfer_buffer[xfer_length++] = p.DefaultAppKeyEnc[i];
            }
            for (int i = 0; i < p.DamMac.Length; i++)
            {
                xfer_buffer[xfer_length++] = p.DamMac[i];
            }

            /* If secure messaging is active, the secure messaging is applied as if the command or
            response would have been sent in a single large frame. The 0xAF command and
            response codes are ignored for these calculations. If a MAC is appended to the command
            or response, this may result in an additional frame if necessary. */
            Xfer_AppendCmac();

            /* OK, now we have the two commands in the buffer, time to split them. */

            byte[] part1 = BinUtils.Copy(xfer_buffer, 0, pivot);
            byte[] part2 = BinUtils.Concat((byte)DesfireCommand.ADDITIONAL_FRAME,  BinUtils.Copy(xfer_buffer, pivot, xfer_length - pivot));

            /* Send Part1 to the card */
            Array.ConstrainedCopy(part1, 0, xfer_buffer, 0, part1.Length);
            xfer_length = part1.Length;

            status = Command(0, DesfireCommandFlag.WANTS_ADDITIONAL_FRAME);
            if (status != Success)
                return status;

            /* Send Part2 to the card */
            Array.ConstrainedCopy(part2, 0, xfer_buffer, 0, part2.Length);
            xfer_length = part2.Length;

            status = Command(0, DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            if (status != Success)
                return status;

            return Success;
        }

        public long CreateDelegatedApplication(uint Aid, ushort DAMSlotNumber, byte DAMSlotVersion, ushort QuotaLimit, byte KeySetting1, byte KeySetting2, byte[] DefaultAppKeyEnc, byte[] DamMac)
        {
            DesfireCreateDelegatedApplicationParameters p = new DesfireCreateDelegatedApplicationParameters();

            p.Aid = Aid;
            p.DAMSlotNumber = DAMSlotNumber;
            p.DAMSlotVersion = DAMSlotVersion;
            p.QuotaLimit = QuotaLimit;
            p.KeySetting1 = KeySetting1;
            p.KeySetting2 = KeySetting2;
            p.DefaultAppKeyEnc = DefaultAppKeyEnc;
            p.DamMac = DamMac;

            return CreateDelegatedApplication(p);
        }


        public long CreateDelegatedApplication(uint Aid, ushort DAMSlotNumber, byte DAMSlotVersion, ushort QuotaLimit, byte KeySetting1, byte KeySetting2, byte KeySetting3, byte AksVersion, byte NoKeySets, byte MaxKeySize, byte AppKeySetSetting, byte[] DefaultAppKeyEnc, byte[] DamMac)
        {
            DesfireCreateDelegatedApplicationParameters p = new DesfireCreateDelegatedApplicationParameters();

            p.Aid = Aid;
            p.DAMSlotNumber = DAMSlotNumber;
            p.DAMSlotVersion = DAMSlotVersion;
            p.QuotaLimit = QuotaLimit;
            p.KeySetting1 = KeySetting1;
            p.KeySetting2 = KeySetting2;
            p.KeySetting3 = KeySetting3;
            p.AksVersion = AksVersion;
            p.NoKeySets = NoKeySets;
            p.MaxKeySize = MaxKeySize;
            p.AppKeySetSetting = AppKeySetSetting;
            p.DefaultAppKeyEnc = DefaultAppKeyEnc;
            p.DamMac = DamMac;

            return CreateDelegatedApplication(p);
        }

        public long CreateDelegatedApplication(uint Aid, ushort DAMSlotNumber, byte DAMSlotVersion, ushort QuotaLimit, byte KeySetting1, byte KeySetting2, ushort IsoDfId, string IsoDfName, byte[] DefaultAppKeyEnc, byte[] DamMac)
        {
            if (string.IsNullOrEmpty(IsoDfName))
                return LibraryError(DesfireLibraryError.InvalidParameter);
            return CreateDelegatedApplication(Aid, DAMSlotNumber, DAMSlotVersion, QuotaLimit, KeySetting1, KeySetting2, IsoDfId, StrUtils.ToBytes(IsoDfName), DefaultAppKeyEnc, DamMac);
        }

        public long CreateDelegatedApplication(uint Aid, ushort DAMSlotNumber, byte DAMSlotVersion, ushort QuotaLimit, byte KeySetting1, byte KeySetting2, ushort IsoDfId, byte[] IsoDfName, byte[] DefaultAppKeyEnc, byte[] DamMac)
        {
            int length = 0;
            if (IsoDfName != null)
                length = IsoDfName.Length;
            return CreateDelegatedApplication(Aid, DAMSlotNumber, DAMSlotVersion, QuotaLimit, KeySetting1, KeySetting2, IsoDfId, IsoDfName, length, DefaultAppKeyEnc, DamMac);
        }

        public long CreateDelegatedApplication(uint Aid, ushort DAMSlotNumber, byte DAMSlotVersion, ushort QuotaLimit, byte KeySetting1, byte KeySetting2, ushort IsoDFId, byte[] IsoDFName, int IsoDFNameLen, byte[] DefaultAppKeyEnc, byte[] DamMac)
        {
            DesfireCreateDelegatedApplicationParameters p = new DesfireCreateDelegatedApplicationParameters();
            p.Aid = Aid;
            p.DAMSlotNumber = DAMSlotNumber;
            p.DAMSlotVersion = DAMSlotVersion;
            p.QuotaLimit = QuotaLimit;
            p.KeySetting1 = KeySetting1;
            p.KeySetting2 = KeySetting2;
            p.HasIso = true;
            p.IsoDFId = IsoDFId;
            p.IsoDFName = BinUtils.Copy(IsoDFName, 0, IsoDFNameLen);
            p.DefaultAppKeyEnc = DefaultAppKeyEnc;
            p.DamMac = DamMac;

            return CreateDelegatedApplication(p);
        }

        public long CreateDelegatedApplication(uint Aid, ushort DAMSlotNumber, byte DAMSlotVersion, ushort QuotaLimit, byte KeySetting1, byte KeySetting2, byte KeySetting3, byte AksVersion, byte NoKeySets, byte MaxKeySize, byte AppKeySetSetting, ushort IsoDfId, string IsoDfName, byte[] DefaultAppKeyEnc, byte[] DamMac)
        {
            if (string.IsNullOrEmpty(IsoDfName))
                return LibraryError(DesfireLibraryError.InvalidParameter);
            return CreateDelegatedApplication(Aid, DAMSlotNumber, DAMSlotVersion, QuotaLimit, KeySetting1, KeySetting2, KeySetting3, AksVersion, NoKeySets, MaxKeySize, AppKeySetSetting, IsoDfId, StrUtils.ToBytes(IsoDfName), DefaultAppKeyEnc, DamMac);
        }

        public long CreateDelegatedApplication(
          uint Aid,
          ushort DAMSlotNumber,
          byte DAMSlotVersion,
          ushort QuotaLimit,
          byte KeySetting1,
          byte KeySetting2,
          byte KeySetting3,
          byte AksVersion,
          byte NoKeySets,
          byte MaxKeySize,
          byte AppKeySetSetting,
          ushort IsoDfId,
          byte[] IsoDfName,
          byte[] DefaultAppKeyEnc,
          byte[] DamMac)
        {
            int length = 0;
            if (IsoDfName != null)
                length = IsoDfName.Length;
            return CreateDelegatedApplication(Aid, DAMSlotNumber, DAMSlotVersion, QuotaLimit, KeySetting1, KeySetting2, KeySetting3, AksVersion, NoKeySets, MaxKeySize, AppKeySetSetting, IsoDfId, IsoDfName, length, DefaultAppKeyEnc, DamMac);
        }

        public long CreateDelegatedApplication(
          uint Aid,
          ushort DAMSlotNumber,
          byte DAMSlotVersion,
          ushort QuotaLimit,
          byte KeySetting1,
          byte KeySetting2,
          byte KeySetting3,
          byte AksVersion,
          byte NoKeySets,
          byte MaxKeySize,
          byte AppKeySetSetting,
          ushort IsoDFId,
          byte[] IsoDFName,
          int IsoDFNameLen,
          byte[] DefaultAppKeyEnc,
          byte[] DamMac)
        {
            DesfireCreateDelegatedApplicationParameters p = new DesfireCreateDelegatedApplicationParameters();
            p.Aid = Aid;
            p.DAMSlotNumber = DAMSlotNumber;
            p.DAMSlotVersion = DAMSlotVersion;
            p.QuotaLimit = QuotaLimit;
            p.KeySetting1 = KeySetting1;
            p.KeySetting2 = KeySetting2;
            p.KeySetting3 = KeySetting3;
            p.AksVersion = AksVersion;
            p.NoKeySets = NoKeySets;
            p.MaxKeySize = MaxKeySize;
            p.AppKeySetSetting = AppKeySetSetting;
            p.HasIso = true;
            p.IsoDFId = IsoDFId;
            p.IsoDFName = BinUtils.Copy(IsoDFName, 0, IsoDFNameLen);
            p.DefaultAppKeyEnc = DefaultAppKeyEnc;
            p.DamMac = DamMac;
            return CreateDelegatedApplication(p);
        }

        #endregion

        #region Cryptography for PrepareCreateDelegatedApplication

        public long CreateDamMac(byte[] PiccDamMacKey, byte[] Message, out byte[] DamMac)
        {
            return CreateDamMac(PiccDamMacKey, Message, Message.Length, out DamMac);
        }

        public long CreateDamMac(byte[] PiccDamMacKey, byte[] Message, int MessageLength, out byte[] DamMac)
        {
            DamMac = null;

            if (PiccDamMacKey == null)
                return LibraryError(DesfireLibraryError.InvalidParameter);
            if (Message == null)
                return LibraryError(DesfireLibraryError.InvalidParameter);

            byte[] IV = new byte[16];

            if (MessageLength < Message.Length)
                Message = BinUtils.Copy(Message, 0, MessageLength);

            if (logCrypto)
            {
                logger.debug("DamMac msg {0}", BinConvert.ToHex(Message));
                if (logSecrets)
                    logger.debug("DamMacKey  {0}", BinConvert.ToHex(PiccDamMacKey));
            }

            DesfireCryptoContextEV2 cryptoContext = new DesfireCryptoContextEV2(this, PiccDamMacKey);
            DamMac = cryptoContext.ComputeCmac(Message);

            if (logCrypto)
                logger.debug("DamMac <-  {0}", BinConvert.ToHex(DamMac));

            return Success;
        }

        public long CreateDefaultKeyEnc(byte[] PiccDamEncKey, byte[] DefaultKeyValue, byte DefaultKeyVersion, out byte[] DefaultKeyEnc)
        {
            return CreateDefaultKeyEnc(PiccDamEncKey, randomGenerator.Get(7), DefaultKeyValue, DefaultKeyVersion, out DefaultKeyEnc);
        }

        public long CreateDefaultKeyEnc(byte[] PiccDamEncKey, byte[] Random, byte[] DefaultKeyValue, byte DefaultKeyVersion, out byte[] DefaultKeyEnc)
        {
            DefaultKeyEnc = null;

            if (PiccDamEncKey == null)
                return LibraryError(DesfireLibraryError.InvalidParameter);
            if ((Random == null) || (Random.Length < 7))
                return LibraryError(DesfireLibraryError.InvalidParameter);
            if ((DefaultKeyValue == null) || (DefaultKeyValue.Length < 8) || (DefaultKeyValue.Length > 24))
                return LibraryError(DesfireLibraryError.InvalidParameter);

            byte[] IV = new byte[16];
            byte[] buffer = new byte[32];

            if (logSecrets)
            {
                logger.debug("Encrypting {0}{1:X02}", BinConvert.ToHex(DefaultKeyValue), DefaultKeyVersion);
                logger.debug("DamEncKey  {0}", BinConvert.ToHex(PiccDamEncKey));
                logger.debug("Random     {0}", BinConvert.ToHex(Random));
            }

            Array.ConstrainedCopy(Random, 0, buffer, 0, 7);
            Array.ConstrainedCopy(DefaultKeyValue, 0, buffer, 7, DefaultKeyValue.Length);
            buffer[7 + DefaultKeyValue.Length] = DefaultKeyVersion;

            if (logSecrets)
                logger.debug("           {0}", BinConvert.ToHex(buffer));

            DesfireCryptoContextEV2 cryptoContext = new DesfireCryptoContextEV2(this, PiccDamEncKey);
            cryptoContext.CipherSendEx(ref buffer, true);

            if (logCrypto)
                logger.debug("EncKey <-  {0}", BinConvert.ToHex(buffer));

            DefaultKeyEnc = buffer;
            return Success;
        }

        #endregion

        #region PrepareCreateDelegatedApplication

        private class DesfirePrepareCreateDelegatedApplicationParameters : DesfireCreateApplicationParameters
        {
            public byte[] PiccDamEncKey;
            public byte[] PiccDamMacKey;

            public ushort DAMSlotNumber;
            public byte DAMSlotVersion;
            public ushort QuotaLimit;
            public byte[] DefaultKeyValue;
            public byte DefaultKeyVersion;

            public byte[] Cryptogram;
            public byte[] DefaultKeyEnc;
            public byte[] DamMac;

            public override string Message()
            {
                string result = base.Message();
                result += string.Format(" DAMSlot Number:{0:X04} Version:{1:X02} QuotaLimit:{2:X04}\n", DAMSlotNumber, DAMSlotVersion, QuotaLimit);
                return result;
            }
        }


        private long PrepareCreateDelegatedApplication(DesfirePrepareCreateDelegatedApplicationParameters p)
        {
            long status;

            logger.trace("PrepareCreateDelegatedApplication({0})", p.Message());

            /* Create the info block containing the command code and the given parameters. */
            byte[] buffer = new byte[128];
            int length = 0;
            buffer[length++] = (byte)DesfireCommand.CREATE_DELEGATED_APPLICATION;
            buffer[length++] = (byte)(p.Aid & 0x000000FF);
            buffer[length++] = (byte)((p.Aid >> 8) & 0x000000FF);
            buffer[length++] = (byte)((p.Aid >> 16) & 0x000000FF);
            buffer[length++] = (byte)(p.DAMSlotNumber & 0x00FF);
            buffer[length++] = (byte)((p.DAMSlotNumber >> 8) & 0x00FF);
            buffer[length++] = p.DAMSlotVersion;
            buffer[length++] = (byte)(p.QuotaLimit & 0x00FF);
            buffer[length++] = (byte)((p.QuotaLimit >> 8) & 0x00FF);
            buffer[length++] = p.KeySetting1;
            buffer[length++] = p.KeySetting2;
            if (p.HasKeySetting)
            {
                buffer[length++] = p.KeySetting3;
                buffer[length++] = p.AksVersion;
                buffer[length++] = p.NoKeySets;
                buffer[length++] = p.MaxKeySize;
                buffer[length++] = p.AppKeySetSetting;
            }
            if (p.HasIso)
            {
                buffer[length++] = (byte)(p.IsoDFId & 0x00FF);
                buffer[length++] = (byte)((p.IsoDFId >> 8) & 0x00FF);
                if (p.IsoDFName != null)
                {
                    if (p.IsoDFName.Length > 16)
                        return LibraryError(DesfireLibraryError.InvalidParameter);
                    Array.ConstrainedCopy(p.IsoDFName, 0, buffer, length, p.IsoDFName.Length);
                    length += p.IsoDFName.Length;
                }
            }

            status = CreateDefaultKeyEnc(p.PiccDamEncKey, p.DefaultKeyValue, p.DefaultKeyVersion, out p.DefaultKeyEnc);
            if (status != Success)
                return status;

            Array.ConstrainedCopy(p.DefaultKeyEnc, 0, buffer, length, p.DefaultKeyEnc.Length);
            length += p.DefaultKeyEnc.Length;

            status = CreateDamMac(p.PiccDamMacKey, buffer, length, out p.DamMac);
            if (status != Success)
                return status;

            Array.ConstrainedCopy(p.DamMac, 0, buffer, length, p.DamMac.Length);
            length += p.DamMac.Length;

            p.Cryptogram = new byte[length - 1];
            Array.ConstrainedCopy(buffer, 1, p.Cryptogram, 0, length - 1);

            return Success;
        }

        public long PrepareCreateDelegatedApplication(byte[] PiccDamEncKey, byte[] PiccDamMacKey, uint Aid, ushort DAMSlotNumber, byte DAMSlotVersion, ushort QuotaLimit, byte KeySetting1, byte KeySetting2, byte[] DefaultKeyValue, byte DefaultKeyVersion, out byte[] Cryptogram)
        {
            DesfirePrepareCreateDelegatedApplicationParameters p = new DesfirePrepareCreateDelegatedApplicationParameters();

            p.PiccDamEncKey = PiccDamEncKey;
            p.PiccDamMacKey = PiccDamMacKey;

            p.Aid = Aid;
            p.DAMSlotNumber = DAMSlotNumber;
            p.DAMSlotVersion = DAMSlotVersion;
            p.QuotaLimit = QuotaLimit;
            p.KeySetting1 = KeySetting1;
            p.KeySetting2 = KeySetting2;

            p.DefaultKeyValue = DefaultKeyValue;
            p.DefaultKeyVersion = DefaultKeyVersion;

            long status = PrepareCreateDelegatedApplication(p);

            Cryptogram = p.Cryptogram;

            return status;
        }

        public long PrepareCreateDelegatedApplication(byte[] PiccDamEncKey, byte[] PiccDamMacKey, uint Aid, ushort DAMSlotNumber, byte DAMSlotVersion, ushort QuotaLimit, byte KeySetting1, byte KeySetting2, byte[] DefaultKeyValue, byte DefaultKeyVersion, out byte[] DefaultKeyEnc, out byte[] DamMac)
        {
            DesfirePrepareCreateDelegatedApplicationParameters p = new DesfirePrepareCreateDelegatedApplicationParameters();

            p.PiccDamEncKey = PiccDamEncKey;
            p.PiccDamMacKey = PiccDamMacKey;

            p.Aid = Aid;
            p.DAMSlotNumber = DAMSlotNumber;
            p.DAMSlotVersion = DAMSlotVersion;
            p.QuotaLimit = QuotaLimit;
            p.KeySetting1 = KeySetting1;
            p.KeySetting2 = KeySetting2;

            p.DefaultKeyValue = DefaultKeyValue;
            p.DefaultKeyVersion = DefaultKeyVersion;

            long status = PrepareCreateDelegatedApplication(p);

            DefaultKeyEnc = p.DefaultKeyEnc;
            DamMac = p.DamMac;

            return status;
        }

        public long PrepareCreateDelegatedApplication(byte[] PiccDamEncKey, byte[] PiccDamMacKey, uint Aid, ushort DAMSlotNumber, byte DAMSlotVersion, ushort QuotaLimit, byte KeySetting1, byte KeySetting2, byte KeySetting3, byte AksVersion, byte NoKeySets, byte MaxKeySize, byte AppKeySetSetting, byte[] DefaultKeyValue, byte DefaultKeyVersion, out byte[] DefaultKeyEnc)
        {
            DesfirePrepareCreateDelegatedApplicationParameters p = new DesfirePrepareCreateDelegatedApplicationParameters();

            p.PiccDamEncKey = PiccDamEncKey;
            p.PiccDamMacKey = PiccDamMacKey;

            p.Aid = Aid;
            p.DAMSlotNumber = DAMSlotNumber;
            p.DAMSlotVersion = DAMSlotVersion;
            p.QuotaLimit = QuotaLimit;
            p.KeySetting1 = KeySetting1;
            p.KeySetting2 = KeySetting2;
            p.KeySetting3 = KeySetting3;
            p.AksVersion = AksVersion;
            p.NoKeySets = NoKeySets;
            p.MaxKeySize = MaxKeySize;
            p.AppKeySetSetting = AppKeySetSetting;

            p.DefaultKeyValue = DefaultKeyValue;
            p.DefaultKeyVersion = DefaultKeyVersion;

            long status = PrepareCreateDelegatedApplication(p);

            DefaultKeyEnc = p.Cryptogram;

            return status;
        }

        public long PrepareCreateDelegatedApplication(byte[] PiccDamEncKey, byte[] PiccDamMacKey, uint Aid, ushort DAMSlotNumber, byte DAMSlotVersion, ushort QuotaLimit, byte KeySetting1, byte KeySetting2, byte KeySetting3, byte AksVersion, byte NoKeySets, byte MaxKeySize, byte AppKeySetSetting, byte[] DefaultKeyValue, byte DefaultKeyVersion, out byte[] DefaultKeyEnc, out byte[] DamMac)
        {
            DesfirePrepareCreateDelegatedApplicationParameters p = new DesfirePrepareCreateDelegatedApplicationParameters();

            p.PiccDamEncKey = PiccDamEncKey;
            p.PiccDamMacKey = PiccDamMacKey;

            p.Aid = Aid;
            p.DAMSlotNumber = DAMSlotNumber;
            p.DAMSlotVersion = DAMSlotVersion;
            p.QuotaLimit = QuotaLimit;
            p.KeySetting1 = KeySetting1;
            p.KeySetting2 = KeySetting2;
            p.KeySetting3 = KeySetting3;
            p.AksVersion = AksVersion;
            p.NoKeySets = NoKeySets;
            p.MaxKeySize = MaxKeySize;
            p.AppKeySetSetting = AppKeySetSetting;

            p.DefaultKeyValue = DefaultKeyValue;
            p.DefaultKeyVersion = DefaultKeyVersion;

            long status = PrepareCreateDelegatedApplication(p);

            DefaultKeyEnc = p.DefaultKeyEnc;
            DamMac = p.DamMac;

            return status;
        }

        public long PrepareCreateDelegatedApplication(byte[] PiccDamEncKey, byte[] PiccDamMacKey, uint Aid, ushort DAMSlotNumber, byte DAMSlotVersion, ushort QuotaLimit, byte KeySetting1, byte KeySetting2, ushort IsoDfId, string IsoDfName, byte[] DefaultKeyValue, byte DefaultKeyVersion, out byte[] Cryptogram)
        {
            Cryptogram = null;
            if (string.IsNullOrEmpty(IsoDfName))
                return LibraryError(DesfireLibraryError.InvalidParameter);
            return PrepareCreateDelegatedApplication(PiccDamEncKey, PiccDamMacKey, Aid, DAMSlotNumber, DAMSlotVersion, QuotaLimit, KeySetting1, KeySetting2, IsoDfId, StrUtils.ToBytes(IsoDfName), DefaultKeyValue, DefaultKeyVersion, out Cryptogram);
        }

        public long PrepareCreateDelegatedApplication(byte[] PiccDamEncKey, byte[] PiccDamMacKey, uint Aid, ushort DAMSlotNumber, byte DAMSlotVersion, ushort QuotaLimit, byte KeySetting1, byte KeySetting2, ushort IsoDfId, string IsoDfName, byte[] DefaultKeyValue, byte DefaultKeyVersion, out byte[] DefaultKeyEnc, out byte[] DamMac)
        {
            DefaultKeyEnc = null;
            DamMac = null;
            if (string.IsNullOrEmpty(IsoDfName))
                return LibraryError(DesfireLibraryError.InvalidParameter);
            return PrepareCreateDelegatedApplication(PiccDamEncKey, PiccDamMacKey, Aid, DAMSlotNumber, DAMSlotVersion, QuotaLimit, KeySetting1, KeySetting2, IsoDfId, StrUtils.ToBytes(IsoDfName), DefaultKeyValue, DefaultKeyVersion, out DefaultKeyEnc, out DamMac);
        }

        public long PrepareCreateDelegatedApplication(byte[] PiccDamEncKey, byte[] PiccDamMacKey, uint Aid, ushort DAMSlotNumber, byte DAMSlotVersion, ushort QuotaLimit, byte KeySetting1, byte KeySetting2, ushort IsoDfId, byte[] IsoDfName, byte[] DefaultKeyValue, byte DefaultKeyVersion, out byte[] Cryptogram)
        {
            int length = 0;
            if (IsoDfName != null)
                length = IsoDfName.Length;
            return PrepareCreateDelegatedApplication(PiccDamEncKey, PiccDamMacKey, Aid, DAMSlotNumber, DAMSlotVersion, QuotaLimit, KeySetting1, KeySetting2, IsoDfId, IsoDfName, length, DefaultKeyValue, DefaultKeyVersion, out Cryptogram);
        }

        public long PrepareCreateDelegatedApplication(byte[] PiccDamEncKey, byte[] PiccDamMacKey, uint Aid, ushort DAMSlotNumber, byte DAMSlotVersion, ushort QuotaLimit, byte KeySetting1, byte KeySetting2, ushort IsoDfId, byte[] IsoDfName, byte[] DefaultKeyValue, byte DefaultKeyVersion, out byte[] DefaultKeyEnc, out byte[] DamMac)
        {
            int length = 0;
            if (IsoDfName != null)
                length = IsoDfName.Length;
            return PrepareCreateDelegatedApplication(PiccDamEncKey, PiccDamMacKey, Aid, DAMSlotNumber, DAMSlotVersion, QuotaLimit, KeySetting1, KeySetting2, IsoDfId, IsoDfName, length, DefaultKeyValue, DefaultKeyVersion, out DefaultKeyEnc, out DamMac);
        }

        public long PrepareCreateDelegatedApplication(byte[] PiccDamEncKey, byte[] PiccDamMacKey, uint Aid, ushort DAMSlotNumber, byte DAMSlotVersion, ushort QuotaLimit, byte KeySetting1, byte KeySetting2, ushort IsoDFId, byte[] IsoDFName, int IsoDFNameLen, byte[] DefaultKeyValue, byte DefaultKeyVersion, out byte[] Cryptogram)
        {
            DesfirePrepareCreateDelegatedApplicationParameters p = new DesfirePrepareCreateDelegatedApplicationParameters();

            p.PiccDamEncKey = PiccDamEncKey;
            p.PiccDamMacKey = PiccDamMacKey;

            p.Aid = Aid;
            p.DAMSlotNumber = DAMSlotNumber;
            p.DAMSlotVersion = DAMSlotVersion;
            p.QuotaLimit = QuotaLimit;
            p.KeySetting1 = KeySetting1;
            p.KeySetting2 = KeySetting2;
            p.HasIso = true;
            p.IsoDFId = IsoDFId;
            p.IsoDFName = BinUtils.Copy(IsoDFName, 0, IsoDFNameLen);

            p.DefaultKeyValue = DefaultKeyValue;
            p.DefaultKeyVersion = DefaultKeyVersion;

            long status = PrepareCreateDelegatedApplication(p);

            Cryptogram = p.Cryptogram;

            return status;
        }

        public long PrepareCreateDelegatedApplication(byte[] PiccDamEncKey, byte[] PiccDamMacKey, uint Aid, ushort DAMSlotNumber, byte DAMSlotVersion, ushort QuotaLimit, byte KeySetting1, byte KeySetting2, ushort IsoDFId, byte[] IsoDFName, int IsoDFNameLen, byte[] DefaultKeyValue, byte DefaultKeyVersion, out byte[] DefaultKeyEnc, out byte[] DamMac)
        {
            DesfirePrepareCreateDelegatedApplicationParameters p = new DesfirePrepareCreateDelegatedApplicationParameters();

            p.PiccDamEncKey = PiccDamEncKey;
            p.PiccDamMacKey = PiccDamMacKey;

            p.Aid = Aid;
            p.DAMSlotNumber = DAMSlotNumber;
            p.DAMSlotVersion = DAMSlotVersion;
            p.QuotaLimit = QuotaLimit;
            p.KeySetting1 = KeySetting1;
            p.KeySetting2 = KeySetting2;
            p.HasIso = true;
            p.IsoDFId = IsoDFId;
            p.IsoDFName = BinUtils.Copy(IsoDFName, 0, IsoDFNameLen);

            p.DefaultKeyValue = DefaultKeyValue;
            p.DefaultKeyVersion = DefaultKeyVersion;

            long status = PrepareCreateDelegatedApplication(p);

            DefaultKeyEnc = p.DefaultKeyEnc;
            DamMac = p.DamMac;

            return status;
        }

        public long PrepareCreateDelegatedApplication(byte[] PiccDamEncKey, byte[] PiccDamMacKey, uint Aid, ushort DAMSlotNumber, byte DAMSlotVersion, ushort QuotaLimit, byte KeySetting1, byte KeySetting2, byte KeySetting3, byte AksVersion, byte NoKeySets, byte MaxKeySize, byte AppKeySetSetting, ushort IsoDfId, string IsoDfName, byte[] DefaultKeyValue, byte DefaultKeyVersion, out byte[] Cryptogram)
        {
            Cryptogram = null;
            if (string.IsNullOrEmpty(IsoDfName))
                return LibraryError(DesfireLibraryError.InvalidParameter);
            return PrepareCreateDelegatedApplication(PiccDamEncKey, PiccDamMacKey, Aid, DAMSlotNumber, DAMSlotVersion, QuotaLimit, KeySetting1, KeySetting2, KeySetting3, AksVersion, NoKeySets, MaxKeySize, AppKeySetSetting, IsoDfId, StrUtils.ToBytes(IsoDfName), DefaultKeyValue, DefaultKeyVersion, out Cryptogram);
        }

        public long PrepareCreateDelegatedApplication(byte[] PiccDamEncKey, byte[] PiccDamMacKey, uint Aid, ushort DAMSlotNumber, byte DAMSlotVersion, ushort QuotaLimit, byte KeySetting1, byte KeySetting2, byte KeySetting3, byte AksVersion, byte NoKeySets, byte MaxKeySize, byte AppKeySetSetting, ushort IsoDfId, string IsoDfName, byte[] DefaultKeyValue, byte DefaultKeyVersion, out byte[] DefaultKeyEnc, out byte[] DamMac)
        {
            DefaultKeyEnc = null;
            DamMac = null;
            if (string.IsNullOrEmpty(IsoDfName))
                return LibraryError(DesfireLibraryError.InvalidParameter);
            return PrepareCreateDelegatedApplication(PiccDamEncKey, PiccDamMacKey, Aid, DAMSlotNumber, DAMSlotVersion, QuotaLimit, KeySetting1, KeySetting2, KeySetting3, AksVersion, NoKeySets, MaxKeySize, AppKeySetSetting, IsoDfId, StrUtils.ToBytes(IsoDfName), DefaultKeyValue, DefaultKeyVersion, out DefaultKeyEnc, out DamMac);
        }

        public long PrepareCreateDelegatedApplication(
          byte[] PiccDamEncKey,
          byte[] PiccDamMacKey,
          uint Aid,
          ushort DAMSlotNumber,
          byte DAMSlotVersion,
          ushort QuotaLimit,
          byte KeySetting1,
          byte KeySetting2,
          byte KeySetting3,
          byte AksVersion,
          byte NoKeySets,
          byte MaxKeySize,
          byte AppKeySetSetting,
          ushort IsoDfId,
          byte[] IsoDfName,
          byte[] DefaultKeyValue,
          byte DefaultKeyVersion,
          out byte[] Cryptogram)
        {
            int length = 0;
            if (IsoDfName != null)
                length = IsoDfName.Length;
            return PrepareCreateDelegatedApplication(PiccDamEncKey, PiccDamMacKey, Aid, DAMSlotNumber, DAMSlotVersion, QuotaLimit, KeySetting1, KeySetting2, KeySetting3, AksVersion, NoKeySets, MaxKeySize, AppKeySetSetting, IsoDfId, IsoDfName, length, DefaultKeyValue, DefaultKeyVersion, out Cryptogram);
        }

        public long PrepareCreateDelegatedApplication(
          byte[] PiccDamEncKey,
          byte[] PiccDamMacKey,
          uint Aid,
          ushort DAMSlotNumber,
          byte DAMSlotVersion,
          ushort QuotaLimit,
          byte KeySetting1,
          byte KeySetting2,
          byte KeySetting3,
          byte AksVersion,
          byte NoKeySets,
          byte MaxKeySize,
          byte AppKeySetSetting,
          ushort IsoDfId,
          byte[] IsoDfName,
          byte[] DefaultKeyValue,
          byte DefaultKeyVersion,
          out byte[] DefaultKeyEnc,
          out byte[] DamMac)
        {
            int length = 0;
            if (IsoDfName != null)
                length = IsoDfName.Length;
            return PrepareCreateDelegatedApplication(PiccDamEncKey, PiccDamMacKey, Aid, DAMSlotNumber, DAMSlotVersion, QuotaLimit, KeySetting1, KeySetting2, KeySetting3, AksVersion, NoKeySets, MaxKeySize, AppKeySetSetting, IsoDfId, IsoDfName, length, DefaultKeyValue, DefaultKeyVersion, out DefaultKeyEnc, out DamMac);
        }

        public long PrepareCreateDelegatedApplication(
          byte[] PiccDamEncKey,
          byte[] PiccDamMacKey,
          uint Aid,
          ushort DAMSlotNumber,
          byte DAMSlotVersion,
          ushort QuotaLimit,
          byte KeySetting1,
          byte KeySetting2,
          byte KeySetting3,
          byte AksVersion,
          byte NoKeySets,
          byte MaxKeySize,
          byte AppKeySetSetting,
          ushort IsoDFId,
          byte[] IsoDFName,
          int IsoDFNameLen,
          byte[] DefaultKeyValue,
          byte DefaultKeyVersion,
          out byte[] Cryptogram)
        {
            DesfirePrepareCreateDelegatedApplicationParameters p = new DesfirePrepareCreateDelegatedApplicationParameters();

            p.PiccDamEncKey = PiccDamEncKey;
            p.PiccDamMacKey = PiccDamMacKey;

            p.Aid = Aid;
            p.DAMSlotNumber = DAMSlotNumber;
            p.DAMSlotVersion = DAMSlotVersion;
            p.QuotaLimit = QuotaLimit;
            p.KeySetting1 = KeySetting1;
            p.KeySetting2 = KeySetting2;
            p.KeySetting3 = KeySetting3;
            p.AksVersion = AksVersion;
            p.NoKeySets = NoKeySets;
            p.MaxKeySize = MaxKeySize;
            p.AppKeySetSetting = AppKeySetSetting;
            p.HasIso = true;
            p.IsoDFId = IsoDFId;
            p.IsoDFName = BinUtils.Copy(IsoDFName, 0, IsoDFNameLen);

            p.DefaultKeyValue = DefaultKeyValue;
            p.DefaultKeyVersion = DefaultKeyVersion;

            long status = PrepareCreateDelegatedApplication(p);

            Cryptogram = p.Cryptogram;

            return status;
        }

        public long PrepareCreateDelegatedApplication(
          byte[] PiccDamEncKey,
          byte[] PiccDamMacKey,
          uint Aid,
          ushort DAMSlotNumber,
          byte DAMSlotVersion,
          ushort QuotaLimit,
          byte KeySetting1,
          byte KeySetting2,
          byte KeySetting3,
          byte AksVersion,
          byte NoKeySets,
          byte MaxKeySize,
          byte AppKeySetSetting,
          ushort IsoDFId,
          byte[] IsoDFName,
          int IsoDFNameLen,
          byte[] DefaultKeyValue,
          byte DefaultKeyVersion,
          out byte[] DefaultKeyEnc,
          out byte[] DamMac)
        {
            DesfirePrepareCreateDelegatedApplicationParameters p = new DesfirePrepareCreateDelegatedApplicationParameters();

            p.PiccDamEncKey = PiccDamEncKey;
            p.PiccDamMacKey = PiccDamMacKey;

            p.Aid = Aid;
            p.DAMSlotNumber = DAMSlotNumber;
            p.DAMSlotVersion = DAMSlotVersion;
            p.QuotaLimit = QuotaLimit;
            p.KeySetting1 = KeySetting1;
            p.KeySetting2 = KeySetting2;
            p.KeySetting3 = KeySetting3;
            p.AksVersion = AksVersion;
            p.NoKeySets = NoKeySets;
            p.MaxKeySize = MaxKeySize;
            p.AppKeySetSetting = AppKeySetSetting;
            p.HasIso = true;
            p.IsoDFId = IsoDFId;
            p.IsoDFName = BinUtils.Copy(IsoDFName, 0, IsoDFNameLen);

            p.DefaultKeyValue = DefaultKeyValue;
            p.DefaultKeyVersion = DefaultKeyVersion;

            long status = PrepareCreateDelegatedApplication(p);

            DefaultKeyEnc = p.DefaultKeyEnc;
            DamMac = p.DamMac;

            return status;
        }

        #endregion


    }
}
