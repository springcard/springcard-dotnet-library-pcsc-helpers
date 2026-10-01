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
using System.Collections.Generic;

namespace SpringCard.PCSC.CardHelpers
{
    /// <summary>
    /// Description of DESFire_mgmt.
    /// </summary>
    public partial class Desfire
    {
        private class DesfireCreateApplicationParameters
        {
            public ulong Aid;
            public byte KeySetting1;
            public byte KeySetting2;
            public bool HasKeySetting { get { return (KeySetting2 & 0x10) != 0x00; } }
            public byte KeySetting3;
            public bool HasKeySets { get { return HasKeySetting && (KeySetting3 & 0x01) != 0x00; } }
            public byte AksVersion;
            public byte NoKeySets;
            public byte MaxKeySize;
            public byte AppKeySetSetting;

            public bool HasIso;
            public ushort IsoDFId;
            public byte[] IsoDFName;

            public virtual string Message()
            {
                List<string> result = new List<string>();

                if (HasKeySetting)
                    result.Add(string.Format($"{Aid:X06},{KeySetting1:X02}{KeySetting2:X02}{KeySetting3:X02}"));
                else
                    result.Add(string.Format($"{Aid:X06},{KeySetting1:X02}{KeySetting2:X02}"));

                if (HasKeySets)
                {
                    result.Add(string.Format($"KeySets:{AksVersion:X02},{NoKeySets},{MaxKeySize},{AppKeySetSetting:X02}"));
                }

                if (HasIso)
                {
                    result.Add(string.Format("ISO:{0:X04},{1}", IsoDFId, BinConvert.ToHex(IsoDFName)));
                }

                return string.Join(" ", result);
            }
        }

        private long CreateApplication(DesfireCreateApplicationParameters p)
        {
            logger.trace("CreateApplication({0})", p.Message());

            /* Create the info block containing the command code and the given parameters. */
            xfer_length = 0;
            xfer_buffer[xfer_length++] = (byte)DesfireCommand.CREATE_APPLICATION;
            xfer_buffer[xfer_length++] = (byte)(p.Aid & 0x000000FF);
            xfer_buffer[xfer_length++] = (byte)((p.Aid >> 8) & 0x000000FF);
            xfer_buffer[xfer_length++] = (byte)((p.Aid >> 16) & 0x000000FF);
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

            if (SessionIsEV2OrGreater())
            {
                return Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.WANTS_ADDITIONAL_FRAME | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
            else
            {
                return Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
        }


        public long CreateApplication(uint Aid, byte KeySetting1, byte KeySetting2)
        {
            DesfireCreateApplicationParameters p = new DesfireCreateApplicationParameters();

            p.Aid = Aid;
            p.KeySetting1 = KeySetting1;
            p.KeySetting2 = KeySetting2;

            return CreateApplication(p);
        }


        public long CreateApplication(uint Aid, byte KeySetting1, byte KeySetting2, byte KeySetting3, byte AksVersion, byte NoKeySets, byte MaxKeySize, byte AppKeySetSetting)
        {
            DesfireCreateApplicationParameters p = new DesfireCreateApplicationParameters();

            p.Aid = Aid;
            p.KeySetting1 = KeySetting1;
            p.KeySetting2 = KeySetting2;
            p.KeySetting3 = KeySetting3;
            p.AksVersion = AksVersion;
            p.NoKeySets = NoKeySets;
            p.MaxKeySize = MaxKeySize;
            p.AppKeySetSetting = AppKeySetSetting;

            return CreateApplication(p);
        }

        public long CreateApplication(uint Aid, byte KeySetting1, byte KeySetting2, ushort IsoDfId, string IsoDfName)
        {
            if (string.IsNullOrEmpty(IsoDfName))
                return LibraryError(DesfireLibraryError.InvalidParameter);
            return CreateApplication(Aid, KeySetting1, KeySetting2, IsoDfId, StrUtils.ToBytes(IsoDfName));
        }

        public long CreateApplication(uint Aid, byte KeySetting1, byte KeySetting2, ushort IsoDfId, byte[] IsoDfName)
        {
            int length = 0;
            if (IsoDfName != null)
                length = IsoDfName.Length;
            return CreateApplication(Aid, KeySetting1, KeySetting2, IsoDfId, IsoDfName, length);
        }

        public long CreateApplication(uint Aid, byte KeySetting1, byte KeySetting2, ushort IsoDFId, byte[] IsoDFName, int IsoDFNameLen)
        {
            DesfireCreateApplicationParameters p = new DesfireCreateApplicationParameters();
            p.Aid = Aid;
            p.KeySetting1 = KeySetting1;
            p.KeySetting2 = KeySetting2;
            p.HasIso = true;
            p.IsoDFId = IsoDFId;
            p.IsoDFName = BinUtils.Copy(IsoDFName, 0, IsoDFNameLen);

            return CreateApplication(p);
        }

        public long CreateApplication(uint Aid, byte KeySetting1, byte KeySetting2, byte KeySetting3, byte AksVersion, byte NoKeySets, byte MaxKeySize, byte AppKeySetSetting, ushort IsoDfId, string IsoDfName)
        {
            if (string.IsNullOrEmpty(IsoDfName))
                return LibraryError(DesfireLibraryError.InvalidParameter);
            return CreateApplication(Aid, KeySetting1, KeySetting2, KeySetting3, AksVersion, NoKeySets, MaxKeySize, AppKeySetSetting, IsoDfId, StrUtils.ToBytes(IsoDfName));
        }

        public long CreateApplication(
          uint Aid,
          byte KeySetting1,
          byte KeySetting2,
          byte KeySetting3,
          byte AksVersion,
          byte NoKeySets,
          byte MaxKeySize,
          byte AppKeySetSetting,
          ushort IsoDfId,
          byte[] IsoDfName)
        {
            int length = 0;
            if (IsoDfName != null)
                length = IsoDfName.Length;
            return CreateApplication(Aid, KeySetting1, KeySetting2, KeySetting3, AksVersion, NoKeySets, MaxKeySize, AppKeySetSetting, IsoDfId, IsoDfName, length);
        }

        public long CreateApplication(
          uint Aid,
          byte KeySetting1,
          byte KeySetting2,
          byte KeySetting3,
          byte AksVersion,
          byte NoKeySets,
          byte MaxKeySize,
          byte AppKeySetSetting,
          ushort IsoDFId,
          byte[] IsoDFName,
          int IsoDFNameLen)
        {
            DesfireCreateApplicationParameters p = new DesfireCreateApplicationParameters();
            p.Aid = Aid;
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
            return CreateApplication(p);
        }

        public long DeleteApplication(uint Aid)
        {
            long status;

            /* Create the info block containing the command code and the given parameters. */
            xfer_length = 0;
            xfer_buffer[xfer_length++] = (byte)DesfireCommand.DELETE_APPLICATION;
            xfer_buffer[xfer_length++] = (byte)(Aid & 0x000000FF);
            Aid >>= 8;
            xfer_buffer[xfer_length++] = (byte)(Aid & 0x000000FF);
            Aid >>= 8;
            xfer_buffer[xfer_length++] = (byte)(Aid & 0x000000FF);

            if (SessionIsEV2OrGreater())
            {
                status = Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.LOOSE_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
            else
            {
                /* Communicate the info block to the card and check the operation's return status. */
                status = Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.LOOSE_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }

            /* If the current application is deleted, the root application is implicitly selected */
            if ((status == Success) && (CurrentAid == Aid))
            {
                CurrentAid = 0;
                EndSecureSession();
            }

            return status;
        }

        public long GetApplicationIDs(out uint[] ListData)
        {
            byte i;
            int recv_length = 1;
            byte[] recv_buffer = new byte[256];
            long status;

            ListData = null;
            List<uint> _ListData = new List<uint>();

            /* create the info block containing the command code */
            xfer_length = 0;
            xfer_buffer[xfer_length++] = (byte)DesfireCommand.GET_APPLICATION_IDS;
            for (; ; )
            {
                if (SessionIsEV2OrGreater())
                {
                    /* authentification CMAC is required */
                    status = Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.WANTS_ADDITIONAL_FRAME | DesfireCommandFlag.WANTS_OPERATION_OK);
                }
                else
                {
                    status = Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.WANTS_ADDITIONAL_FRAME | DesfireCommandFlag.WANTS_OPERATION_OK);
                }

                if (status != Success)
                    return status;

                if ((xfer_length - 1) > (256 - recv_length))
                {
                    Array.ConstrainedCopy(xfer_buffer, INF + 1, recv_buffer, recv_length, (256 - recv_length));
                    recv_length = 256;
                }
                else
                {
                    Array.ConstrainedCopy(xfer_buffer, INF + 1, recv_buffer, recv_length, (xfer_length - 1));
                    recv_length += (xfer_length - 1);
                }

                if (xfer_buffer[INF + 0] != (byte) DesfireCardError.AdditionalFrame)
                    break;

                xfer_length = 1;
            }

            recv_buffer[0] = (byte)Success;

            /* Check the CMAC */
            if (SessionIsEV1OrGreater())
            {
                if (!SessionCryptoContext.VerifyAndRemoveCmacRecv(recv_buffer, ref recv_length))
                    status = LibraryError(DesfireLibraryError.WrongCMAC);
            }
            if (status != Success)
                return status;

            recv_length -= 1;     /* substract 1 byte for the received status */

            /* ByteCount must be in multiples of APPLICATION_ID_SIZE bytes
               we check this to proof the format integrity
               if zero bytes have been received this is ok -> means no
               applications existing */
            if ((recv_length % APPLICATION_ID_SIZE) != 0)
                return LibraryError(DesfireLibraryError.WrongLength);

            for (i = 0; i < (recv_length / APPLICATION_ID_SIZE); i++)
            {
                /* Extract AID */
                uint aid;

                aid = recv_buffer[INF + 3 + APPLICATION_ID_SIZE * i];
                aid <<= 8;
                aid += recv_buffer[INF + 2 + APPLICATION_ID_SIZE * i];
                aid <<= 8;
                aid += recv_buffer[INF + 1 + APPLICATION_ID_SIZE * i];

                _ListData.Add(aid);
            }

            ListData = _ListData.ToArray();
            return status;
        }

        public long GetDFNames(out DesfireIsoApplication[] ListData)
        {
            byte i;
            int recv_length = 1;
            byte[] recv_buffer = new byte[1024];
            long status;

            ListData = null;
            List<DesfireIsoApplication> _ListData = new List<DesfireIsoApplication>();

            /* create the info block containing the command code */
            xfer_length = 0;
            xfer_buffer[xfer_length++] = (byte)DesfireCommand.GET_DF_NAMES;

            i = 0;
            for (; ; )
            {
                if (SessionIsEV2OrGreater())
                {
                    status = Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.WANTS_ADDITIONAL_FRAME | DesfireCommandFlag.WANTS_OPERATION_OK);
                }
                else
                {
                    status = Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.WANTS_ADDITIONAL_FRAME | DesfireCommandFlag.WANTS_OPERATION_OK);
                }


                if (status != Success)
                    return status;

                if ((xfer_length != 1) && (xfer_length < 6))
                    return LibraryError(DesfireLibraryError.WrongLength);

                /* Extract application data */
                DesfireIsoApplication _data = new DesfireIsoApplication();

                _data.Aid = xfer_buffer[INF + 3];
                _data.Aid <<= 8;
                _data.Aid += xfer_buffer[INF + 2];
                _data.Aid <<= 8;
                _data.Aid += xfer_buffer[INF + 1];

                _data.IsoId = xfer_buffer[INF + 5];
                _data.IsoId <<= 8;
                _data.IsoId += xfer_buffer[INF + 4];

                int bIsoNameLen = xfer_length - INF - 6;
                _data.IsoName = new byte[bIsoNameLen];

                for (int j = 0; j < _data.IsoName.Length; j++)
                    _data.IsoName[j] = xfer_buffer[INF + 6 + j];

                _ListData.Add(_data);
                i++;

                if ((xfer_length - 1) > (1024 - recv_length))
                {
                    Array.ConstrainedCopy(xfer_buffer, INF + 1, recv_buffer, recv_length, (1024 - recv_length));
                    recv_length = 1024;
                }
                else
                {
                    /* Remember the frame for later CMAC processing */
                    Array.ConstrainedCopy(xfer_buffer, INF + 1, recv_buffer, recv_length, (xfer_length - 1));
                    recv_length += (xfer_length - 1);
                }

                if (xfer_buffer[INF + 0] != (byte) DesfireCardError.AdditionalFrame)
                    break;

                xfer_length = 1;
            }

            recv_buffer[0] = (byte)Success;

            /* Check the CMAC */
            if (SessionIsEV1OrGreater())
            {
                if (!SessionCryptoContext.VerifyAndRemoveCmacRecv(recv_buffer, ref recv_length))
                    status = LibraryError(DesfireLibraryError.WrongCMAC);
            }
            if (status != Success)
                return status;

            recv_length -= 1;     /* substract 1 byte for the received status */

            ListData = _ListData.ToArray();
            return status;
        }

        public long SelectApplication(uint Aid)
        {
            logger.trace("SelectApplication({0:X06})", Aid);

            long status;
            uint aid_copy = Aid; /* MBA: save it ! */

            /* Each SelectApplication causes a currently valid authentication state to be lost */
            EndSecureSession();

            /* Create the info block containing the command code and the given parameters. */
            xfer_buffer[INF + 0] = (byte)DesfireCommand.SELECT_APPLICATION;
            xfer_buffer[INF + 1] = (byte)(Aid & 0x000000FF);
            Aid >>= 8;
            xfer_buffer[INF + 2] = (byte)(Aid & 0x000000FF);
            Aid >>= 8;
            xfer_buffer[INF + 3] = (byte)(Aid & 0x000000FF);
            xfer_length = 4;

            /* Communicate the info block to the card and check the operation's return status. */
            status = Command(0, DesfireCommandFlag.WANTS_OPERATION_OK);

            if (status == Success)
                CurrentAid = aid_copy;

            return status;
        }
    }
}
