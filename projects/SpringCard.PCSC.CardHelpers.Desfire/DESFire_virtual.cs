/*
 * SpringCard DESFire Library (C#)
 * Copyright (c) SpringCard SAS, 2008-2025
 *
 * This file is part of the SpringCard DESFire library.
 * See LICENSE.txt for license details and restrictions.
 *
 */
using System;
using SpringCard.LibCs;

namespace SpringCard.PCSC.CardHelpers
{
    public partial class Desfire
    {
        public long ISOSelect(byte[] IID, out byte[] PiccChal, out byte[] VCData)
        {
            long status;

            logger.trace("ISOSelect({0)", BinConvert.ToHex(IID));

            PiccChal = null;
            VCData = null;

            status = IsoApdu((byte)(byte)DesfireCommand.CMD_ISOSVC, 0x04, 0x00, IID, 0, out byte[] fci, out ushort SW);
            if (status != Success)
                return status;

            status = TranslateSW(SW, 0x00);
            if (status != Success)
                return status;

            if (fci == null)
            {
                return LibraryError(DesfireLibraryError.WrongLength);
            }

            if (fci.Length == 2)
            {
                /* Since no MAC is returned, this indicates AuthVCMandatory flag is not set and IsoSelect is success
                   * as per the ref arch(v 15) page no 283 */
            }
            else if (fci.Length == 36)
            {
                /* FCI Length should be 36 bytes excluding 2 bytes of status data */
                /* As per reference architecture, Handling the two response cases:
                 * Case-1: [if TargetVC != NULL AND TargetVC.AuthVCMandatory == true] and
                 * Case-2: [if TargetVC == NULL] in a single if-case since there is no way to get 'AuthVCMandatory' and 'targetted IID Supported' flag values */

                /* 4 Bytes Header + 16 Bytes RndChal + 16 Bytes Payload + 2 Bytes SW1||SW2 (Total 38 Bytes returned) */

                if ((fci[0] == 0x6F) &&
                   (fci[1] == 0x22) &&
                   (fci[2] == 0x85) &&
                   (fci[3] == 0x20))
                {
                    PiccChal = new byte[16];
                    Array.ConstrainedCopy(fci, 4, PiccChal, 0, 16);
                    VCData = new byte[16];
                    Array.ConstrainedCopy(fci, 20, VCData, 0, 16);
                }
            }
            else
            {
                /* Case-3: [if TargetVC != NULL AND TargetVC.AuthVCMandatory == false AND (IID is DESFire application DF name)]
                       * FCI[36] bytes shall be stored in file ID 31 of the DF */
                //memcpy(pFCI, &pRecv[0], 36);
            }

            return status;
        }

        public long ISOSelect(byte[] KeyValue, byte[] IID, out byte[] PiccChal, out byte[] VCData)
        {
            DesfireCryptoContextEV2 cryptoContext = new DesfireCryptoContextEV2(this, KeyValue);
            return ISOSelect(cryptoContext, IID, out PiccChal, out VCData);
        }

        public long ISOSelect(DesfireCryptoContextEV2 cryptoContext, byte[] IID, out byte[] PiccChal, out byte[] VCData)
        {
            long status;

            status = ISOSelect(IID, out PiccChal, out VCData);
            
            if ((PiccChal != null) && (VCData != null))
            {
                cryptoContext.CipherRecv(ref VCData);

                /* Decrypted VCData is not plain text. It needs to be XORed with PiccChal to obtain plain VCData */
                for (int i = 0; i < 16; i++)
                    VCData[i] = (byte)(VCData[i] ^ PiccChal[i]);
            }

            return status;
        }

        public long ISOExternalAuthenticate(byte[] PcdChal)
        {
            logger.trace("ISOExternalAuthenticate({0)", BinConvert.ToHex(PcdChal));

            long status;
            if ((IsoWrapping & DesfireIsoWrapping.Card) == 0)
                return LibraryError(DesfireLibraryError.InvalidParameter);

            status = IsoApdu((byte)DesfireCommand.CMD_ISOEXT_AUTH, 0x00, 0x00, PcdChal, 0, out byte[] resp, out ushort SW);
            if (status != Success)
                return status;

            status = TranslateSW(SW, 0x00);
            if (status != Success)
                return status;

            return Success;
        }

        public long ISOExternalAuthenticate(byte[] KeyValue, byte[] PiccChal, byte[] VCData)
        {
            DesfireCryptoContextEV2 cryptoContext = new DesfireCryptoContextEV2(this, KeyValue);
            return ISOExternalAuthenticate(cryptoContext, PiccChal, VCData);
        }

        public long ISOExternalAuthenticate(DesfireCryptoContextEV2 cryptoContext, byte[] PiccChal, byte[] VCData)
        {
            byte[] buffer = new byte[32];
            Array.ConstrainedCopy(PiccChal, 0, buffer, 0, 16);
            Array.ConstrainedCopy(VCData, 0, buffer, 16, 16);

            byte[] cmac = cryptoContext.ComputeCmac(buffer);

            return ISOExternalAuthenticate(cmac);
        }

        public long ISOSelectAndExternalAuthenticate(byte[] KeyValue, byte[] IID, out byte[] VCData)
        {
            long status;
            DesfireCryptoContextEV2 cryptoContext = new DesfireCryptoContextEV2(this, KeyValue);

            status = ISOSelect(cryptoContext, IID, out byte[] PiccChal, out VCData);
            if (status != Success)
                return status;

            status = ISOExternalAuthenticate(cryptoContext, PiccChal, VCData);
            if (status != Success)
                return status;

            return Success;
        }
    }
}
