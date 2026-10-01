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
        public long ReadSign(byte Addr, out byte[] Data)
        {
            int recv_length = 0;
            long status;

            Data = null;

            /* create the info block containing the command code */
            xfer_length = 0;
            xfer_buffer[xfer_length++] = (byte)DesfireCommand.READ_SIGN;
            xfer_buffer[xfer_length++] = Addr;

            if (SessionIsEV1OrGreater())
            {
                status = Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
            else
            {
                status = Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }

            if (status != (byte)DesfireCardError.MoreOperationOK)
                return status;

            recv_length = xfer_length;

            if (SessionIsEV1OrGreater())
            {
                recv_length = xfer_length - 1;

                byte[] data = new byte[recv_length];
                Array.ConstrainedCopy(xfer_buffer, 1, data, 0, recv_length);

                SessionCryptoContext.CipherRecv(ref data, ref recv_length);

                /* remove cmac */
                if ((recv_length - 1) != ORIGINALITY_SIGN_LENGTH_ENC)
                {
                    status = LibraryError(DesfireLibraryError.WrongLength);
                }

                Data = BinUtils.Copy(data, 0, recv_length);
            }
            else
            {
                if ((recv_length - 1) != ORIGINALITY_SIGN_LENGTH)
                {
                    status = LibraryError(DesfireLibraryError.WrongLength);
                }

                Data = BinUtils.Copy(xfer_buffer, 1, recv_length - 1);
            }

            return status;
        }

    }
}
