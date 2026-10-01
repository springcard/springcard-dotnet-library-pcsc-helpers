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
    public partial class Desfire
    {

        public long Authenticate(byte KeyNumber, byte[] KeyValue)
        {
            DesfireCryptoContextEV0 cryptoContext = new DesfireCryptoContextEV0(this, KeyValue);
            return Authenticate(KeyNumber, cryptoContext);
        }

        /**
         * @brief Authenticates with the DESFire chip using the specified key.
         *
         * @param KeyNumber The key number to use for authentication.
         * @param KeyValue The key value (8 or 16 bytes).
         * @return A status code indicating the result of the operation.
         */
        private long Authenticate(byte KeyNumber, DesfireCryptoContextEV0 CryptoContext)
        {
            long status;

            if (CryptoContext == null)
                return LibraryError(DesfireLibraryError.InvalidParameter);

            logger.trace("Authenticate({0:X02},{1:X06})", KeyNumber, CryptoContext.AuthKVC);

            /* Create the command string consisting of the command byte and the parameter byte. */
            xfer_length = 0;
            xfer_buffer[xfer_length++] = (byte)DesfireCommand.AUTHENTICATE;
            xfer_buffer[xfer_length++] = KeyNumber;

            /* Send the command string to the PICC and get its response (1st frame exchange).
               The PICC has to respond with an (byte) ECardError.AdditionalFrame status byte. */
            status = Command(0, DesfireCommandFlag.WANTS_ADDITIONAL_FRAME);
            if (status != Success)
                goto done;

            /* Check the number of bytes received, we expect 9 bytes. */
            if (xfer_length != 9)
            {
                /* Error: block with inappropriate number of bytes received from the card. */
                status = LibraryError(DesfireLibraryError.WrongLength);
                goto done;
            }

            byte[] PiccChal1 = BinUtils.Copy(xfer_buffer, 1, 8);
            status = CryptoContext.ProcessAuth1(PiccChal1, out byte[] PcdChal1);
            if (status != Success)
                goto done;

            /* Start the second frame with a status byte indicating to the PICC that the Authenticate
               command is continued. */
            xfer_length = 0;
            xfer_buffer[xfer_length++] = (byte) DesfireCommand.ADDITIONAL_FRAME;
            /* Append our challenge */
            Array.ConstrainedCopy(PcdChal1, 0, xfer_buffer, xfer_length, PcdChal1.Length);
            xfer_length += PcdChal1.Length;

            /* Send the 2nd frame to the PICC and get its response. */
            status = Command(0, DesfireCommandFlag.WANTS_OPERATION_OK);
            if (status != Success)
                goto done;

            if (xfer_length != 9)
            {
                /* Error: block with inappropriate number of bytes received from the card. */
                status = LibraryError(DesfireLibraryError.WrongLength);
                goto done;
            }

            byte[] PiccChal2 = new byte[8];
            Array.ConstrainedCopy(xfer_buffer, 1, PiccChal2, 0, 8);
            status = CryptoContext.ProcessAuth2(PiccChal2);
            if (status != Success)
                goto done;

            /* Good, we are authenticated! */
            logger.trace("Session Key is {0:X06}", CryptoContext.SessionKVC);
            BeginSecureSession(KeyNumber, CryptoContext);
            return Success;

        done:
            EndSecureSession();
            return status;
        }
    }
}
