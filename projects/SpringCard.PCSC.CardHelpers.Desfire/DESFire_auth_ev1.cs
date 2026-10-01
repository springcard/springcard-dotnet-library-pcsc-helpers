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
        public long AuthenticateISO(byte KeyNumber, byte[] KeyValue)
        {
            return AuthenticateEV1TDes(KeyNumber, KeyValue);
        }

        public long AuthenticateAes(byte KeyNumber, byte[] KeyValue)
        {
            return AuthenticateEV1Aes(KeyNumber, KeyValue);
        }

        public long AuthenticateEV1TDes(byte KeyNumber, byte[] KeyValue)
        {
            if (KeyValue == null)
                return LibraryError(DesfireLibraryError.InvalidParameter);

            switch (KeyValue.Length)
            {
                case 16:
                    return AuthenticateEV1TDes2K(KeyNumber, KeyValue);
                case 24:
                    return AuthenticateEV1TDes3K(KeyNumber, KeyValue);
            }

            return LibraryError(DesfireLibraryError.InvalidParameter);
        }

        public long AuthenticateEV1TDes2K(byte KeyNumber, byte[] KeyValue)
        {
            byte[] bKeyBuffer24 = new byte[24];

            if (KeyValue == null)
                return LibraryError(DesfireLibraryError.InvalidParameter);

            if (KeyValue.Length != 16)
                return LibraryError(DesfireLibraryError.InvalidParameter);

            Array.ConstrainedCopy(KeyValue, 0, bKeyBuffer24, 0, 16);
            Array.ConstrainedCopy(KeyValue, 0, bKeyBuffer24, 16, 8);

            return AuthenticateEV1TDes3K(KeyNumber, bKeyBuffer24);
        }

        public long AuthenticateEV1TDes3K(byte KeyNumber, byte[] KeyValue)
        {
            DesfireCryptoContextEV1TDes cryptoContext = new DesfireCryptoContextEV1TDes(this, KeyValue);
            return AuthenticateEV1(KeyNumber, cryptoContext);
        }

        public long AuthenticateEV1(byte KeyNumber, DesfireCryptoContextEV1TDes CryptoContext)
        {
            long status;

            if (CryptoContext == null)
                return LibraryError(DesfireLibraryError.InvalidParameter);

            logger.trace("AuthenticateISO({0:X02},{1:X06})", KeyNumber, CryptoContext.AuthKVC);

            /* Create the command string consisting of the command byte and the parameter byte. */
            xfer_buffer[INF + 0] = (byte)DesfireCommand.AUTHENTICATE_ISO;
            xfer_buffer[INF + 1] = KeyNumber;
            xfer_length = 2;

            /* Send the command string to the PICC and get its response (1st frame exchange).
               The PICC has to respond with an (byte) ECardError.AdditionalFrame status byte. */
            status = Command(0, DesfireCommandFlag.WANTS_ADDITIONAL_FRAME);
            if (status != Success)
                goto done;

            /* Check the number of bytes received, we expect 9 or 17 bytes. */
            if ((xfer_length != 9) && (xfer_length != 17))
            {
                /* Error: block with inappropriate number of bytes received from the card. */
                status = LibraryError(DesfireLibraryError.WrongLength);
                goto done;
            }

            byte[] PiccChal1 = BinUtils.Copy(xfer_buffer, 1, xfer_length - 1);
            status = CryptoContext.ProcessAuth1(PiccChal1, out byte[] PcdChal1);
            if (status != Success)
                goto done;

            /* Start the second frame with a status byte indicating to the PICC that the Authenticate
               command is continued. */
            xfer_length = 0;
            xfer_buffer[xfer_length++] = (byte)DesfireCommand.ADDITIONAL_FRAME;
            /* Append our challenge */
            Array.ConstrainedCopy(PcdChal1, 0, xfer_buffer, xfer_length, PcdChal1.Length);
            xfer_length += PcdChal1.Length;

            /* Send the 2nd frame to the PICC and get its response. */
            status = Command(0, DesfireCommandFlag.WANTS_OPERATION_OK);
            if (status != Success)
                goto done;

            if ((xfer_length != 9) && (xfer_length != 17))
            {
                /* Error: block with inappropriate number of bytes received from the card. */
                status = LibraryError(DesfireLibraryError.WrongLength);
                goto done;
            }

            byte[] PiccChal2 = new byte[xfer_length - 1];
            Array.ConstrainedCopy(xfer_buffer, 1, PiccChal2, 0, xfer_length - 1);
            status = CryptoContext.ProcessAuth2(PiccChal2);
            if (status != Success)
                goto done;

            /* Good, we are authenticated! */
            logger.trace("Session Key is {0:X06})", CryptoContext.SessionKVC);
            BeginSecureSession(KeyNumber, CryptoContext);
            return Success;

        done:
            EndSecureSession();
            return status;
        }

        public long AuthenticateEV1Aes(byte KeyNumber, byte[] KeyValue)
        {
            DesfireCryptoContextEV1Aes cryptoContext = new DesfireCryptoContextEV1Aes(this, KeyValue);
            return AuthenticateEV1Aes(KeyNumber, cryptoContext);
        }

        public long AuthenticateEV1Aes(byte KeyNumber, DesfireCryptoContextEV1Aes CryptoContext)
        {
            long status;

            if (CryptoContext == null)
                return LibraryError(DesfireLibraryError.InvalidParameter);

            logger.trace("AuthenticateAES({0:X02},{1:X06})", KeyNumber, CryptoContext.AuthKVC);

            /* Create the command string consisting of the command byte and the parameter byte. */
            xfer_buffer[INF + 0] = (byte)DesfireCommand.AUTHENTICATE_AES;
            xfer_buffer[INF + 1] = KeyNumber;
            xfer_length = 2;

            /* Send the command string to the PICC and get its response (1st frame exchange).
               The PICC has to respond with an (byte) ECardError.AdditionalFrame status byte. */
            status = Command(0, DesfireCommandFlag.WANTS_ADDITIONAL_FRAME);
            if (status != Success)
                goto done;

            /* Check the number of bytes received, we expect 17 bytes. */
            if (xfer_length != 17)
            {
                /* Error: block with inappropriate number of bytes received from the card. */
                status = LibraryError(DesfireLibraryError.WrongLength);
                goto done;
            }

            /* OK, we received the cryptogram Ek( RndB ) from the PICC.
               Decipher Ek( RndB ) to get RndB in xfer_buffer.
               Note that the status code has already been extracted from the queue. */
            byte[] PiccChal1 = BinUtils.Copy(xfer_buffer, 1, xfer_length - 1);
            status = CryptoContext.ProcessAuth1(PiccChal1, out byte[] PcdChal1);
            if (status != Success)
                goto done;

            /* Start the second frame with a status byte indicating to the PICC that the Authenticate
               command is continued. */
            xfer_length = 0;
            xfer_buffer[xfer_length++] = (byte)DesfireCommand.ADDITIONAL_FRAME;
            /* Append our challenge */
            Array.ConstrainedCopy(PcdChal1, 0, xfer_buffer, xfer_length, PcdChal1.Length);
            xfer_length += PcdChal1.Length;

            /* Send the 2nd frame to the PICC and get its response. */
            status = Command(0, DesfireCommandFlag.WANTS_OPERATION_OK);
            if (status != Success)
                goto done;

            if (xfer_length != 17)
            {
                /* Error: block with inappropriate number of bytes received from the card. */
                status = LibraryError(DesfireLibraryError.WrongLength);
                goto done;
            }

            byte[] PiccChal2 = new byte[xfer_length - 1];
            Array.ConstrainedCopy(xfer_buffer, 1, PiccChal2, 0, xfer_length - 1);
            status = CryptoContext.ProcessAuth2(PiccChal2);
            if (status != Success)
                goto done;

            /* Good, we are authenticated! */
            logger.trace("Session Key is {0:X06})", CryptoContext.SessionKVC);
            BeginSecureSession(KeyNumber, CryptoContext);
            return Success;

        done:
            EndSecureSession();
            return status;
        }

    }
}
