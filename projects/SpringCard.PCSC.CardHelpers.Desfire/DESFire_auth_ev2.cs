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
        public long AuthenticateEV2First(byte KeyNumber, byte[] KeyValue)
        {
            return AuthenticateEV2First(KeyNumber, KeyValue, null, out byte[] dummy0, out byte[] dummy1, out byte[] dummy2);
        }

        public long AuthenticateEV2First(byte KeyNumber, byte[] KeyValue, byte[] PcdCaps2)
        {
            return AuthenticateEV2First(KeyNumber, KeyValue, PcdCaps2, out byte[] dummy0, out byte[] dummy1, out byte[] dummy2);
        }

        public long AuthenticateEV2First(byte KeyNumber, byte[] KeyValue, out byte[] PiccCaps2)
        {
            return AuthenticateEV2First(KeyNumber, KeyValue, null, out byte[] dummy0, out PiccCaps2, out byte[] dummy1);
        }

        public long AuthenticateEV2First(byte KeyNumber, byte[] KeyValue, byte[] PcdCaps2, out byte[] PiccCaps2)
        {
            return AuthenticateEV2First(KeyNumber, KeyValue, PcdCaps2, out byte[] dummy0, out PiccCaps2, out byte[] dummy1);
        }

        public long AuthenticateEV2First(byte KeyNumber, byte[] KeyValue, byte[] PcdCaps2, out byte[] PiccCaps2, out byte[] TransactionIdentifier)
        {
            return AuthenticateEV2First(KeyNumber, KeyValue, PcdCaps2, out byte[] dummy, out PiccCaps2, out TransactionIdentifier);
        }

        public long AuthenticateEV2First(byte KeyNumber, byte[] KeyValue, byte[] PcdCaps2, out byte[] PcdCaps2_echo, out byte[] PiccCaps2, out byte[] TransactionIdentifier)
        {
            DesfireCryptoContextEV2 cryptoContext = new DesfireCryptoContextEV2(this, KeyValue);
            return AuthenticateEV2First(KeyNumber, cryptoContext, PcdCaps2, out PcdCaps2_echo, out PiccCaps2, out TransactionIdentifier);
        }

        public long AuthenticateEV2First(byte KeyNumber, DesfireCryptoContextEV2 CryptoContext, byte[] PcdCaps2, out byte[] PcdCaps2_echo, out byte[] PiccCaps2, out byte[] TransactionIdentifier)
        {
            long status;
            TransactionIdentifier = null;
            PcdCaps2_echo = null;
            PiccCaps2 = null;

            if (CryptoContext == null)
                return LibraryError(DesfireLibraryError.InvalidParameter);

            logger.trace("AuthenticateEV2First({0:X02},{1:X06})", KeyNumber, CryptoContext.AuthKVC);

            /* Create the command string consisting of the command byte and the parameter byte. */
            xfer_length = 0;
            xfer_buffer[xfer_length++] = (byte)DesfireCommand.AUTHENTICATE_EV2_FIRST;
            xfer_buffer[xfer_length++] = KeyNumber;

            if (PcdCaps2 != null)
            {
                xfer_buffer[xfer_length++] = (byte)PcdCaps2.Length;
                if (PcdCaps2.Length != 0)
                {
                    Array.ConstrainedCopy(PcdCaps2, 0, xfer_buffer, xfer_length, PcdCaps2.Length);
                    xfer_length += PcdCaps2.Length;
                }
            }
            else
            {
                xfer_buffer[xfer_length++] = 0;
            }

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

            /* OK, we received the cryptogram E(Kx, RndB) from the PICC.
               Decipher E(Kx, RndB) to get RndB in xfer_buffer.
               Note that the status code has already been extracted from the queue. */
            byte[] PiccChal1 = BinUtils.Copy(xfer_buffer, 1, xfer_length - 1);
            status = CryptoContext.ProcessAuth1(PiccChal1, out byte[] PcdChal1);
            if (status != Success)
            {
                logger.trace("AuthenticateEV2First: ProcessAuth1 failed with status {0}", status);
                goto done;
            }

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

            if (xfer_length != 33)
            {
                /* Error: block with inappropriate number of bytes received from the card. */
                status = LibraryError(DesfireLibraryError.WrongLength);
                goto done;
            }

            byte[] PiccChal2 = new byte[xfer_length - 1];
            Array.ConstrainedCopy(xfer_buffer, 1, PiccChal2, 0, xfer_length - 1);
            status = CryptoContext.ProcessAuth2First(PiccChal2, out TransactionIdentifier, out PiccCaps2, out PcdCaps2_echo);
            if (status != Success)
            {
                logger.trace("AuthenticateEV2First: ProcessAuth2First failed with status {0}", status);
                goto done;
            }

            /* Good, we are authenticated! */
            logger.trace("Session Keys: ENC={0:X06} CMAC={1:X06}", CryptoContext.SessionEncKVC, CryptoContext.SessionCmacKVC);
            logger.trace("Transaction Identifier: {0}", BinConvert.ToHex(CryptoContext.TransactionIdentifier));
            BeginSecureSession(KeyNumber, CryptoContext);
            return Success;

        done:
            EndSecureSession();
            return status;
        }

        public long AuthenticateEV2NonFirst(byte KeyNumber, byte[] KeyValue)
        {
            DesfireCryptoContextEV2 cryptoContext = new DesfireCryptoContextEV2(this, KeyValue);
            return AuthenticateEV2NonFirst(KeyNumber, cryptoContext);
        }

        public long AuthenticateEV2NonFirst(byte KeyNumber, DesfireCryptoContextEV2 CryptoContext)
        {
            long status;

            if (CryptoContext == null)
                return LibraryError(DesfireLibraryError.InvalidParameter);
            if ((this.SessionCryptoContext == null) || !(this.SessionCryptoContext is DesfireCryptoContextEV2))
                return LibraryError(DesfireLibraryError.InvalidParameter); /* NonFirst authentication must follow a previous authentication */

            logger.trace("AuthenticateEV2NonFirst({0:X02},{1:X06})", KeyNumber, CryptoContext.AuthKVC);

            /* Create the command string consisting of the command byte and the parameter byte. */
            xfer_length = 0;
            xfer_buffer[xfer_length++] = (byte)DesfireCommand.AUTHENTICATHE_EV2_NONFIRST;
            xfer_buffer[xfer_length++] = KeyNumber;

            /* Send the command string to the PICC and get its response (1st frame exchange).
               The PICC has to respond with an (byte) ECardError.AdditionalFrame status byte. */
            /*do not affect the CmdCtr(neither increasing, nor resetting)*/
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

            /* OK, we received the cryptogram E(Kx, RndB) from the PICC.
               Decipher E(Kx, RndB) to get RndB in xfer_buffer.
               Note that the status code has already been extracted from the queue. */
            byte[] PiccChal1 = BinUtils.Copy(xfer_buffer, 1, xfer_length - 1);
            status = CryptoContext.ProcessAuth1(PiccChal1, out byte[] PcdChal1);
            if (status != Success)
            {
                logger.trace("AuthenticateEV2NonFirst: ProcessAuth1 failed with status {0}", status);
                goto done;
            }

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
            status = CryptoContext.ProcessAuth2NonFirst(PiccChal2);
            if (status != Success)
            {
                logger.trace("AuthenticateEV2NonFirst: ProcessAuth2NonFirst failed with status {0}", status);
                goto done;
            }

            /* Good, we are authenticated! */
            /* --------------------------- */

            /* Forward the Transaction Identifier and the Counter from the previous context to the new one */
            CryptoContext.ImportTransaction(this.SessionCryptoContext as DesfireCryptoContextEV2);

            /* And now use the new context */
            logger.trace("Session Keys: ENC={0:X06} CMAC={1:X06}", CryptoContext.SessionEncKVC, CryptoContext.SessionCmacKVC);
            BeginSecureSession(KeyNumber, CryptoContext);
            return Success;

        done:
            EndSecureSession();
            return status;
        }
    }
}
