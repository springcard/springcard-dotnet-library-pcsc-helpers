/*
 * Created by SharpDevelop.
 * User: Jerome Izaac
 * Date: 15/09/2017
 * Time: 10:34
 * 
 * To change this template use Tools | Options | Coding | Edit Standard Headers.
 */
using SpringCard.LibCs;
using System;
using System.Security.Cryptography;

namespace SpringCard.PCSC.CardHelpers
{
    /// <summary>
    /// Description of DESFire_keys.
    /// </summary>
    public partial class Desfire
    {
        public long ChangeKey(byte KeyNumber, byte KeyVersion, byte[] NewKeyValue, byte[] OldKeyValue)
        {
            if (SessionIsEV2OrGreater())
            {
                return ChangeKeyExEV2((byte)DesfireCommand.CHANGE_KEY, false, 0, KeyNumber, true, KeyVersion, NewKeyValue, OldKeyValue);
            }
            else if (SessionIsEV1OrGreater())
            {
                return ChangeKeyExEV1(KeyNumber, true, KeyVersion, NewKeyValue, OldKeyValue);
            }
            else
            {
                logger.debug("ChangeKey[AES] called outside a EV1 or EV2 session");
                return LibraryError(DesfireLibraryError.InvalidParameter);
            }
        }

        public long ChangeKeyAes(byte KeyNumber, byte KeyVersion, byte[] NewKeyValue, byte[] OldKeyValue)
        {
            return ChangeKey(KeyNumber, KeyVersion, NewKeyValue, OldKeyValue);
        }

        /**
 * @fn *   ChangeKeyAes
 * @brief *   Change an AES key in the selected Desfire application.
 * @details
 * *
 * @return *   DesfireCommand.OPERATION_OK    : change succeeded
 */
        private long ChangeKeyExEV1(byte KeyNumber, bool WithVersion, byte KeyVersion, byte[] NewKeyValue, byte[] OldKeyValue)
        {
            if (NewKeyValue == null)
                return LibraryError(DesfireLibraryError.InvalidParameter);

            if (WithVersion)
            {
                logger.trace("ChangeKeyEV1({0:X02},{1:X02} length={2})", KeyNumber, KeyVersion, NewKeyValue.Length);
            }
            else
            {
                logger.trace("ChangeKeyEV1({0:X02} length={1})", KeyNumber, NewKeyValue.Length);
            }

            if (logSecrets)
            {
                logger.debug("New key: {0}", BinConvert.ToHex(NewKeyValue));
                if (OldKeyValue != null)
                    logger.debug("Old key: {0}", BinConvert.ToHex(OldKeyValue));
            }

            int KeySize = NewKeyValue.Length;
            switch (KeySize)
            {
                case 16:
                case 24:
                case 32:
                    break;

                default:
                    logger.debug("KeySize is {0}B", KeySize);
                    return LibraryError(DesfireLibraryError.InvalidParameter);
            }

            if ((OldKeyValue != null) && (OldKeyValue.Length != NewKeyValue.Length))
                return LibraryError(DesfireLibraryError.InvalidParameter);

            RememberChangeKey(KeyNumber, NewKeyValue);

            bool endSession = false;

            /* We'll be forgetting the current authentication state if we're changing the current key */
            if ((KeyNumber & 0x3F) == GetSessionKeyNumber())
            {
                logger.debug("Changing the authentication key itself will end the session");
                endSession = true;
            }

            /* Place the header */
            xfer_length = 0;
            xfer_buffer[xfer_length++] = (byte)DesfireCommand.CHANGE_KEY;
            xfer_buffer[xfer_length++] = KeyNumber;

            /* Put the new key into the buffer. */
            Array.ConstrainedCopy(NewKeyValue, 0, xfer_buffer, xfer_length, KeySize);
            xfer_length += KeySize;

            byte[] crc32 = new byte[4];
            if (OldKeyValue != null)
            {
                /* If a 'previous key' has been passed, format the 40 byte cryptogram according to the     */
                /* three key procedure (new key, previous key, all encrypted with the current session key) */

                /* XOR the previous key with the new key. */
                for (int i = 0; i < KeySize; i++)
                    xfer_buffer[xfer_length - KeySize + i] ^= OldKeyValue[i];

                if (logSecrets)
                    logger.debug("XOR key: {0}", BinConvert.ToHex(xfer_buffer, xfer_length - KeySize, KeySize));

                if (WithVersion)
                {
                    /* The key version goes here */
                    xfer_buffer[xfer_length++] = KeyVersion;
                }

                /* Append a first CRC, computed over the XORed key combination and the header */

                ComputeCrc32(xfer_buffer, xfer_length, ref crc32);
                Array.ConstrainedCopy(crc32, 0, xfer_buffer, xfer_length, 4);

                xfer_length += 4;

                /* Append a second CRC, computed over the new key only. */
                ComputeCrc32(NewKeyValue, KeySize, ref crc32);
                Array.ConstrainedCopy(crc32, 0, xfer_buffer, xfer_length, 4);
                xfer_length += 4;

            }
            else
            {
                /* If no 'previous key' has been passed, format the 32 byte cryptogram according to the */
                /* two key procedure (new key, encrypted with the current session key).                 */

                if (WithVersion)
                {
                    /* The key version goes here */
                    xfer_buffer[xfer_length++] = KeyVersion;
                }

                /* Append the CRC computed over the new key and the header */
                ComputeCrc32(xfer_buffer, xfer_length, ref crc32);
                Array.ConstrainedCopy(crc32, 0, xfer_buffer, xfer_length, 4);
                xfer_length += 4;
            }

            /* 'Encrypt' the buffer */
            Xfer_Padd_CipherSend(2);

            /* Communicate the info block to the card and check the operation's return status. */
            long status;
            if (endSession)
                status = Command(0, DesfireCommandFlag.WANTS_OPERATION_OK); /* No CMAC since the session is terminating */
            else
                status = Command(0, DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            if (status != Success)
                return status;

            /* Forget the current authentication state if we're changing the current key */
            if (endSession)
                EndSecureSession();

            return Success;
        }
    }
}
