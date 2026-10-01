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

namespace SpringCard.PCSC.CardHelpers
{
    /// <summary>
    /// Description of DESFire_keys.
    /// </summary>
    public partial class Desfire
    {
        public long ChangeKey(byte KeyNumber, byte[] NewKeyValue, byte[] OldKeyValue)
        {
            if (SessionIsEV2OrGreater())
            {
                return ChangeKeyExEV2((byte)DesfireCommand.CHANGE_KEY, false, 0, KeyNumber, false, 0, NewKeyValue, OldKeyValue);
            }
            else if (SessionIsEV1OrGreater())
            {
                return ChangeKeyExEV1(KeyNumber, false, 0, NewKeyValue, OldKeyValue);
            }
            else
            {
                return ChangeKeyExEV0(KeyNumber, NewKeyValue, OldKeyValue);
            }            
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="KeySetNumber"></param>
        /// <param name="KeyNumber"></param>
        /// <param name="NewKeyValue"></param>
        /// <param name="OldKeyValue"></param>
        /// <returns></returns>
        private long ChangeKeyExEV0(byte KeyNumber, byte[] NewKeyValue, byte[] OldKeyValue)
        {
            int HeaderSize = 2;
            byte b;
            byte[] buffer = new byte[24];

            logger.trace("ChangeKey16({0:X02})", KeyNumber);
            if (logSecrets)
            {
                logger.debug("New key: {0}", BinConvert.ToHex(NewKeyValue));
                if (OldKeyValue != null)
                    logger.debug("Old key: {0}", BinConvert.ToHex(OldKeyValue));
            }

            RememberChangeKey(KeyNumber, NewKeyValue);

            bool endSession = false;
            /* Forget the current authentication state if we're changing the current key */
            if ((KeyNumber & 0x3F) == GetSessionKeyNumber())
                endSession = true;

            for (int k = 0; k < buffer.Length; k++)
                buffer[k] = 0;

            /* Begin the info block with the command code and the number of the key to be changed. */
            xfer_length = 0;
            xfer_buffer[xfer_length++] = (byte)DesfireCommand.CHANGE_KEY;
            xfer_buffer[xfer_length++] = KeyNumber;

            byte[] crc16 = new byte[2];
            if (OldKeyValue != null)
            {
                /* If a 'previous key' has been passed, format the 24 byte cryptogram according to the     */
                /* three key procedure (new key, previous key, all encrypted with the current session key) */

                /* Take the new key into the buffer. */
                Array.ConstrainedCopy(NewKeyValue, 0, buffer, 0, 16);

                /* XOR the previous key to the new key. */
                for (b = 0; b < 16; b++)
                    buffer[b] ^= OldKeyValue[b];

                /* Append a first CRC, computed over the XORed key combination. */
                ComputeCrc16(buffer, 16, ref crc16);
                Array.ConstrainedCopy(crc16, 0, buffer, 16, 2);

                /* Append a second CRC, computed over the new key only. */
                ComputeCrc16(NewKeyValue, 16, ref crc16);
                Array.ConstrainedCopy(crc16, 0, buffer, 18, 2);

            }
            else
            {
                /* If no 'previous key' has been passed, format the 24 byte cryptogram according to the */
                /* two key procedure (new key, encrypted with the current session key).                 */

                /* Take the new key into the buffer. */
                for (int k = 0; k < 16; k++)
                    buffer[k] = NewKeyValue[k];

                /* Append the CRC computed over the new key. */
                ComputeCrc16(NewKeyValue, 16, ref crc16);
                Array.ConstrainedCopy(crc16, 0, buffer, 16, 2);

            }

            /* Append the 24 byte buffer to the command string. */
            Array.ConstrainedCopy(buffer, 0, xfer_buffer, xfer_length, 24);
            xfer_length += 24;

            /* 'Encrypt' the 24 bytes */
            Xfer_Padd_CipherSend(HeaderSize);

            /* Communicate the info block to the card and check the operation's return status. */
            long status;
            if (endSession)
            {
                status = Command(0, DesfireCommandFlag.WANTS_OPERATION_OK);
            }
            else
            {
                status = Command(0, DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }

            if (status != Success)
                return status;

            /* Forget the current authentication state if we're changing the current key */
            if (endSession)
                EndSecureSession();

            return Success;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="KeyNumber"></param>
        /// <param name="NewKeyValue"></param>
        /// <param name="OldKeyValue"></param>
        /// <param name="HeaderSize"></param>
        /// <returns></returns>
        private long ChangeKeyEx(byte[] Header, byte[] NewKeyValue, byte[] OldKeyValue)
        {
            if ((Header == null) || (Header.Length < 2))
                return LibraryError(DesfireLibraryError.InvalidParameter);
            
            if ((NewKeyValue == null) || ((NewKeyValue.Length != 16) && (NewKeyValue.Length != 24)))
                return LibraryError(DesfireLibraryError.InvalidParameter);

            int KeySize = NewKeyValue.Length;

            if ((OldKeyValue != null) && (OldKeyValue.Length != KeySize))
                return LibraryError(DesfireLibraryError.InvalidParameter);

            byte KeyNumber = Header[Header.Length - 1];
            logger.trace("ChangeKeyEx({0:X02}, {1})", KeyNumber, KeySize);
            if (logSecrets)
            {
                logger.debug("New key: {0}", BinConvert.ToHex(NewKeyValue));
                if (OldKeyValue != null)
                    logger.debug("Old key: {0}", BinConvert.ToHex(OldKeyValue));
            }

            RememberChangeKey(KeyNumber, NewKeyValue);

            bool endSession = false;
            /* Forget the current authentication state if we're changing the current key */
            if ((KeyNumber & 0x3F) == GetSessionKeyNumber())
                endSession = true;

            byte b = 0x00;

            /* Place the header */
            xfer_length = 0;
            Array.ConstrainedCopy(Header, 0, xfer_buffer, xfer_length, Header.Length);
            xfer_length += Header.Length;

            /* Take the new key into the buffer. */
            Array.ConstrainedCopy(NewKeyValue, 0, xfer_buffer, xfer_length, KeySize);
            xfer_length += KeySize;

            byte[] crc32 = new byte[4];
            if (OldKeyValue != null)
            {
                /* If a 'previous key' has been passed, format the 40 byte cryptogram according to the     */
                /* three key procedure (new key, previous key, all encrypted with the current session key) */

                /* XOR the previous key with the new key. */
                for (b = 0; b < KeySize; b++)
                    xfer_buffer[xfer_length - KeySize + b] ^= OldKeyValue[b];

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

                /* Append the CRC computed over the new key and the header */
                ComputeCrc32(xfer_buffer, xfer_length, ref crc32);
                Array.ConstrainedCopy(crc32, 0, xfer_buffer, xfer_length, 4);
                xfer_length += 4;
            }

            /* 'Encrypt' the buffer */
            Xfer_Padd_CipherSend(Header.Length);

            /* Communicate the info block to the card and check the operation's return status. */
            long status;

            if (endSession)
            {
                status = Command(0, DesfireCommandFlag.WANTS_OPERATION_OK);
            }
            else
            {
                status = Command(0, DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
            if (status != Success)
                return status;

            /* Forget the current authentication state if we're changing the current key */
            if (endSession)
                EndSecureSession();

            return Success;
        }

        /**
 * @fn *   ChangeKey24
 * @brief *   Change a 3DES3K key in the selected Desfire application.
 * @details
 * *
 * @return *   DesfireCommand.OPERATION_OK    : change succeeded
 */

#if TODO
        public long ChangeKey(byte KeyNumber, byte[] NewKeyValue, byte[] OldKeyValue)
        {
            if ((NewKeyValue == null) || (NewKeyValue.Length != 24))
                return error(ELibError.InvalidParameter);

            if (OldKeyValue != null)
            {
                if (OldKeyValue.Length == 8)
                    OldKeyValue = BinUtils.Concat(OldKeyValue, OldKeyValue);
                if (OldKeyValue.Length == 16)
                    OldKeyValue = BinUtils.Concat(OldKeyValue, BinUtils.Copy(OldKeyValue, 0, 8));
                if (OldKeyValue.Length != 24)
                    return error(ELibError.InvalidParameter);
            }

            if (SessionIsEV2OrGreater())
            {
                return ChangeKeyExEV2((byte)DesfireCommand.CHANGE_KEY, false, 0, KeyNumber, false, 0, NewKeyValue, OldKeyValue);
            }
            else if (SessionIsEV1OrGreater())
            {
                return ChangeKeyExEV1(KeyNumber, false, 0, NewKeyValue, OldKeyValue);
            }
            else
            {
                return error(ELibError.InvalidParameter);
            }                
        }
#endif
    }
}
