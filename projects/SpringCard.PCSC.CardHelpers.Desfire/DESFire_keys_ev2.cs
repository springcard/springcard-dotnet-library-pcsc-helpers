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
        public long ChangeKeyEV2(byte KeySetNumber, byte KeyNumber, byte[] NewKeyValue, byte[] OldKeyValue)
        {
            if (NewKeyValue == null)
                return LibraryError(DesfireLibraryError.InvalidParameter);

            if (NewKeyValue.Length == 16)
                return ChangeKey16EV2(KeySetNumber, KeyNumber, NewKeyValue, OldKeyValue);

            if (NewKeyValue.Length == 24)
                return ChangeKey24EV2(KeySetNumber, KeyNumber, NewKeyValue, OldKeyValue);

            return LibraryError(DesfireLibraryError.InvalidParameter);
        }

        public long ChangeKey16EV2(byte KeySetNumber, byte KeyNumber, byte[] NewKeyValue, byte[] OldKeyValue)
        {
            if ((NewKeyValue == null) || (NewKeyValue.Length != 16))
                return LibraryError(DesfireLibraryError.InvalidParameter);

            if (OldKeyValue != null)
            {
                if (OldKeyValue.Length == 8)
                    OldKeyValue = BinUtils.Concat(OldKeyValue, OldKeyValue);
                if (OldKeyValue.Length != 16)
                    return LibraryError(DesfireLibraryError.InvalidParameter);
            }

            if (SessionIsEV2OrGreater())
            {
                return ChangeKeyExEV2((byte)DesfireCommand.CHANGE_KEY_EV2, true, KeySetNumber, KeyNumber, false, 0, NewKeyValue, OldKeyValue);
            }
            else
            {
                return LibraryError(DesfireLibraryError.InvalidParameter);
            }
        }

        public long ChangeKey24EV2(byte KeySetNumber, byte KeyNumber, byte[] NewKeyValue, byte[] OldKeyValue)
        {
            if ((NewKeyValue == null) || (NewKeyValue.Length != 24))
                return LibraryError(DesfireLibraryError.InvalidParameter);

            if (OldKeyValue != null)
            {
                if (OldKeyValue.Length == 8)
                    OldKeyValue = BinUtils.Concat(OldKeyValue, OldKeyValue);
                if (OldKeyValue.Length == 16)
                    OldKeyValue = BinUtils.Concat(OldKeyValue, BinUtils.Copy(OldKeyValue, 0, 8));
                if (OldKeyValue.Length != 24)
                    return LibraryError(DesfireLibraryError.InvalidParameter);
            }

            if (SessionIsEV2OrGreater())
            {
                return ChangeKeyExEV2((byte)DesfireCommand.CHANGE_KEY_EV2, true, KeySetNumber, KeyNumber, false, 0, NewKeyValue, OldKeyValue);
            }
            else
            {
                return LibraryError(DesfireLibraryError.InvalidParameter);
            }
        }

        public long ChangeKeyEV2(byte KeySetNumber, byte KeyNumber, byte KeyVersion, byte[] NewKeyValue, byte[] OldKeyValue)
        {
            if ((NewKeyValue == null) || (NewKeyValue.Length != 16))
                return LibraryError(DesfireLibraryError.InvalidParameter);

            if (OldKeyValue != null)
                if (OldKeyValue.Length != 16)
                    return LibraryError(DesfireLibraryError.InvalidParameter);

            if (SessionIsEV2OrGreater())
            {
                return ChangeKeyExEV2((byte)DesfireCommand.CHANGE_KEY_EV2, true, KeySetNumber, KeyNumber, true, KeyVersion, NewKeyValue, OldKeyValue);
            }
            else
            {
                return LibraryError(DesfireLibraryError.InvalidParameter);
            }
        }

        private long ChangeKeyExEV2(byte OpCode, bool WithKeyset, byte KeySetNumber, byte KeyNumber, bool WithVersion, byte KeyVersion, byte[] NewKeyValue, byte[] OldKeyValue)
        {
            if (NewKeyValue == null)
                return LibraryError(DesfireLibraryError.InvalidParameter);
            if ((OldKeyValue != null) && (OldKeyValue.Length != NewKeyValue.Length))
                return LibraryError(DesfireLibraryError.InvalidParameter);

            bool otherKeyset = false;
            if (WithKeyset)
                if (KeySetNumber != 0x00)
                    otherKeyset = true;

            if (WithKeyset && WithVersion)
            {
                logger.trace("ChangeKeyEV2[{0:X02}]({1:X02}.{2:X02},{3:X02})", OpCode, KeySetNumber, KeyNumber, KeyVersion);
            }
            else if (WithKeyset)
            {
                logger.trace("ChangeKeyEV2[{0:X02}]({1:X02}.{2:X02})", OpCode, KeySetNumber, KeyNumber);
            }
            else if (WithVersion)
            {
                logger.trace("ChangeKeyEV2[{0:X02}]({1:X02},{2:X02})", OpCode, KeyNumber, KeyVersion);
            }
            else
            {
                logger.trace("ChangeKeyEV2[{0:X02}]({1:X02})", OpCode, KeyNumber);
            }

            if (logSecrets)
            {
                logger.debug("New key: {0}", BinConvert.ToHex(NewKeyValue));
                if (OldKeyValue != null)
                    logger.debug("Old key: {0}", BinConvert.ToHex(OldKeyValue));
            }

            int KeySize = NewKeyValue.Length;
            if ((KeySize != 16) && (KeySize != 32))
            {
                logger.debug("KeySize is {0}B", KeySize);
                return LibraryError(DesfireLibraryError.InvalidParameter);
            }

            if (!otherKeyset)
            {
                RememberChangeKey(KeyNumber, NewKeyValue);
            }

            bool endSession = false;

            /* We'll be forgetting the current authentication state if we're changing the current key */
            if (!otherKeyset && ((KeyNumber & 0x3F) == GetSessionKeyNumber()))
            {
                logger.debug("Changing the authentication key itself will end the session");
                endSession = true;
            }

            /* Place the header */
            xfer_length = 0;
            xfer_buffer[xfer_length++] = OpCode;
            if (WithKeyset)
                xfer_buffer[xfer_length++] = KeySetNumber;
            xfer_buffer[xfer_length++] = KeyNumber;

            int headerLength = xfer_length;

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

                /* Append a CRC, computed over the new key only. */
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
            }

            /* 'Encrypt' the buffer */
            Xfer_Padd_CipherSend(headerLength);

            /* Add the CMAC */
            Xfer_AppendCmac();

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
