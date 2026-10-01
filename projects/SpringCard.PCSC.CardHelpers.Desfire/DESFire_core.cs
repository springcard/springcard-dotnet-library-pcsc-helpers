/*
 * Created by SharpDevelop.
 * User: Jerome Izaac
 * Date: 08/09/2017
 * Time: 14:03
 * 
 * To change this template use Tools | Options | Coding | Edit Standard Headers.
 */
using System;
using System.Net.NetworkInformation;
using SpringCard.LibCs;

namespace SpringCard.PCSC.CardHelpers
{
    /// <summary>
    /// Description of DESFire_core.
    /// </summary>
    public partial class Desfire
    {
        [Flags]
        private enum DesfireCommandFlag
        {
            WANTS_OPERATION_OK = 0x0001,
            WANTS_ADDITIONAL_FRAME = 0x0002,
            FAST_CHAINING_ALLOWED = 0x0004,

            APPEND_COMMAND_CMAC = 0x0010,
            COMPUTE_COMMAND_CMAC = 0x0020,
            CHECK_RESPONSE_CMAC = 0x0040,
            LOOSE_RESPONSE_CMAC = 0x0080,

            INCREMENT_COUNTER = 0x0100,
        }

        private long Command(DesfireCommandFlag flags)
        {
            return Command(-1, flags);
        }


        byte lastCommand;

        private long Command(int accept_len, DesfireCommandFlag flags)
        {
            long status;

            if (xfer_buffer[0] != 0xAF)
                lastCommand = xfer_buffer[0];

            if (SessionIsEV2OrGreater())
            {
                /* EV2 CMAC is calculated but not sent for certain command */
                if ((flags & (DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC)) != 0)
                {
                    /* compute cmac only when first frame of a command */
                    if (xfer_buffer[0] != (byte) DesfireCardError.AdditionalFrame)
                    {
                        byte[] cmac = SessionCryptoContext.ComputeCmacSend(xfer_buffer, xfer_length);
                        if ((flags & DesfireCommandFlag.APPEND_COMMAND_CMAC) != 0)
                        {
                            Array.ConstrainedCopy(cmac, 0, xfer_buffer, xfer_length, cmac.Length);
                            xfer_length += cmac.Length;
                        }
                    }
                }
            }
            else if (SessionIsEV1OrGreater())
            {
                /* EV1 CMAC is calculated but not sent for certain command */
                    if ((flags & (DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC)) != 0)
                {
                    /* compute cmac only when first frame of a command */
                    if (xfer_buffer[0] != (byte) DesfireCardError.AdditionalFrame)
                    {
                        byte[] cmac = SessionCryptoContext.ComputeCmacSend(xfer_buffer, xfer_length);
                        if ((flags & DesfireCommandFlag.APPEND_COMMAND_CMAC) != 0)
                        {
                            Array.ConstrainedCopy(cmac, 0, xfer_buffer, xfer_length, cmac.Length);
                            xfer_length += cmac.Length;
                        }
                    }                   
                }
            }

            status = Exchange();

            if (status != Success)
            {
                logger.debug("Exchange->{0}", status);
                return status;
            }

            /* Check whether the PICC's response consists of at least one byte.         */
            /* If the response is empty, we can not even determine the PICC's status.   */
            /* Therefore an empty response is always a length error.                    */
            if ((xfer_length < 1) /* || (xfer_length > max_frame_size)*/)
            {
                /* Error: block with inappropriate number of bytes received from the PICC. */
                logger.debug("Received {0}B, too short", xfer_length);
                return LibraryError(DesfireLibraryError.WrongLength);
            }

            /*  Check the status byte received from the PICC.
            Depending on which of the flags (sgbWANTS_OPERATION_OK and sgbWANTS_ADDITIONAL_FRAME)
            are set in the bExpectedStatusFlags parameter, we accept either the status byte
            sgbOPERATION_OK or the status byte sgb(byte) ECardError.AdditionalFrame or both of them. */
            switch (xfer_buffer[0])
            {
                case (byte) Success:
                    if ((flags & DesfireCommandFlag.WANTS_OPERATION_OK) == 0)
                    {
                        logger.debug("Unexpected status 00");
                        return LibraryError(DesfireLibraryError.UnexpectedTermination);
                    }
                    break;
                case (byte)DesfireCardError.AdditionalFrame:
                    if ((flags & DesfireCommandFlag.WANTS_ADDITIONAL_FRAME) == 0)
                    {
                        logger.debug("Unexpected status AF");
                        return LibraryError(DesfireLibraryError.UnexpectedChaining);
                    }
                    break;
                default:
                    /* Error: error or unexpected status received from the PICC. */
                    logger.debug("Card status is {0:X02} -> error {1}", xfer_buffer[0], (DesfireCardError)xfer_buffer[0]);
                    return CardError(xfer_buffer[0]);
            }

            if ((flags & (DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.LOOSE_RESPONSE_CMAC)) != 0)
            {
                if (SessionIsEV1OrGreater())
                {
                    string sessionText = "EV1";
                    if (SessionIsEV2OrGreater())
                        sessionText = "EV2";

                    logger.debug("Session is EV1 or greater (actually {0}), expecting CMAC", sessionText);

                    /* Go into CMAC stuff */
                    /* If authenticated with SAM, Desfire_XferCmacRecv uses the SAM*/
                    if (xfer_buffer[0] == (byte) DesfireCardError.AdditionalFrame)
                        return LibraryError(DesfireLibraryError.UnexpectedChaining);

                    bool cmacMissing = false;
                    if (xfer_length <= SessionCryptoContext.CmacSize)
                    {
                        if ((flags & DesfireCommandFlag.LOOSE_RESPONSE_CMAC) != 0)
                        {
                            logger.debug("{0} CMAC missing (ignored)", sessionText);
                            cmacMissing = true;
                        }
                        else
                        {
                            logger.debug("{0} received length error (no room for CMAC)", sessionText);
                            return LibraryError(DesfireLibraryError.WrongLength);
                        }
                    }

                    if (!cmacMissing)
                    {
                        if (!SessionCryptoContext.VerifyCmacRecv(xfer_buffer, xfer_length))
                        {
                            if ((flags & DesfireCommandFlag.LOOSE_RESPONSE_CMAC) != 0)
                            {
                                logger.debug("{0} CMAC error (ignored)", sessionText);
                            }
                            else
                            {
                                logger.debug("{0} CMAC error", sessionText);
                                return LibraryError(DesfireLibraryError.WrongCMAC);
                            }
                        }

                        xfer_length -= SessionCryptoContext.CmacSize;
                    }
                }
                else
                {
                    logger.debug("Session is not EV1 or greater, not expecting CMAC");
                }
            }

            /* Finally check the length of the response. */
            if ((accept_len != 0) && (accept_len != xfer_length))
            {
                /* Error: block with inappropriate number of bytes received from the PICC. */
                logger.debug("Received length error (expected {0}, got {1})", accept_len, xfer_length);
                return LibraryError(DesfireLibraryError.WrongLength);
            }

            if (SessionIsEV2OrGreater())
            {
                /* We may have to increase the transaction counter, after EV2 authentication but plain communication */
                if ((xfer_buffer[0] == Success) && ((flags & DesfireCommandFlag.INCREMENT_COUNTER) != 0))
                {
                    (SessionCryptoContext as DesfireCryptoContextEV2).IncrementTransactionCounter();
                }
            }

            return Success;
        }

        long Exchange()
        {
            byte card_status;
            UInt16 resp_data_len;

            byte[] send_buffer = new byte[256];
            UInt16 send_length;
            byte[] recv_buffer = new byte[256];
            UInt16 recv_length = (UInt16)recv_buffer.Length;

            logger.debug("<< {0}", BinConvert.ToHex(xfer_buffer, xfer_length));

            if (xfer_length > 200)
                return SCARD_E_INSUFFICIENT_BUFFER;

            /* Build the APDU */
            /* -------------- */
            if (IsoWrapping == DesfireIsoWrapping.Card)
            {
                int l = send_buffer.Length;

                if (!BuildIsoApdu(xfer_buffer, xfer_length, send_buffer, ref l, false))
                    return LibraryError(DesfireLibraryError.InvalidParameter);

                send_length = (ushort)l;

            }
            else if (IsoWrapping == DesfireIsoWrapping.Reader)
            {
                int l = send_buffer.Length;

                if (!BuildIsoApdu(xfer_buffer, xfer_length, send_buffer, ref l, true))
                    return LibraryError(DesfireLibraryError.InvalidParameter);

                send_length = (ushort)l;

            }
            else
            {
                Array.ConstrainedCopy(xfer_buffer, 0, send_buffer, 0, xfer_length);
                send_length = (ushort)xfer_length;
            }

            byte[] to_send = new byte[send_length];
            Array.ConstrainedCopy(send_buffer, 0, to_send, 0, send_length);

            logger.trace("<< {0}", BinConvert.ToHex(to_send));

            recv_buffer = transmitter.Transmit(to_send);

            if (recv_buffer != null)
            {
                logger.trace(">> {0}", BinConvert.ToHex(recv_buffer));
                recv_length = (ushort)recv_buffer.Length;
            }
            else
            {
                logger.trace(">> ERROR");
                return -1;
            }

            /* Check status word */
            /* ----------------- */

            if (IsoWrapping == DesfireIsoWrapping.Card)
            {
                if (recv_length < 2)
                    return LibraryError(DesfireLibraryError.PcscBadResponseLength);

                /* SW1 must be 91YY */
                if (recv_buffer[recv_length - 2] != 0x91)
                    return LibraryError(DesfireLibraryError.PcscBadStatusWord);

                /* SW2 is the card status */
                card_status = recv_buffer[recv_length - 1];

                /* Retrieve card's data */
                resp_data_len = (UInt16)(recv_length - 2);

                /* Remember received size */
                xfer_length = resp_data_len + 1;

                /* Copy the buffer */
                Array.ConstrainedCopy(recv_buffer, 0, xfer_buffer, 1, xfer_length);
            }
            else if (IsoWrapping == DesfireIsoWrapping.Reader)
            {
                /* SW must be 9000 */
                UInt16 sw;

                if (recv_length < 2)
                    return LibraryError(DesfireLibraryError.PcscBadResponseLength);

                sw = (ushort)((recv_buffer[recv_length - 2] * 0x0100) | recv_buffer[recv_length - 1]);


                switch (sw)
                {
                    case 0x9000: break;

                    case 0x6F01:
                    case 0x6F3D:
                    case 0x6F51:
                    case 0x6F52:
                        return SCARD_W_REMOVED_CARD;

                    case 0x6F02:
                    case 0x6F3E:
                        return SCARD_E_COMM_DATA_LOST;

                    case 0x6F47:
                        return SCARD_E_CARD_UNSUPPORTED;

                    default: return LibraryError(DesfireLibraryError.PcscBadStatusWord);
                }

                if (recv_length < 3)
                    return LibraryError(DesfireLibraryError.WrongLength);

                /* Card status word is at the beginning of the buffer */
                card_status = recv_buffer[0];

                /* Retrieve card's data */
                resp_data_len = (UInt16)(recv_length - 3);

                /* Remember received size */
                xfer_length = resp_data_len + 1;

                /* Copy the buffer */
                Array.ConstrainedCopy(recv_buffer, 1, xfer_buffer, 1, xfer_length);
            }
            else
            {
                if (recv_length < 1)
                    return LibraryError(DesfireLibraryError.WrongLength);

                card_status = recv_buffer[0];

                resp_data_len = (UInt16)(recv_length - 1);

                /* Remember received size */
                xfer_length = resp_data_len + 1;

                /* Copy the buffer */
                Array.ConstrainedCopy(recv_buffer, 0, xfer_buffer, 0, xfer_length);
            }


            /* Check whether the PICC's response consists of at least one byte.
            If the response is empty, we can not even determine the PICC's status.
            Therefore an empty response is always a length error. */

            if ((xfer_length < 1) /*|| (xfer_length > max_frame_size)*/)
            {
                /* Error: block with inappropriate number of bytes received from the PICC. */
                return LibraryError(DesfireLibraryError.WrongLength);
            }

            /* Copy the buffer */
            if (card_status == (byte)DesfireCardError.MoreOperationOK)
            {
                xfer_buffer[0] = (byte)Success;
            }
            else
            {
                xfer_buffer[0] = card_status;
            }

            logger.debug(">> {0}", BinConvert.ToHex(xfer_buffer, xfer_length));
            return Success;
        }

    }
}
