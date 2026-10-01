using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using SpringCard.LibCs;

namespace SpringCard.PCSC.CardHelpers
{
    public partial class Desfire
    {
        const byte SW_AUTHENT = 0x01;
        const byte SW_SELECT_DF = 0x02;
        const byte SW_WRITE = 0x04;

        static bool Comparebytes(byte[] a1, uint a1_offset, byte[] a2, uint a2_offset, uint size)
        {
            for (int i = 0; i < size; ++i)
            {
                if (a1[a1_offset + i] != a2[a2_offset + i])
                {
                    return true;
                }
            }
            return false;
        }

        /// <summary>
        /// 
        /// 
        /// </summary>
        /// <param name="INS"></param>
        /// <param name="P1"></param>
        /// <param name="P2"></param>
        /// <param name="Lc"></param>
        /// <param name="data_in"></param>
        /// <param name="Le"></param>
        /// <param name="data_out"></param>
        /// <param name="data_out_len"></param>
        /// <param name="SW"></param>
        /// <returns></returns>
        long IsoApdu(byte INS, byte P1, byte P2, byte Lc, byte[] data_in, byte Le, ref byte[] data_out, ref UInt16 data_out_len, ref UInt16 SW)
        {

            long status = 0;
            byte[] send_buffer;
            UInt16 send_length = 0;

            byte[] recv_buffer = new byte[280];
            int recv_length = recv_buffer.Length;
            UInt16 i;
            UInt16 _SW;


            if (data_out_len != 0)
                send_buffer = new byte[Lc + 6];
            else
                send_buffer = new byte[Lc + 5];

            if (((Lc == 0) && (data_in != null)) || ((Lc != 0) && (data_in == null)))
                return LibraryError(DesfireLibraryError.InvalidParameter);

            send_buffer[send_length++] = 0;
            send_buffer[send_length++] = INS;
            send_buffer[send_length++] = P1;
            send_buffer[send_length++] = P2;
            send_buffer[send_length++] = Lc;
            if (data_in != null)
            {                
                for (i = 0; i < Lc; i++)
                    send_buffer[send_length++] = data_in[i];
            }
            if (data_out_len != 0)
            {
                send_buffer[send_length++] = Le;
            }

            logger.trace("DESFire< " + BinConvert.ToHex(send_buffer, send_length));
            recv_buffer = transmitter.Transmit(send_buffer);

            if (recv_buffer != null)
            {
                logger.trace("DESFire> " + BinConvert.ToHex(recv_buffer));
                recv_length = (ushort)recv_buffer.Length;
            }
            else
            {
                Logger.Debug(">> ERROR");
                return -1;
            }

            if (recv_length < 2)
                return LibraryError(DesfireLibraryError.PcscBadResponseLength);

            recv_length -= 2;

            //if (data_out_len != null)
            data_out_len = (UInt16)recv_length;

            if (data_out != null)
            {
                if ((Le == 0) && (recv_length > 256))
                {
                    recv_length = 256;
                    status = LibraryError(DesfireLibraryError.Overflow);
                }
                else
                  if ((Le != 0) && (recv_length > Le))
                {
                    recv_length = Le;
                    status = LibraryError(DesfireLibraryError.Overflow);
                }

                //memcpy(data_out, recv_buffer, recv_length);
                Array.ConstrainedCopy(recv_buffer, 0, data_out, 0, recv_length);
            }

            _SW = recv_buffer[recv_length + 0];
            _SW <<= 8;
            _SW |= recv_buffer[recv_length + 1];

            //if (SW is not null)
            SW = _SW;

            if (_SW != 0x9000)
                status = LibraryError(DesfireLibraryError.PcscBadStatusWord);

            return status;
        }

        private long IsoApdu(byte INS, byte P1, byte P2, byte[] data_in, int Le, out byte[] data_out, out ushort SW, bool extended = false)
        {
            return IsoApdu(0, INS, P1, P2, data_in, Le, out data_out, out SW, extended);
        }

        private long IsoApdu(byte CLA, byte INS, byte P1, byte P2, byte Le, out byte[] data_out, out ushort SW, bool extended = false)
        {
            return IsoApdu(CLA, INS, P1, P2, null, Le, out data_out, out SW, extended);
        }

        private long IsoApdu(byte CLA, byte INS, byte P1, byte P2, byte[] data_in, int Le, out byte[] data_out, out ushort SW, bool extended = false)
        {
            long rc = 0;
            byte[] send_buffer;
            int send_length = 0;
            byte[] recv_buffer = null;

            data_out = null;
            SW = 0xFFFF;

            int Lc = 0;
            if (data_in != null)
                Lc = data_in.Length;

            int len_lc = 0;
            int len_le = 0;

            if (Lc >= 254)
                extended = true;
            if (Le >= 254)
                extended = true;

            if (Lc > 0)
            {
                if (extended)
                    len_lc = 3; /* Extended APDU, no Le */
                else
                    len_lc = 1; /* Short APDU, no Le */
            }
            if (Le >= 0)
            {
                if (extended)
                {
                    if (len_lc > 0)
                        len_le = 2; /* Extended APDU, with Lc and Le */
                    else
                        len_le = 3; /* Extended APDU, with Le but no Lc */
                }                   
                else
                    len_le = 1; /* Short APDU, with Le */
            }

            send_buffer = new byte[4 + len_lc + Lc + len_le];

            send_buffer[send_length++] = CLA;
            send_buffer[send_length++] = INS;
            send_buffer[send_length++] = P1;
            send_buffer[send_length++] = P2;

            switch (len_lc)
            {
                case 3:
                    send_buffer[send_length++] = 0;
                    send_buffer[send_length++] = (byte)(Lc >> 8);
                    send_buffer[send_length++] = (byte)(Lc);
                break;
                case 1:
                    send_buffer[send_length++] = (byte)(Lc);
                break;
            }

            for (int i = 0; i < Lc; i++)
                send_buffer[send_length++] = data_in[i];

            switch (len_le)
            {
                case 3:
                    send_buffer[send_length++] = 0;
                    send_buffer[send_length++] = (byte)(Le >> 8);
                    send_buffer[send_length++] = (byte)(Le);
                break;
                case 2:
                    send_buffer[send_length++] = (byte)(Le >> 8);
                    send_buffer[send_length++] = (byte)(Le);
                break;
                case 1:
                    send_buffer[send_length++] = (byte)(Le);
                break;
            }

            logger.trace("<< " + BinConvert.ToHex(send_buffer));
            recv_buffer = transmitter.Transmit(send_buffer);
            logger.trace(">> " + BinConvert.ToHex(recv_buffer));

            if ((recv_buffer == null) || (recv_buffer.Length < 2))
                return LibraryError(DesfireLibraryError.PcscBadResponseLength);

            /* Wrapping of the native MIFARE Plus EV1 APDU Format */
            SW = recv_buffer[recv_buffer.Length - 2];
            SW <<= 8;
            SW |= recv_buffer[recv_buffer.Length - 1];

            if (recv_buffer.Length > 2)
                data_out = BinUtils.Copy(recv_buffer, 0, recv_buffer.Length - 2);

            if (CLA == 0x90)
            {
                if (SW != 0x9190)
                    rc = LibraryError(DesfireLibraryError.PcscBadStatusWord);
            }
            else
            {
                if (SW != 0x9000)
                    rc = LibraryError(DesfireLibraryError.PcscBadStatusWord);
            }

            return rc;
        }

        long TranslateSW(UInt16 SW, byte param, string context = null)
        {
            long status;

            switch (SW)
            {
                case 0x9000:
                    status = Success;
                    break;

                case 0x9190:
                    status = Success;
                    break;

                case 0x6282: /* End of file reached before reading Le bytes */
                    status = CardError(DesfireCardError.BoundaryError);
                    break;

                case 0x6581: /* Memory failure */
                    status = CardError(DesfireCardError.EepromError);
                    break;

                case 0x6700: /* Wrong length */
                    status = CardError(DesfireCardError.LengthError);
                    break;

                case 0x6982: /* File access not allowed */
                    status = CardError(DesfireCardError.AuthenticationError);
                    break;

                case 0x6985:
                    if ((param & SW_WRITE) != 0x00)
                    {
                        /* Access condition not satisfied */
                        status = CardError(DesfireCardError.PermissionDenied);
                    }
                    else
                    {
                        /* File empty */
                        status = CardError(DesfireCardError.BoundaryError);
                    }
                    break;

                case 0x6A82:
                    if ((param & SW_SELECT_DF) != 0x00)
                    {
                        /* DF not found */
                        status = CardError(DesfireCardError.ApplicationNotFound);
                    }
                    else
                    {
                        /* EF not found */
                        status = CardError(DesfireCardError.FileNotFound);
                    }
                    break;

                case 0x6A86: /* Wrong parameter P1 and/or P2 */
                    status = CardError(DesfireCardError.ParameterError);
                    break;

                case 0x6A87: /* Lc inconsistent with P1/P2 */
                    status = CardError(DesfireCardError.LengthError);
                    break;

                case 0x6B00: /* Wrong parameter P1 and/or P2 */
                    status = CardError(DesfireCardError.ParameterError);
                    break;

                case 0x6C00:
                    if ((param & SW_AUTHENT) != 0x00)
                    {
                        /* Wrong Le */
                        status = CardError(DesfireCardError.ParameterError);
                    }
                    else
                    {
                        /* File not found */
                        status = CardError(DesfireCardError.FileNotFound);
                    }
                    break;

                case 0x6D00: /* Instruction not supported */
                    status = CardError(DesfireCardError.IllegalCommandCode);
                    break;

                case 0x6E00: /* Wrong CLA */
                    status = CardError(DesfireCardError.IllegalCommandCode);
                    break;


                default:
                    status = LibraryError(DesfireLibraryError.PcscBadStatusWord);
                    break;
            }

            if (status != Success)
            {
                if (context == null)
                    logger.trace("Card SW={0:X04} -> {1}", SW, status);
                else
                    logger.trace("{0}: card SW={0:X04} -> {1}", context, SW, status);
            }

            return status;
        }

        /**
 * @fn *   IsoSelectApplet
 * @brief *   Send the ISO 7816-4 SELECT FILE command with the DESFIRE applet name as parameter
 * @details
 * *
 * @return *   DesfireCommand.OPERATION_OK   : success
 */
        long IsoSelectApplet(ref UInt16? SW)
        {
            byte[] DesfireAID = new byte[] { 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x00 };
            long status;
            UInt16 SW_local = 0;
            UInt16 data_out_local = 0;
            byte[] nullbyte = new byte[16];

            EndSecureSession();
            IsoWrapping = DesfireIsoWrapping.Card;

            status = IsoApdu(0xA4, 0x04, 0x00, (byte)DesfireAID.Length, DesfireAID, 0, ref nullbyte, ref data_out_local, ref SW_local);

            if (SW != null)
            {
                SW = SW_local;
            }
            return status;
        }

        /**
 * @fn *   IsoSelectDF
 * @brief *   Implementation of ISO 7816-4 SELECT FILE command using a Directory File ID (P2=0x02)
 * @details
 * *
 * @return *   DesfireCommand.OPERATION_OK   : success
 * @note *   The abFci and wGotFciLength parameter could be set to null if no FCI is expected
 */
        long IsoSelectDF(ushort FileId, byte[] Fci, UInt16 FciMaxLength, ref UInt16 FciGotLength, ref ushort SW)
        {
            long status;
            byte[] data = new byte[2];
            UInt16 SW_local = 0;
            UInt16 data_out_local = 0;
            byte[] nullbyte = new byte[16];

            /*if (SW == null)
              SW = &_SW;*/

            /* Change application = forget authentication state */
            EndSecureSession();

            data[0] = (byte)(FileId >> 8);
            data[1] = (byte)FileId;

            /* Do the select */
            if (Fci == null)
            {
                status = IsoApdu(0xA4, 0x00, 0x0C, 2, data, 0, ref nullbyte, ref data_out_local, ref SW_local);
            }
            else
            {
                byte Le;

                Le = (FciMaxLength > 255) ? (byte)0 : (byte)FciMaxLength;

                status = IsoApdu(0xA4, 0x00, 0x00, 2, data, Le, ref Fci, ref FciGotLength, ref SW_local);
            }

            /* Translate the Status UInt16 into a Desfire error code */
            if (status == LibraryError(DesfireLibraryError.PcscBadStatusWord))
                status = TranslateSW(SW_local, SW_SELECT_DF);

            //if (SW != null)
            {
                SW = SW_local;
            }
            return status;
        }

        /**
 * @fn *   IsoSelectDFName
 * @brief *   Implementation of ISO 7816-4 SELECT FILE command using a Directory Name (P2=0x04)
 * @details
 * *
 * @return *   DesfireCommand.OPERATION_OK   : success
 * @note *   The abFci and wGotFciLength parameter could be set to null if no FCI is expected
 */
        long IsoSelectDFName(byte[] abDFName, byte abDFNameLength, byte[] abFci, UInt16 wFciMaxLength, ref UInt16 wFciGotLength, ref UInt16? SW)
        {
            long status;
            UInt16 SW_local = 0;
            UInt16 data_out_local = 0;
            byte[] nullbyte = new byte[16];

            /* Change application = forget authentication state */
            EndSecureSession();

            /* Do the select */
            if (abFci == null)
            {
                status = IsoApdu(0xA4, 0x04, 0x0C, abDFNameLength, abDFName, 0, ref nullbyte, ref data_out_local, ref SW_local);
            }
            else
            {
                byte Le;

                Le = (wFciMaxLength > 255) ? (byte)0 : (byte)wFciMaxLength;
                status = IsoApdu(0xA4, 0x04, 0x00, abDFNameLength, abDFName, Le, ref abFci, ref wFciGotLength, ref SW_local);
            }

            /* Translate the Status UInt16 into a Desfire error code */
            if (status == LibraryError(DesfireLibraryError.PcscBadStatusWord))
                status = TranslateSW(SW_local, SW_SELECT_DF);

            if (SW != null)
            {
                SW = SW_local;
            }

            return status;
        }

        /**
 * @fn *   IsoSelectEF
 * @brief *   Implementation of ISO 7816-4 SELECT FILE command using a Elementary File ID (P2=0x02)
 * @details
 * *
 * @return *   DesfireCommand.OPERATION_OK   : success
 */
        long IsoSelectEF(UInt16 wFileID, ref UInt16? SW)
        {
            long status;
            byte[] data = new byte[2];
            UInt16 SW_local = 0;
            UInt16 data_out_local = 0;
            byte[] nullbyte = new byte[16];

            data[0] = (byte)(wFileID >> 8);
            data[1] = (byte)wFileID;

            status = IsoApdu(0xA4, 0x02, 0x0C, 2, data, 0, ref nullbyte, ref data_out_local, ref SW_local);

            /* Translate the Status UInt16 into a Desfire error code */
            if (status == LibraryError(DesfireLibraryError.PcscBadStatusWord))
                status = TranslateSW(SW_local, 0);

            if (SW != null)
            {
                SW = SW_local;
            }

            return status;
        }

        /**
 * @fn *   IsoReadBinary
 * @brief *   Implementation of ISO 7816-4 READ BINARY command in Desfire EV1 flavour
 * @details
 * *
 * @return *   DesfireCommand.OPERATION_OK   : success
 * @note *   After a successfull authentication, a CMAC is added to card's response.
 */
        long IsoReadBinary(UInt16 wOffset, byte[] abData, byte bWantLength, ref UInt16 wGotLength, ref UInt16? SW)
        {
            byte P1, P2;
            long status;
            UInt16 SW_local = 0;


            if (abData == null)
                return LibraryError(DesfireLibraryError.InvalidParameter);

            /*if (wGotLength == null)
              return error(ELibError.InvalidParameter);*/

            if (wOffset > 32767)
                return LibraryError(DesfireLibraryError.InvalidParameter);

            P1 = (byte)(wOffset >> 8);
            P2 = (byte)wOffset;

            status = IsoApdu(0xB0, P1, P2, 0, null, bWantLength, ref abData, ref wGotLength, ref SW_local);

            if ((status == Success) && (GetSessionType() != EAuthType.NONE))
            {
                /* There's a CMAC at the end of the data */
                byte l;
                byte[] buffer = new byte[280];
                
                if (wGotLength < 8)
                {
                    /* CMAC not included ? */
                    return LibraryError(DesfireLibraryError.WrongLength);
                }

                l = (byte)(wGotLength - 8);

                //memcpy(&buffer[0], abData, l);
                Array.ConstrainedCopy(abData, 0, buffer, 0, l);
                buffer[l++] = (byte)SW;

                byte[] cmac = SessionCryptoContext.ComputeCmacRecv(buffer, l);

                wGotLength -= 8;


                //if (memcmp(cmac, &abData[wGotLength], 8))
                if (Comparebytes(cmac, 0, abData, (uint)wGotLength, 8))
                {
                    /* Wrong CMAC */
                    return LibraryError(DesfireLibraryError.WrongCMAC);
                }
            }

            /* Translate the Status UInt16 into a Desfire error code */
            if (status == LibraryError(DesfireLibraryError.PcscBadStatusWord))
                status = TranslateSW(SW_local, 0);

            if (SW != null)
            {
                SW = SW_local;
            }

            return status;
        }

        /**
 * @fn *   IsoUpdateBinary
 * @brief *   Implementation of ISO 7816-4 UPDATE BINARY command in Desfire EV1 flavour
 * @details
 * *
 * @return *   DesfireCommand.OPERATION_OK     : success
 */
        long IsoUpdateBinary(UInt16 wOffset, byte[] abData, byte bLength, ref UInt16? SW)
        {
            byte P1, P2;
            long status;
            UInt16 SW_local = 0;
            UInt16 data_out_local = 0;
            byte[] nullbyte = new byte[16];

            if (wOffset > 32767)
                return LibraryError(DesfireLibraryError.InvalidParameter);

            P1 = (byte)(wOffset >> 8);
            P2 = (byte)wOffset;

            status = IsoApdu(0xD6, P1, P2, bLength, abData, 0, ref nullbyte, ref data_out_local, ref SW_local);

            /* Translate the Status UInt16 into a Desfire error code */
            if (status == LibraryError(DesfireLibraryError.PcscBadStatusWord))
                status = TranslateSW(SW_local, SW_WRITE);

            if (SW != null)
            {
                SW = SW_local;
            }

            return status;
        }

        /**
 * @fn *   IsoReadRecord
 * @brief *   Implementation of ISO 7816-4 READ RECORD command in Desfire EV1 flavour
 * @details
 * *
 * @return *   DesfireCommand.OPERATION_OK   : success
 * @note *   After a successfull authentication, a CMAC is added to card's response.
 */
        long IsoReadRecord(byte bRecNum, bool fReadAll, byte[] abData, UInt16 wMaxLength, ref UInt16 wGotLength, ref UInt16 SW)
        {
            byte P2, Le;
            long status;
            UInt16 SW_local = 0;


            /*if (wGotLength == null)
              return error(ELibError.InvalidParameter);*/

            if (abData == null)
                return LibraryError(DesfireLibraryError.InvalidParameter);

            P2 = (fReadAll) ? (byte)0x05 : (byte)0x04;
            Le = (wMaxLength > 255) ? (byte)0 : (byte)wMaxLength;

            status = IsoApdu(0xB2, bRecNum, P2, 0, null, Le, ref abData, ref wGotLength, ref SW_local);

            if ((status == Success) && (GetSessionType() != EAuthType.NONE))
            {
                /* There's a CMAC at the end of the data */
                byte l;
                byte[] buffer = new byte[280];

                if (wGotLength < 8)
                {
                    /* CMAC not included ? */
                    return LibraryError(DesfireLibraryError.WrongLength);
                }

                l = (byte)(wGotLength - 8);
                //memcpy(&buffer[0], abData, l);
                Array.ConstrainedCopy(abData, 0, buffer, 0, l);
                buffer[l++] = (byte)SW;

                byte[] cmac = SessionCryptoContext.ComputeCmacRecv(buffer, l);

                wGotLength -= 8;

                //if (memcmp(cmac, &abData[*wGotLength], 8))
                if (Comparebytes(cmac, 0, abData, wGotLength, 8))
                {
                    /* Wrong CMAC */
                    return LibraryError(DesfireLibraryError.WrongCMAC);
                }
            }

            /* Translate the Status UInt16 into a Desfire error code */
            if (status == LibraryError(DesfireLibraryError.PcscBadStatusWord))
                status = TranslateSW(SW, 0);

            return status;
        }

        /**
 * @fn *   IsoAppendRecord
 * @brief *   Implementation of ISO 7816-4 APPEND RECORD command in Desfire EV1 flavour
 * @details
 * *
 * @return *   DesfireCommand.OPERATION_OK     : success
 */
        long IsoAppendRecord(byte[] abData, byte bLength, ref UInt16? SW)
        {
            long status;
            UInt16 SW_local = 0;
            UInt16 data_out_local = 0;
            byte[] nullbyte = new byte[16];

            status = IsoApdu(0xE2, 0x00, 0x00, bLength, abData, 0, ref nullbyte, ref data_out_local, ref SW_local);

            /* Translate the Status UInt16 into a Desfire error code */
            if (status == LibraryError(DesfireLibraryError.PcscBadStatusWord))
                status = TranslateSW(SW_local, SW_WRITE);

            if (SW != null)
            {
                SW = SW_local;
            }

            return status;
        }

        /**
 * @fn *   IsoGetChallenge
 * @brief *   Implementation of ISO 7816-4 GET CHALLENGE command in Desfire EV1 flavour
 * @details
 * *
 * @return *   DesfireCommand.OPERATION_OK    : success
 */
        long IsoGetChallenge(byte bRndSize, byte[] RndCard1, ref ushort? SW)
        {
            long status;
            ushort SW_local = 0;
            ushort data_out_local = 0;

            //status = IsoApdu(0x84, 0x00, 0x00, 0, null, bRndSize, ref abRndCard1, ref null, ref SW_local);      
            status = IsoApdu(0x84, 0x00, 0x00, 0, null, bRndSize, ref RndCard1, ref data_out_local, ref SW_local);

            /* Translate the Status UInt16 into a Desfire error code */
            if (status == LibraryError(DesfireLibraryError.PcscBadStatusWord))
                status = TranslateSW(SW_local, SW_AUTHENT);

            if (SW != null)
            {
                SW = SW_local;
            }

            return status;
        }

#if _1
    static long Desfire_IsoLoadKey(byte bKeyAlgorithm, byte[] KeyValue)
    {  

      if (abKeyValue == null)
        return error(ELibError.InvalidParameter);

      if (bKeyAlgorithm == DesfireCommand.ISO_CIPHER_2KDES)
      {
        if (!memcmp(&abKeyValue[0], &abKeyValue[8], 8))
        {
          SetSessionType(ESessionType.KEY_ISO_DES);
          //InitCrypto3Des(abKeyValue[0], &abKeyValue[8], &abKeyValue[0]);
          SetKey(/*session_key*/SesAuthENCKey);
        }
        else
        {
          SetSessionType(ESessionType.KEY_ISO_DES);
          InitCrypto3Des( & abKeyValue[0], &abKeyValue[0], &abKeyValue[0]);
        }
      }
      else
        if (bKeyAlgorithm == DesfireCommand.ISO_CIPHER_3KDES)
      {
        SetSessionType(ESessionType.KEY_ISO_3DES3K);
        InitCrypto3Des( abKeyValue[0], &abKeyValue[8], &abKeyValue[16]);
      }
      else
          if (bKeyAlgorithm == DesfireCommand.ISO_CIPHER_AES)
      {
        SetSessionType(ESessionType.KEY_ISO_AES);
        InitCryptoAes( abKeyValue);
      }
      else
        return error(ELibError.InvalidParameter);

      CleanupInitVector();
      return DesfireCommand.OPERATION_OK;
    }

/**
 * @fn *   IsoExternalAuthenticate
 * @brief *   Implementation of ISO 7816-4 EXTERNAL AUTHENTICATE command in Desfire EV1 flavour
 * @details
 * *
 * @return *   DesfireCommand.OPERATION_OK    : success
 */
IsoExternalAuthenticate(byte bKeyAlgorithm, byte bKeyReference, byte bRndSize, byte abRndCard1[], byte abRndHost1[], byte abKeyValue[],ref UInt16 SW)
{
  long status;
  UInt32 t;
  UInt16 _SW;
  byte buffer[32];
  

  if (SW == null)
    SW = &_SW;

      //memcpy(&buffer[0], abRndHost1, bRndSize);
      Array.ConstrainedCopy(abRndHost1, 0, buffer, 0, bRndSize);
      //memcpy(&buffer[bRndSize], abRndCard1, bRndSize);
      Array.ConstrainedCopy(abRndCard1, 0, buffer, bRndSize, bRndSize);

      if (abKeyValue != null)
  {
    status = Desfire_IsoLoadKey bKeyAlgorithm, abKeyValue);
    if (status != DesfireCommand.OPERATION_OK)
      return status;
  }

  t = 2 * bRndSize;
  Desfire_CipherSend buffer, &t, sizeof(buffer));

  status = IsoApdu) 0x82, bKeyAlgorithm, bKeyReference, (byte)(2 * bRndSize), buffer, 0, null, null, SW);

  if (status == error(ELibError.PcscBadStatusWord))
    status = TranslateSW(*SW, SW_AUTHENT);

  return status;
}

/**
 * @fn *   IsoInternalAuthenticate
 * @brief *   Implementation of ISO 7816-4 INTERNAL AUTHENTICATE command in Desfire EV1 flavour
 * @details
 * *
 * @return *   DesfireCommand.OPERATION_OK    : success
 */
IsoInternalAuthenticate(byte bKeyAlgorithm, byte bKeyReference, byte bRndSize, byte abRndHost2[], byte abRndCard2[], byte abKeyValue[],ref UInt16 SW)
{
  long status;
  UInt16 length;
  byte buffer[32];
  UInt32 t;
  UInt16 _SW;
  

  if (SW == null)
    SW = &_SW;

  if (abRndHost2 == null)
    return error(ELibError.InvalidParameter);

  status = IsoApdu) 0x88, bKeyAlgorithm, bKeyReference, bRndSize, abRndHost2, (byte)(2 * bRndSize), buffer, &length, SW);
  if (status != DesfireCommand.OPERATION_OK)
  {
    if (status == error(ELibError.PcscBadStatusWord))
      status = TranslateSW(*SW, SW_AUTHENT);

    return status;
  }

  if (abKeyValue != null)
  {
    status = Desfire_IsoLoadKey bKeyAlgorithm, abKeyValue);
    if (status != DesfireCommand.OPERATION_OK)
      return status;
  }

  t = 2 * bRndSize;
  Desfire_CipherRecv buffer, &t);

  if (memcmp(abRndHost2, &buffer[bRndSize], bRndSize))
    status = error(ELibError.WrongKey);

  if (abRndCard2 != null)
        //memcpy(abRndCard2, &buffer[0], bRndSize);
        Array.ConstrainedCopy(buffer, 0, abRndCard2, 0, bRndSize);

      return status;
}

/**
 * @fn *   IsoMutualAuthenticate
 * @brief *   Perform a mutual-authentication using the Desfire ISO 7816-4 commands (IsoGetChallenge,
 * @details
 * *
 * @return *   DesfireCommand.OPERATION_OK    : authentication succeed
 */
IsoMutualAuthenticate(byte bKeyAlgorithm, byte bKeyReference, byte abKeyValue[],ref UInt16 SW)
{
  long status;
  UInt16 _SW;

  byte bRndSize;
  byte abRndCard1[16], abRndCard2[16];
  byte abRndHost1[16], abRndHost2[16];

  

  if (SW == null) SW = &_SW;

  switch (bKeyAlgorithm)
  {
    case DesfireCommand.ISO_CIPHER_2KDES: bRndSize = 8; break;
    case DesfireCommand.ISO_CIPHER_3KDES: bRndSize = 16; break;
    case DesfireCommand.ISO_CIPHER_AES: bRndSize = 16; break;
    default: return error(ELibError.InvalidParameter);
  }

  if (abKeyValue == null)
    return error(ELibError.InvalidParameter);

  session_key_id = bKeyReference & 0x7F;

  /* Get random bytes to populate host's challenges */
  GetRandombytes abRndHost1, bRndSize);
  GetRandombytes abRndHost2, bRndSize);

  /* Get first challenge from card */
  status = IsoGetChallenge) bRndSize, abRndCard1, SW);
  if (status != DesfireCommand.OPERATION_OK)
    return status;

  /* Activate the cipher engine */
  CleanupAuthentication();
  status = Desfire_IsoLoadKey bKeyAlgorithm, abKeyValue);
  if (status != DesfireCommand.OPERATION_OK)
    return status;

  /* External authenticate feeds the card with first challenge from the host */
  status = IsoExternalAuthenticate) bKeyAlgorithm, bKeyReference, bRndSize, abRndCard1, abRndHost1, null, SW);
  if (status != DesfireCommand.OPERATION_OK)
    return status;

  /* Internal authenticate returns second challenge from the card */
  status = IsoInternalAuthenticate) bKeyAlgorithm, bKeyReference, bRndSize, abRndHost2, abRndCard2, null, SW);
  if (status != DesfireCommand.OPERATION_OK)
    return status;

  /* Compute the session key over host's first challenge and card's second challenge */
  if (bKeyAlgorithm == DesfireCommand.ISO_CIPHER_2KDES)
  {
    if (!memcmp(&abKeyValue[0], &abKeyValue[8], 8))
    {
      /* Single DES key */
      memcpy(&session_enc_key[0], &abRndHost1[0], 4);
      memcpy(&session_enc_key[4], &abRndCard2[0], 4);
      memcpy(&session_enc_key[8], &session_enc_key[0], 8);
      memcpy(&session_enc_key[16], &session_enc_key[0], 8);

      Desfire_InitCrypto3Des& session_enc_key[0], null, null);

    }
    else
    {
      /* Triple DES with 2 keys */
      memcpy(&session_enc_key[0], &abRndHost1[0], 4);
      memcpy(&session_enc_key[4], &abRndCard2[0], 4);
      memcpy(&session_enc_key[8], &abRndHost1[4], 4);
      memcpy(&session_enc_key[12], &abRndCard2[4], 4);
      memcpy(&session_enc_key[16], &session_enc_key[0], 8);

      Desfire_InitCrypto3Des& session_enc_key[0], &session_enc_key[8], null);

    }
  }
  else
    if (bKeyAlgorithm == DesfireCommand.ISO_CIPHER_3KDES)
  {
    /* Triple DES with 3 keys */
    memcpy(&session_enc_key[0], &abRndHost1[0], 4);
    memcpy(&session_enc_key[4], &abRndCard2[0], 4);
    memcpy(&session_enc_key[8], &abRndHost1[6], 4);
    memcpy(&session_enc_key[12], &abRndCard2[6], 4);
    memcpy(&session_enc_key[16], &abRndHost1[12], 4);
    memcpy(&session_enc_key[20], &abRndCard2[12], 4);

    Desfire_InitCrypto3Des& session_enc_key[0], &session_enc_key[8], &session_enc_key[16]);

  }
  else
      if (bKeyAlgorithm == DesfireCommand.ISO_CIPHER_AES)
  {
    /* AES */
    memcpy(&session_enc_key[0], &abRndHost1[0], 4);
    memcpy(&session_enc_key[4], &abRndCard2[0], 4);
    memcpy(&session_enc_key[8], &abRndHost1[12], 4);
    memcpy(&session_enc_key[12], &abRndCard2[12], 4);

    Desfire_InitCryptoAes session_enc_key);
  }

  Desfire_CleanupInitVector();

  /* Initialize the CMAC calculator */
  Desfire_InitCmac();

  return DesfireCommand.OPERATION_OK;
}
#endif
    }
}
