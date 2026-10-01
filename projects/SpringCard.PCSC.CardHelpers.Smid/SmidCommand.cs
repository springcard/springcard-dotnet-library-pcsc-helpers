using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Utilities;
using SpringCard.LibCs;
using System;
using System.Collections.Generic;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Security.Cryptography;
using static Org.BouncyCastle.Asn1.Cmp.Challenge;

namespace SpringCard.PCSC.CardHelpers
{
    public partial class Smid
    {
        const int SMID_USI_LENGTH = 7;
        private bool bCheckSelfTest = false;
        public SmidProtocolVersion _SmidProtocolVersion { get; set; }
        

        public long SelectApplication(byte[] smidAid, byte[] usi)
        {

            EndSecureSession();

            xfer_buffer[0] = 0x00;   
            xfer_buffer[1] = (byte)SmidCommand.SELECT;
            xfer_buffer[2] = 0x04;
            xfer_buffer[3] = 0x00;
            xfer_buffer[4] = (byte)smidAid.Length;               // Lc
            Array.ConstrainedCopy(smidAid, 0, xfer_buffer, 5, smidAid.Length);
            xfer_length = (ushort)(5 + smidAid.Length);

            if (bCheckSelfTest)
            {
                logger.trace("> {0:X02}", BinConvert.ToHex(xfer_buffer, xfer_length));

                xfer_buffer[0] = 0x00;
                xfer_buffer[1] = 0x01;
                xfer_buffer[2] = 0x02;
                xfer_buffer[3] = 0x03;
                xfer_buffer[4] = 0x04;
                xfer_buffer[5] = 0x05;
                xfer_buffer[6] = 0x06;
                xfer_buffer[7] = 0x90;
                xfer_buffer[8] = 0x00;
                xfer_length = 9;
                logger.trace("< {0:X02}", BinConvert.ToHex(xfer_buffer, xfer_length));
            }
            else
            {
                long status = 0x0000;
                if (Command(ref status) == false)
                {
                    logger.trace("SelectApplication error\n");
                    return status;
                }
            }

            if (xfer_length != (SMID_USI_LENGTH + 2) /*SW1 SW2*/)
            {
                logger.trace("Wrong USI length (%d)\n", xfer_length);
                return LibraryError(SmidLibraryError.WrongUsiLength);
            }
            if(( usi != null) && (usi.Length >= SMID_USI_LENGTH))
                Array.ConstrainedCopy(xfer_buffer, 0, usi, 0, SMID_USI_LENGTH);
            else
            {
                logger.trace("USI buffer too small or null\n");
                return LibraryError(SmidLibraryError.InvalidParameter);
            }           

            return Smid.Success;
        }
        public long SelectApplication21x(byte[] usi)
        {
            byte[] smid21Aid = new byte[] { 0xF5, 0x1B, 0xC0, 0x53, 0x54, 0x69, 0x64, 0x4D, 0x6F, 0x62, 0x69, 0x6C, 0x65, 0x49, 0x44, 0x01 };
            _SmidProtocolVersion = SmidProtocolVersion.Smid_v212;
            return SelectApplication(smid21Aid, usi);
        }

        public long SelectApplication(byte[] usi)
        {
            byte[] smid10Aid = new byte[] { 0xF0, 0x51, 0xBC, 0x53, 0x54, 0x69, 0x64, 0x4D, 0x6F, 0x62, 0x69, 0x6C, 0x65, 0x2D, 0x49, 0x44 };

            if (SelectApplication21x(usi) == Smid.Success)
            {
                _SmidProtocolVersion = SmidProtocolVersion.Smid_v212;
                return Smid.Success;
            }

            if (SelectApplication(smid10Aid, usi) == Smid.Success)
            {
                _SmidProtocolVersion = SmidProtocolVersion.Smid_v110;
                return Smid.Success;
            }
            else
            {
                return LibraryError(SmidLibraryError.SelectApplicationFailed);
            }
        }
        
        public long HceGetNbCard(ushort siteCode, byte settingsUnlock, byte[] card_number)
        {
            long status = 0;
            uint expected_length = 3;

            if (card_number == null)
	        {
                return LibraryError(SmidLibraryError.InvalidParameter);
            }

            /* our default answer */
            card_number[0] = 0x00;

            /* Send GetNbCard */
            /* natif */
            /*xfer_buffer[0] = 0x6C;
            xfer_buffer[1] = (siteCode >> 8) & 0xFF;
            xfer_buffer[2] = (siteCode >> 0) & 0xFF;
            xfer_buffer[3] = settingsUnlock;
            xfer_length = 4;*/
            if (_SmidProtocolVersion == SmidProtocolVersion.Smid_v110)
            {
                expected_length = 4;
                /* ISO wrapped */
                xfer_buffer[0] = 0xFF;
                xfer_buffer[1] = 0xFE;
                xfer_buffer[2] = 0x00;
                xfer_buffer[3] = 0x00;
                xfer_buffer[4] = 0x04;
                xfer_buffer[5] = (byte)SmidCommand.GET_NB_CARD;
                xfer_buffer[6] = (byte)((siteCode >> 8) & 0xFF);
                xfer_buffer[7] = (byte)((siteCode >> 0) & 0xFF);
                xfer_buffer[8] = settingsUnlock;
                xfer_buffer[9] = 0x00;             //Le
                xfer_length = 10;
            }
            else
            {
                xfer_buffer[0] = (byte)ISO7816_CLA;
                xfer_buffer[1] = (byte)SmidCommand.GET_NB_CARD;               // INS
                xfer_buffer[2] = 0x00;               // P1
                xfer_buffer[3] = 0x00;               // P2
                xfer_buffer[4] = 0x03;               // Lc
                xfer_buffer[5] = (byte)((siteCode >> 8) & 0xFF);
                xfer_buffer[6] = (byte)((siteCode >> 0) & 0xFF);
                xfer_buffer[7] = settingsUnlock;
                xfer_buffer[8] = 0x00;             //Le
                xfer_length = 9;
            }

            if (bCheckSelfTest)
            {
                logger.trace ("> {0:X02}", BinConvert.ToHex(xfer_buffer, xfer_length));
                xfer_buffer[0] = 0x02;
                xfer_buffer[1] = 0x91;
                xfer_buffer[2] = 0x00;
                xfer_length = 3;
                logger.trace("< {0:X02}", BinConvert.ToHex(xfer_buffer, xfer_length));
            }
            else
            {
                if (Command(ref status) == false)
                {
                    logger.trace("GetNbCard error\n");
                    return status;
                }
            }

            /* Status | nbCard | SW1 | SW2*/
            if (xfer_length != expected_length)
            {
                logger.trace("GetNbCard answer wrong length\n");
                return CardError(SmidCardError.LengthError);
            }

            if (expected_length == 4)
            {
                /* ISO wrapped */
                if (xfer_buffer[0] != (byte)SmidCardError.NormalProcessing)
                {
                    logger.trace("GetNbCard answer error\n");
                    return CardError(xfer_buffer[xfer_length - 1]);
                }
                /* all good */
                card_number[0] = xfer_buffer[1];
                return status;
            }
            else
            {
                card_number[0] = xfer_buffer[0];
            }

            /* all good */           

            return status;
         }
        /// <summary> Send SiteCode | Info | NFCiD | RFU and retrieve
        /// client's Encrypted challenge

        public long HceAuthenticateNfcV2(
            byte[] secretKeyValue,
            byte[] usi,
            ushort site_code,
            byte[] salt)
        {
            byte[] buffer = new byte[16];
            byte[] challenge = new byte[16 * 2];
            
            //byte[] rndB = new byte[16];
            long status = 0;
            byte[] rndA;
            /* create initial key context */

            if (logSecrets)
                logger.trace("KeySecretValue   {0:X02}", BinConvert.ToHex(secretKeyValue, 16));

            logger.trace("usi   {0:X02}", BinConvert.ToHex(usi, 7));

            if (logSecrets)
                logger.trace("salt   {0:X02}", BinConvert.ToHex(salt, 16));

            SmidCryptoContext211 cryptoContext = new SmidCryptoContext211(this, secretKeyValue, site_code, usi);


            if (_SmidProtocolVersion == SmidProtocolVersion.Smid_v110)
            {
                xfer_buffer[0] = 0xFF;               // CLA
                xfer_buffer[1] = 0xFE;               // INS
                xfer_buffer[2] = 0x00;               // P1
                xfer_buffer[3] = 0x00;               // P2
                xfer_buffer[4] = 0x06;               // Lc
                xfer_buffer[5] = (byte)SmidCommand.AUTHENTICATE;
                xfer_buffer[6] = (byte)((site_code >> 8) & 0xFF);
                xfer_buffer[7] = (byte)((site_code >> 0) & 0xFF);
                xfer_buffer[8] = 0x01;
                xfer_buffer[9] = (byte)SmidCommand.NFC_ID;
                xfer_buffer[10] = (byte)SmidCommand.RFU;
                xfer_length = 11;
            }
            else
            {
                // Send SiteCode | Info | NFCiD | RFU and retrieve
                // client's Encrypted challenge
                xfer_buffer[0] = (byte)ISO7816_CLA;               // CLA
                xfer_buffer[1] = (byte)SmidCommand.AUTHENTICATE;               // INS
                xfer_buffer[2] = 0x00;               // P1
                xfer_buffer[3] = 0x00;               // P2
                xfer_buffer[4] = 0x05;               // Lc
                xfer_buffer[5] = (byte)((site_code >> 8) & 0xFF);
                xfer_buffer[6] = (byte)((site_code >> 0) & 0xFF);
                xfer_buffer[7] = 0x01;
                xfer_buffer[8] = (byte)SmidCommand.NFC_ID;
                xfer_buffer[9] = (byte)SmidCommand.RFU;
                xfer_length = 10;
            }

            if (bCheckSelfTest)
            {
                logger.trace("> {0:X02}", BinConvert.ToHex(xfer_buffer, xfer_length));

                xfer_buffer[0] = 0x0B;
                xfer_buffer[1] = 0x42;
                xfer_buffer[2] = 0xFF;
                xfer_buffer[3] = 0xB2;
                xfer_buffer[4] = 0x32;
                xfer_buffer[5] = 0xB7;
                xfer_buffer[6] = 0xC4;
                xfer_buffer[7] = 0xDA;
                xfer_buffer[8] = 0x75;
                xfer_buffer[9] = 0xC0;
                xfer_buffer[10] = 0x52;
                xfer_buffer[11] = 0xCF;
                xfer_buffer[12] = 0xEB;
                xfer_buffer[13] = 0x77;
                xfer_buffer[14] = 0x23;
                xfer_buffer[15] = 0x4B;

                xfer_buffer[16] = 0x91;
                xfer_buffer[17] = 0xAF;
                xfer_length = 18;
                logger.trace("< {0:X02}", BinConvert.ToHex(xfer_buffer, xfer_length));
            }
            else
            {
                if (Command(ref status) == false)
                {
                    logger.trace("AuthenticateNfcHceV2_step1 error\n");
                    EndSecureSession();
                    return status;
                }
            }

            xfer_length -= 2; // remove SW1 SW2

            if (_SmidProtocolVersion == SmidProtocolVersion.Smid_v110)
            {
                if ((xfer_length != 17) || (xfer_buffer[0] != (byte)SmidCommand.EXTENDED_STID))
                {
                    logger.trace("AuthenticateNfcHceV2 length error or status error\n");
                    EndSecureSession();
                    return CardError(SmidCardError.LengthError);
                }
                /* we now have E(Kx,RndB) */
                Array.ConstrainedCopy(xfer_buffer, 1, challenge, 0, 16);
            }
            else
            {
                if (xfer_length != 16)
                {
                    logger.trace("AuthenticateNfcHceV2 length error or status error\n");
                    EndSecureSession();
                    return CardError(SmidCardError.LengthError);
                }
                /* we now have E(Kx,RndB) */
                Array.ConstrainedCopy(xfer_buffer, 0, challenge, 0, 16);
            }
            if (logCrypto)
                logger.trace("challenge {0:X02}", BinConvert.ToHex(challenge, 32));
            Array.Copy(challenge, 0, buffer, 0, 16);

            /* we now do have E(Kx,RndB), generate E(Kx,RndA | RndB) */
            if (logCrypto)
                logger.trace("buffer {0:X02}", BinConvert.ToHex(buffer, buffer.Length));

            byte[] rndB = cryptoContext.Decrypt(Smid.SmidCryptoContext211.EnkKeyId, new byte[16], buffer);
            if (logCrypto)
                logger.trace("rndB {0:X02}", BinConvert.ToHex(rndB, rndB.Length));

            if (bCheckSelfTest)
            {
                rndA = new byte[16] { 0x0B, 0x6D, 0xD9, 0x25, 0x9E, 0x07, 0x7C, 0x37, 0x0C, 0xEB, 0x2C, 0x71, 0x0B, 0xB7, 0x6C, 0x2B};
                if (logCrypto)
                    logger.trace("rndA {0:X02}", BinConvert.ToHex(rndA, 16));
                Array.ConstrainedCopy(rndA, 0, challenge, 0, 16);
            }
            else
            {
                rndA = randomGenerator.Get(16);
                if (logCrypto)
                    logger.trace("rndA {0:X02}", BinConvert.ToHex(rndA, 16));
                Array.ConstrainedCopy(rndA, 0, challenge, 0, 16);
            }            
            Array.ConstrainedCopy(rndB, 0, challenge, 16,16);

            if (logCrypto)
                logger.trace("challenge {0:X02}", BinConvert.ToHex(challenge, 32));

            /* Send SCKx(RndA | RndB) */
            if (_SmidProtocolVersion == SmidProtocolVersion.Smid_v110)
            {
                xfer_buffer[0] = 0xFF;               // CLA
                xfer_buffer[1] = 0xFE;               // INS
                xfer_buffer[2] = 0x00;               // P1
                xfer_buffer[3] = 0x00;               // P2
                xfer_buffer[4] = 0x21;               // Lc

                xfer_buffer[5] = (byte)SmidCommand.EXTENDED_STID;
                Array.ConstrainedCopy(cryptoContext.Encrypt(Smid.SmidCryptoContext211.EnkKeyId, new byte[16], challenge), 0, xfer_buffer, 6, 32);
                xfer_length = 6 + 32;
            }
            else
            {
                xfer_buffer[0] = (byte)ISO7816_CLA;
                xfer_buffer[1] = (byte)SmidCommand.EXTENDED;
                xfer_buffer[2] = 0x00;
                xfer_buffer[3] = 0x00;
                xfer_buffer[4] = 0x20;
                Array.ConstrainedCopy(cryptoContext.Encrypt(Smid.SmidCryptoContext211.EnkKeyId, new byte[16], challenge), 0, xfer_buffer, 5, 32);
                xfer_length = 5 + 32;
            }

            /*0xFF | E(Kx,RndA | RndB) */
            if (bCheckSelfTest)
            {
                logger.trace(">  {0:X02}", BinConvert.ToHex(xfer_buffer, xfer_length));
                xfer_buffer[0] = 0x98;
                xfer_buffer[1] = 0x7A;
                xfer_buffer[2] = 0x9E;
                xfer_buffer[3] = 0x61;
                xfer_buffer[4] = 0x98;
                xfer_buffer[5] = 0x18;
                xfer_buffer[6] = 0xBE;
                xfer_buffer[7] = 0xED;
                xfer_buffer[8] = 0x00;
                xfer_buffer[9] = 0xB9;
                xfer_buffer[10] = 0xBA;
                xfer_buffer[11] = 0x68;
                xfer_buffer[12] = 0x9C;
                xfer_buffer[13] = 0x20;
                xfer_buffer[14] = 0xBD;
                xfer_buffer[15] = 0x0D;
                xfer_buffer[16] = 0xBB;
                xfer_buffer[17] = 0xA4;
                xfer_buffer[18] = 0xE3;
                xfer_buffer[19] = 0xF3;
                xfer_buffer[20] = 0x67;
                xfer_buffer[21] = 0x5A;
                xfer_buffer[22] = 0xC8;
                xfer_buffer[23] = 0xB0;
                xfer_buffer[24] = 0x5D;
                xfer_buffer[25] = 0x0A;
                xfer_buffer[26] = 0x43;
                xfer_buffer[27] = 0x1F;
                xfer_buffer[28] = 0x72;
                xfer_buffer[29] = 0x65;
                xfer_buffer[30] = 0xF5;
                xfer_buffer[31] = 0xD6;
                xfer_buffer[32] = 0x91;
                xfer_buffer[33] = 0x00;
                xfer_length = 34;
                logger.trace("<  {0:X02}", BinConvert.ToHex(xfer_buffer, xfer_length));
            }
            else
            {
                if (Command(ref status) == false)
                {
                    logger.trace("AuthenticateNfcHceV2 error 0xFF | E(Kx,RndA | RndB)\n");
                    EndSecureSession();
                    return status;
                }
            }

            xfer_length -= 2; // remove SW1 SW2
            if (_SmidProtocolVersion == SmidProtocolVersion.Smid_v110)
            {
                if ((xfer_length != 33) || (xfer_buffer[0] != (byte)SmidCardError.NormalProcessing))
                {
                    logger.trace("AuthenticateNfcHceV2 length error 0xFF | E(Kx,RndA | RndB)\n");
                    EndSecureSession();
                    return CardError(SmidCardError.LengthError);
                }
                /* we now have E(Kx,RndC | RndA) */
                Array.ConstrainedCopy(xfer_buffer, 1, challenge, 0, (16 * 2));
            }
            else
            {
                if (xfer_length != 32)
                {
                    logger.trace("AuthenticateNfcHceV2 length error 0xFF | E(Kx,RndA | RndB)\n");
                    EndSecureSession();
                    return CardError(SmidCardError.LengthError);
                }
                /* we now have E(Kx,RndC | RndA) */
                Array.ConstrainedCopy(xfer_buffer, 0, challenge, 0, (16 * 2));
            }
            if (logCrypto)
                logger.trace("challenge {0:X02}", BinConvert.ToHex(challenge, 32));

            /* CKx(RndC | RndA) */
            buffer = cryptoContext.Decrypt(Smid.SmidCryptoContext211.EnkKeyId, new byte[16], challenge);
            if (logCrypto)
                logger.trace("CKx(RndC | RndA)  {0:X02}", BinConvert.ToHex(buffer));
            
            if (Comparebytes( rndA, 0, buffer, 16, 16) == false)
            {
                logger.trace("AuthenticateNfcHceV2  Error RndA\n");
                LibraryError(SmidLibraryError.AuthenticationFailed);
            }

            cryptoContext.SessionKeyGeneration(salt, rndA, rndB);
            BeginSecureSession(cryptoContext);

            return status;
        }

        public long HceGetData (ushort offset, uint length, byte[] output, ref uint output_length)
        {
            long status = 0x0000;
            int offset_xfer_buffer = 0;

            if (output == null)
	        {
                logger.trace("HceGetData buffer is null\n");                
                return LibraryError(SmidLibraryError.InvalidParameter);
            }
            if (_SmidProtocolVersion == SmidProtocolVersion.Smid_v110)
            {
                xfer_buffer[0] = 0xFF;   
                xfer_buffer[1] = 0xFE;   
                xfer_buffer[2] = 0x00;   
                xfer_buffer[3] = 0x00;   
                xfer_buffer[4] = 0x05;
                xfer_buffer[5] = (byte)SmidCommand.GET_DATA;
                xfer_buffer[6] = (byte)(offset >> 8);
                xfer_buffer[7] = (byte)(offset & 0x00FF);
                xfer_buffer[8] = (byte)(length >> 8);
                xfer_buffer[9] = (byte)(length & 0x00FF);
                xfer_buffer[10] = 0x00;             //Le
                xfer_length = 11;
            }
            else
            {
                xfer_buffer[0] = (byte)ISO7816_CLA;
                xfer_buffer[1] = (byte)SmidCommand.GET_DATA;
                xfer_buffer[2] = 0x00;         
                xfer_buffer[3] = 0x00;
                xfer_buffer[4] = 0x04;
                xfer_buffer[5] = (byte)(offset >> 8);
                xfer_buffer[6] = (byte)(offset & 0x00FF);
                xfer_buffer[7] = (byte)(length >> 8);
                xfer_buffer[8] = (byte)(length & 0x00FF);
                xfer_buffer[9] = 0x00;             //Le
                xfer_length = 10;
            }

            if (bCheckSelfTest)
            {
                logger.trace(">  {0:X02}", BinConvert.ToHex(xfer_buffer, xfer_length));
                xfer_buffer[0] = 0x7D;
                xfer_buffer[1] = 0x4D;
                xfer_buffer[2] = 0x98;
                xfer_buffer[3] = 0x0D;
                xfer_buffer[4] = 0xA0;
                xfer_buffer[5] = 0x97;
                xfer_buffer[6] = 0x5A;
                xfer_buffer[7] = 0x08;
                xfer_buffer[8] = 0x4C;
                xfer_buffer[9] = 0x70;
                xfer_buffer[10] = 0xF6;
                xfer_buffer[11] = 0x6A;
                xfer_buffer[12] = 0xE9;
                xfer_buffer[13] = 0x42;
                xfer_buffer[14] = 0x4C;
                xfer_buffer[15] = 0xFA;
                xfer_buffer[16] = 0x2C;
                xfer_buffer[17] = 0xD5;
                xfer_buffer[18] = 0x75;
                xfer_buffer[19] = 0x58;
                xfer_buffer[20] = 0x00;
                xfer_buffer[21] = 0x72;
                xfer_buffer[22] = 0x2C;
                xfer_buffer[23] = 0x39;
                xfer_buffer[24] = 0x14;
                xfer_buffer[25] = 0x7F;
                xfer_buffer[26] = 0xFF;
                xfer_buffer[27] = 0xE3;
                xfer_buffer[28] = 0x9A;
                xfer_buffer[29] = 0x2C;
                xfer_buffer[30] = 0x41;
                xfer_buffer[31] = 0x1B;
                xfer_buffer[32] = 0x91;
                xfer_buffer[33] = 0x00;
                xfer_length = 34;
                logger.trace("<  {0:X02}", BinConvert.ToHex(xfer_buffer, xfer_length));
            }
            else
            {
                if (Command(ref status) == false)
                {
                    logger.trace("GetData error\n");
                    return status;
                }
            }
            
            xfer_length -= 2; // remove SW1 SW2

            if (_SmidProtocolVersion == SmidProtocolVersion.Smid_v110)
            {
                if (xfer_buffer[0] != (byte)SmidCardError.NormalProcessing)
                {
                    logger.trace("GetData status error\n");
                    return CardError(SmidCardError.IntegrityError);
                }

                /* at least 1 status byte + 2 AES blocks (data+CMAC) */
                if (xfer_length != (1 + (2 * 16)))
                {
                    logger.trace("GetData wrong length\n");
                    return CardError(SmidCardError.LengthError);
                }
                xfer_length -= 1; // remove status byte
                offset_xfer_buffer = 1;
            }
            else
            {
                if (xfer_length != (2 * 16))
                {
                    logger.trace("GetData wrong length\n");
                    return CardError(SmidCardError.LengthError);
                }
                offset_xfer_buffer = 0;
            }
            byte[] data_encrypted = new byte[xfer_length];
            Array.ConstrainedCopy(xfer_buffer, offset_xfer_buffer, data_encrypted, 0, xfer_length);
            if ( ((SmidCryptoContext211) SessionCryptoContext).DecipherData(0x0001, data_encrypted, output, ref output_length) == false)
            {
                logger.trace("GetData decipher error\n");
                return CardError(SmidCardError.IntegrityError);
            }
            return status;

        }


        public long HceTransactionCommit(byte[] readerReference, byte statusCode)
        {
            long status = 0;
            
            if (readerReference == null)
            {
                return LibraryError(SmidLibraryError.InvalidParameter);
            }

            xfer_buffer[0] = (byte) ISO7816_CLA;
            xfer_buffer[1] = (byte) SmidCommand.TRANSACTION_COMMIT;
            xfer_buffer[2] = 0x00;      
	        xfer_buffer[3] = 0x00;      
	        xfer_buffer[4] = (byte) (readerReference.Length + 2);
            xfer_buffer[5] = 0x00;  //RFU
            Array.Copy(readerReference, 0, xfer_buffer, 6, readerReference.Length);
            
            xfer_buffer[6 + readerReference.Length] = statusCode;
	        xfer_buffer[6 + readerReference.Length + 1] = 0x00; 
	        xfer_length = 6 + readerReference.Length + 2;

            byte[] data_tocryp = new byte[readerReference.Length + 2];            
            Array.Copy(xfer_buffer, 5, data_tocryp, 0, data_tocryp.Length);
            if (logCrypto)
                logger.trace("data_tocryp:   {0:X02}", BinConvert.ToHex(data_tocryp));
            /* rounded on 16 + 16 for CMAC */
            int rounded_size = (readerReference.Length + 2) + (16 - ((readerReference.Length + 2) % 16)) + 16;
            byte[] output = new byte[rounded_size];
            if (((SmidCryptoContext211)SessionCryptoContext).cipherData(0x0002, data_tocryp, output, (uint)output.Length) == false)
            {
                logger.trace("WriteData Cipher error\n");
                return CardError(SmidCardError.IntegrityError);
            }
            if (logCrypto)
                logger.trace("cryped data:   {0:X02}", BinConvert.ToHex(output));

            xfer_buffer[4] = (byte)(output.Length);

            Array.Copy(output, 0, xfer_buffer, 5, output.Length);
            xfer_length = (ushort)(5 + output.Length);
            if (bCheckSelfTest)
            {
                logger.trace(">  {0:X02}", BinConvert.ToHex(xfer_buffer, xfer_length));                
                xfer_buffer[0] = 0x91;
                xfer_buffer[1] = 0x00;
                xfer_length = 2;
                logger.trace("<  {0:X02}", BinConvert.ToHex(xfer_buffer, xfer_length));
            }
            else
            {
                if (Command(ref status) == false)
                {
                    logger.trace("GetData error\n");
                    return status;
                }
            }

            return status;
        }

        public bool SelfTestOnOff()
        {
            if (bCheckSelfTest)
                bCheckSelfTest = false;
            else
                bCheckSelfTest = true;
            return true;
        }

    }
}
