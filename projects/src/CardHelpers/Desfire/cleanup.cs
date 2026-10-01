
        /// <summary>
        ///  NIST Special Publication 800-38B. Use KsessionAuthMac
        /// </summary>
        void InitCmacEv2()
        {
            byte bMSB;
            byte block_size, rb_xor_value;
            int t, i;
            byte[] IV = new byte[16];
            rb_xor_value = 0x87;
            block_size = 16;

            CmacSubKey1 = new byte[block_size];
            CmacSubKey2 = new byte[block_size];

            // Generate the padding bytes for O-MAC by enciphering a zero block
            // with the actual session key:
            for (i = 0; i < CmacSubKey1.Length; i++)
                CmacSubKey1[i] = 0;

            t = block_size;
#if _VERBOSE
      Console.WriteLine("=================================================================");
      Console.WriteLine("InitCmacEv2 L= " + BinConvert.ToHex(cmac_subkey_1, t));
#endif
            SP80038BEncrypt(SessionCmacKey, IV, null, ref CmacSubKey1, ref t, t);
#if _VERBOSE
      Console.WriteLine("InitCmacEv2 SesAuthMACKey= " + BinConvert.ToHex(SesAuthMACKey, SesAuthMACKey.Length));
#endif

            // If the MSBit of the generated cipher == 1 -> K1 = (cipher << 1) ^ Rb ...
            // store MSB:
            bMSB = CmacSubKey1[0];

            // Shift the complete cipher for 1 bit ==> K1:
            byte tmp;
            for (i = 0; i < block_size - 1; i++)
            {
                tmp = (byte)((CmacSubKey1[i] << 1) & 0x00FE);
                CmacSubKey1[i] = tmp;

                // add the carry over bit:
                CmacSubKey1[i] |= (byte)(((CmacSubKey1[i + 1] & 0x80) != 0) ? 0x01 : 0x00);
            }

            tmp = (byte)((CmacSubKey1[block_size - 1] << 1) & 0x00FE);
            CmacSubKey1[block_size - 1] = tmp;
            if ((bMSB & 0x80) != 0)
            {
                // XOR with Rb:
                CmacSubKey1[block_size - 1] ^= rb_xor_value;
            }
#if _VERBOSE
      Console.WriteLine("InitCmacEv2 cmac_subkey_1= " + BinConvert.ToHex(cmac_subkey_1, t));
#endif

            // store MSB:
            bMSB = CmacSubKey1[0];

            // Shift K1 ==> K2:
            for (i = 0; i < block_size - 1; i++)
            {
                CmacSubKey2[i] = (byte)((CmacSubKey1[i] << 1) & 0x00FE);
                CmacSubKey2[i] |= (byte)(((CmacSubKey1[i + 1] & 0x80) != 0) ? 0x01 : 0x00);
            }
            CmacSubKey2[block_size - 1] = (byte)((CmacSubKey1[block_size - 1] << 1) & 0x00FE);

            if ((bMSB & 0x80) == 0x80)
            {
                // XOR with Rb:
                CmacSubKey2[block_size - 1] ^= rb_xor_value;
            }
#if _VERBOSE
      Console.WriteLine("InitCmacEv2 cmac_subkey_2= " + BinConvert.ToHex(cmac_subkey_2, t));
#endif

        }

        /// <summary>
        /// MAC(KsAuthMac,Cmd||CmdCtr||TI||CmdHeader||CmdData))
        /// </summary>
        /// <param name="data">input for cmac calculation</param>
        /// <param name="length">lenght of data</param>
        /// <param name="move_status"></param>
        /// <param name="cmac"></param>
        private void ComputeCmacEv2(byte[] data, bool move_status, out byte[] cmac)
        {
            ComputeCmacEV2(data, data.Length, move_status, out cmac);
        }

        private void ComputeCmacEV2(byte[] data, int length, bool move_status, out byte[] cmac, bool verifyPc = false)
        {
            int actual_length, block_size;
            byte[] IV = new byte[16];

            string debug_left = "";
            string debug_right = "";

            logger.debug("ComputeCmacEv2");

            if (!SessionIsEV1OrGreater())
            {
                logger.fatal("INVALID FUNCTION CALL 'Compute CMAC'\n");
                throw new Exception("CMAC EV2 can't be invoked outside an EV2/ISO session");
            }

            /* cryto is AES, so 16 */
            block_size = 16;

            // First we enlarge eNumOfBytes to a multiple of the cipher block size for allocating
            // memory of the intermediate buffer. Zero padding will be done by the DF8Encrypt function.
            // If we are ISO-authenticated, we have to do the spetial padding for the O-MAC:
            actual_length = length;
            if (TransactionIdentifier != null)
            {
                /* add 6 for CmdCtr and TI */
                actual_length += 6;
                while ((actual_length % block_size) != 0)
                    actual_length++;
            }
            else
            {
                if (actual_length == 0)
                    actual_length = 16;
                else
                {
                    if (actual_length == 0)
                        actual_length++;

                    while ((actual_length % block_size) != 0)
                        actual_length++;
                }
            }

            byte[] buffer = new byte[actual_length];

            /* true when request verifying */
            /* true it is or response */
            if (move_status)
            {
                if (TransactionIdentifier == null)
                {
                    Array.ConstrainedCopy(data, 1, buffer, 0, (length - 1));
                    buffer[length - 1] = data[0];

                    debug_right = " " + BinConvert.ToHex(data[0]) + debug_right;
                }
                else
                {
                    /* RespStatus */
                    Array.ConstrainedCopy(data, 0, buffer, 0, 1);

                    /* CmdCtr */
                    buffer[1] = (byte)(CmdCtr & 0x00FF);
                    buffer[2] = (byte)((CmdCtr >> 8) & 0x00FF);
                    debug_left += " " + BinConvert.ToHex(CmdCtr);

                    /* TI */
                    Array.ConstrainedCopy(TransactionIdentifier, 0, buffer, 3, 4);
                    debug_left += " " + BinConvert.ToHex(TransactionIdentifier, 0, 4);

                    /* RespData */
                    Array.ConstrainedCopy(data, 1, buffer, 7, (length - 1));
                    if (length > 1)
                        debug_left += " " + BinConvert.ToHex(data, 1, length - 1);
                }
            }
            else
            {
                if (TransactionIdentifier == null)
                {
                    Array.ConstrainedCopy(data, 0, buffer, 0, (length));
                    debug_left += " " + BinConvert.ToHex(data, 0, length);
                }
                else
                {
                    /* CmdHeader */
                    Array.ConstrainedCopy(data, 0, buffer, 0, 1);
                    debug_left += " " + BinConvert.ToHex(data, 0, 1);

                    /* CmdCtr */
                    buffer[1] = (byte)(CmdCtr & 0x00FF);
                    buffer[2] = (byte)((CmdCtr >> 8) & 0x00FF);
                    debug_left += " " + BinConvert.ToHex(CmdCtr);

                    /* TI */
                    Array.ConstrainedCopy(TransactionIdentifier, 0, buffer, 3, 4);
                    debug_left += " " + BinConvert.ToHex(TransactionIdentifier, 0, 4);

                    /* CmdHeader + CmdData */
                    Array.ConstrainedCopy(data, 1, buffer, 7, (length - 1));
                    if (length > 1)
                        debug_left += " " + BinConvert.ToHex(data, 1, length - 1);
                }
            }

            if (TransactionIdentifier == null)
            {
                if (length == 0)
                {
                    buffer[0] = 0x80;
                    debug_left += " 80";
                }
                else if ((length % block_size) != 0)
                {
                    buffer[length] = 0x80;
                    debug_left += " 80";
                }

                if (((length % block_size) != 0) || (length == 0))
                {
                    if (LogCrypto)
                        logger.debug("\tInput:  {0} [!TI, SK2]", debug_left.TrimStart() + debug_right.TrimEnd());

                    SP80038BEncrypt(SessionCmacKey, IV, CmacSubKey2, ref buffer, ref actual_length, actual_length);
                }
                else
                {
                    if (LogCrypto)
                        logger.debug("\tInput:  {0} [!TI, SK1]", debug_left.TrimStart() + debug_right.TrimEnd());

                    SP80038BEncrypt(SessionCmacKey, IV, CmacSubKey1, ref buffer, ref actual_length, actual_length);
                }

            }
            else if ((TransactionIdentifier != null) && ((((length + 6) % block_size) != 0) || (length == 0)))
            {
                /* Do the ISO padding and/or XORing */
                /* modulo has to be done on Cmd + Ctr + Ti */

                if (buffer.Length > (length + 6))
                {
                    buffer[length + 6] = 0x80;
                    debug_left += " 80";
                }

                if (LogCrypto)
                    logger.debug("\tInput:  {0} [TI, SK2]", debug_left.TrimStart() + debug_right.TrimEnd());

                SP80038BEncrypt(SessionCmacKey, IV, CmacSubKey2, ref buffer, ref actual_length, actual_length);
            }
            else
            {

                /* Block complete -> no padding */
                if (LogCrypto)
                    logger.debug("\tInput:  {0} [TI, SK1]", debug_left.TrimStart() + debug_right.TrimEnd());

                SP80038BEncrypt(SessionCmacKey, IV, CmacSubKey1, ref buffer, ref actual_length, actual_length);
            }


            if (LogCrypto)
                logger.debug("\tCipher: {0}", BinConvert.ToHex(buffer, 0, actual_length));

            cmac = new byte[8];

            /* cmac is present on the last 16 digits */
            /* MACt(key, message) = S14 || S12 || S10 || S8 || S6 || S4 || S2 || S0 */
            for (int z = 0; (z < 8) && (buffer.Length >= 16); z++)
            {
                cmac[z] = buffer[(buffer.Length - 16) + (z * 2) + 1];
            }

            if (LogCrypto)
                logger.debug("\tOutput: {0}", BinConvert.ToHex(cmac));
        }

        long VerifyCmacEV2(byte[] buffer, ref int length)
        {
            int l;

            if (!SessionIsEV1OrGreater())
                return DF_OPERATION_OK;

            l = length;

            if (l < 9)
                return DFCARD_WRONG_LENGTH;

            l -= 8;

            if (LogCrypto)
            {
                logger.debug("VerifyCmacRecvEv2");
                logger.debug("\tIncoming CMAC   {0}", BinConvert.ToHex(buffer, l, 8));
            }

            ComputeCmacEV2(buffer, l, true, out byte[] cmac);

            if (LogCrypto)
            {
                logger.debug("\tCalculated CMAC {0}", BinConvert.ToHex(cmac, 8));
            }

            for (int i = 0; i < 8; i++)
            {
                if (buffer[l + i] != cmac[i])
                {
                    return DFCARD_WRONG_MAC;
                }
            }

            length = l;
            return DF_OPERATION_OK;
        }

        /// <summary>
        /// NIST Special Publication 800-38B.
        /// Used to calculate Session Key.
        /// </summary>
        /// <param name="Key"></param>
        /// <param name="IV"></param>
        /// <param name="input"></param>
        /// <param name="cmac"></param>
        /// <returns></returns>
        public bool CalculateCMACEV2(byte[] Key, byte[] IV, byte[] input, out byte[] cmac)
        {
            int i;
            int actual_length;
            int block_size;
            int length = input.Length;

#if _VERBOSE
      Console.WriteLine("=================================================================");
      Console.WriteLine("CalculateCMACEV2 Key= " + BinConvert.ToHex(Key, Key.Length));
      Console.WriteLine("CalculateCMACEV2 " + BinConvert.ToHex(input, length));
#endif
            SetSessionCmacKey(Key);
            InitCmacEv2();

            /*if (!IsEV1())
              Console.WriteLine("INVALID FUNCTION CALL 'Compute CMAC'\n");*/

            /* cryto is AES, so 16 */
            block_size = 16;

            // First we enlarge eNumOfBytes to a multiple of the cipher block size for allocating
            // memory of the intermediate buffer. Zero padding will be done by the DF8Encrypt function.
            // If we are ISO-authenticated, we have to do the spetial padding for the O-MAC:
            actual_length = length;

            if (actual_length == 0)
            {
                actual_length = 16;
            }
            else
            {
                while ((actual_length % block_size) != 0)
                    actual_length++;
            }

            byte[] buffer = new byte[actual_length];
            for (i = 0; i < actual_length; i++)
                buffer[i] = 0;

            Array.ConstrainedCopy(input, 0, buffer, 0, (length));

#if _VERBOSE
      if (input.Length > 0)
      {
        Console.WriteLine("CalculateCMACEV2 before padding " + BinConvert.ToHex(buffer, actual_length));
      }
#endif

            /* Do the ISO padding and/or XORing */
            if (((length % block_size) != 0) || (length == 0))
            {
                if (length == 0)
                    buffer[0] = 0x80;
                else
                    buffer[length] = 0x80;

#if _VERBOSE
        Console.WriteLine("CalculateCMACEV2 padding padded buffer " + BinConvert.ToHex(buffer, actual_length));
#endif
                SP80038BEncrypt(Key, IV, CmacSubKey2, ref buffer, ref actual_length, actual_length);
            }
            else
            {
                /* Block complete -> no padding */
#if _VERBOSE
        Console.WriteLine("CalculateCMACEV2 no padding buffer " + BinConvert.ToHex(buffer, actual_length));
#endif
                SP80038BEncrypt(Key, IV, CmacSubKey1, ref buffer, ref actual_length, actual_length);
            }


#if _VERBOSE
      Console.WriteLine("CalculateCMACEV2 ciphered " + BinConvert.ToHex(buffer, (buffer.Length - 16), 16));
#endif

            cmac = new byte[16];
            Array.ConstrainedCopy(buffer, (buffer.Length - 16), cmac, 0, 16);

#if _VERBOSE
      Console.WriteLine("CalculateCMACEV2 CMAC " + BinConvert.ToHex(cmac, 16));
#endif
            return true;
        }

        /// <summary>
        /// IV for CmdData = E(KSesAuthENC; 0xA5 || 0x5A || TI || CmdCtr || 0x0000000000000000)
        /// EBC mode of NIST SP800-38A
        /// </summary>
        /// <param name="cipher">header is different between cipher and decipher</param>
        /// 
        void RefreshVectorEv2(bool cipher = true)
        {
            byte[] plain_text = new byte[16];

            for (int i = 0; i < sessionInitVector.Length; i++)
                sessionInitVector[i] = 0;

            if (cipher == true)
            {
                plain_text[0] = 0xA5;
                plain_text[1] = 0x5A;
            }
            else
            {
                plain_text[0] = 0x5A;
                plain_text[1] = 0xA5;
            }

            for (int i = 2; i < 6; i++)
                plain_text[i] = TransactionIdentifier[i - 2];

            /* CmdCtr LSB first */
            plain_text[6] = (byte)(CmdCtr & 0x00FF);
            plain_text[7] = (byte)((CmdCtr >> 8) & 0x00FF);
#if _VERBOSE
      Console.WriteLine("InitVectorEv2 Use CmdCtr {0} ", CmdCtr);
#endif


            for (int i = 8; i < 16; i++)
                plain_text[i] = 0x00;


#if _VERBOSE
      Console.WriteLine("=================================================================");
      Console.WriteLine("InitVectorEv2 Plain " + BinConvert.ToHex(plain_text, 16));
#endif

            byte[] IV = DesfireCryptoEngine.AES_Encrypt_ECB(plain_text, SessionCipherKey, sessionInitVector);

            for (int i = 0; i < IV.Length; i++)
                sessionInitVector[i] = IV[i];

#if _VERBOSE
      Console.WriteLine("InitVectorEv2 Key " + BinConvert.ToHex(SesAuthENCKey, SesAuthENCKey.Length));
      Console.WriteLine("InitVectorEv2 Cipher " + BinConvert.ToHex(init_vector, IV.Length));

#endif


        }

        byte[] SP80038ADecrypt(byte[] cipher_key, byte[] input, int offset = 0, int length = 0, bool random_iv = false)
        {
            byte[] buffer = BinUtils.Copy(input, offset, length);
            SP80038ADecrypt(cipher_key, ref buffer, random_iv);
            return buffer;
        }

        void SP80038ADecrypt(byte[] cipher_key, ref byte[] data, bool random_iv = false)
        {
            int length = data.Length;
            SP80038ADecrypt(cipher_key, ref data, ref length, random_iv);
            if (length < data.Length)
                data = BinUtils.Copy(data, length);
        }

        /// <summary>
        /// Decipher received data, CBC mode of NIST SP800-38A
        /// </summary>
        /// <param name="cipher_key">key to use for deciphering</param>
        /// <param name="data">deciphered data</param>
        /// <param name="length">length of deciphered data</param>
        void SP80038ADecrypt(byte[] cipher_key, ref byte[] data, ref int length, bool random_iv = false)
        {
            byte[] buffer;
            byte[] dummy_iv = new byte[16] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            int block_count;
            int i, j;

            logger.debug("SP80038ADecrypt");

            if (data == null)
                return;

            if ((length % 16) != 0)
                return;

            buffer = new byte[16];
            block_count = (UInt16)(length / 16);

            if (random_iv == false)
            {
                for (i = 0; i < sessionInitVector.Length; i++)
                    sessionInitVector[i] = 0;
            }
            else
            {
                /* refresh IV to take in account CmdCtr */
                RefreshVectorEv2(false);
                //init_vector = new byte[16] { 0xC9, 0x13, 0xB4, 0x53, 0x11, 0xA4, 0x99, 0x59, 0xDF, 0x94, 0x60, 0x12, 0x6D, 0xFD, 0x52, 0x7F };

            }

            logger.debug("\tIV     {0}", BinConvert.ToHex(sessionInitVector));
            logger.debug("\tCipher {0}", BinConvert.ToHex(data, length));

            for (i = 0; i < block_count; i++)
            {
                //1.
                Array.ConstrainedCopy(data, (16 * i), buffer, 0, 16);   // B  <- P

                //2.
                byte[] deciphered = DesfireCryptoEngine.AES_Decrypt(buffer, cipher_key, dummy_iv);
                Array.ConstrainedCopy(deciphered, 0, data, (16 * i), 16);

                //3. 
                for (j = 0; j < 16; j++)
                    data[16 * i + j] ^= sessionInitVector[j];  // P  <- P XOR IV           

                //4. 
                Array.ConstrainedCopy(buffer, 0, sessionInitVector, 0, 16);// IV <- B 
            }

            logger.debug("\tPlain  {0}", BinConvert.ToHex(data, length));
        }

        byte[] SP80038AEncrypt(byte[] plain)
        {
            int block_size = 16;
            int block_count;
            int i, j;
            byte[] dummy_iv = new byte[16] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

            logger.debug("SP80038AEncrypt");

            if (plain == null)
                return null;

            /* refresh IV to take in account CmdCtr */
            RefreshVectorEv2();

            logger.debug("\tIV     {0}", BinConvert.ToHex(sessionInitVector));
            logger.debug("\tPlain  {0}", BinConvert.ToHex(plain));

            /* Step 1 : padding */
            /* adding always 0x80 followed, if required, by zero bytes until a string with a length of a multiple of
             * 16 byte is obtained.There are no exceptions. Note that if the plain data is a multiple of 16 
             * bytes already, an additional padding block is added.
             */

            byte[] padded = BinUtils.Concat(plain, 0x80);
            while ((padded.Length % block_size) != 0)
                padded = BinUtils.Concat(padded, 0);

            logger.debug("\tPadded {0}", BinConvert.ToHex(padded));

            byte[] cipher = new byte[padded.Length];

            block_count = (padded.Length / block_size);

            /* Keep last IV */
            for (i = 0; i < block_count; i++)
            {
                /* P  <- P XOR IV for first */
                /* P  <- P XOR P(n-1) for other */
                for (j = 0; j < 16; j++)
                    padded[16 * i + j] ^= sessionInitVector[j];

                //2.
                byte[] tmp = new byte[block_size];
                Array.ConstrainedCopy(padded, (16 * i), tmp, 0, block_size);

                //3. P  <- IV  
                sessionInitVector = DesfireCryptoEngine.AES_Encrypt(tmp, SessionCipherKey, dummy_iv);
                Array.ConstrainedCopy(sessionInitVector, 0, cipher, (16 * i), 16);
            }

            logger.debug("\tCipher {0}", BinConvert.ToHex(cipher));

            return cipher;
        }

        /// <summary>
        /// CBC mode of NIST SP800-38A
        /// </summary>
        /// <param name="data">data to cipher</param>
        /// <param name="length"></param>
        /// <param name="max_length"></param>
        void SP80038AEncrypt(byte[] input, int offset, int length, int max_length, ref byte[] output, int offset_out, ref int output_length)
        {
            int block_size = 16;
            int block_count;
            int i, j;
            byte[] dummy_iv = new byte[16] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

            logger.debug("SP80038AEncrypt");

            if (input == null)
                return;
            if ((length - offset) <= 0)
                return;

            byte[] plain = BinUtils.Copy(input, offset, length - offset);

            /* refresh IV to take in account CmdCtr */
            RefreshVectorEv2();

            logger.debug("\tIV     {0}", BinConvert.ToHex(sessionInitVector));
            logger.debug("\tPlain  {0}", BinConvert.ToHex(plain));

            /* Step 1 : padding */
            /* adding always 0x80 followed, if required, by zero bytes until a string with a length of a multiple of
             * 16 byte is obtained.There are no exceptions. Note that if the plain data is a multiple of 16 
             * bytes already, an additional padding block is added.
             */

            byte[] padded = BinUtils.Concat(plain, 0x80);
            while ((padded.Length % block_size) != 0)
                padded = BinUtils.Concat(padded, 0);

            logger.debug("\tPadded {0}", BinConvert.ToHex(padded));

            byte[] cipher = new byte[padded.Length];

            block_count = (padded.Length / block_size);

            /* Keep last IV */
            for (i = 0; i < block_count; i++)
            {
                /* P  <- P XOR IV for first */
                /* P  <- P XOR P(n-1) for other */
                for (j = 0; j < 16; j++)
                    padded[16 * i + j] ^= sessionInitVector[j];

                //2.
                byte[] tmp = new byte[block_size];
                Array.ConstrainedCopy(padded, (16 * i), tmp, 0, block_size);

                //3. P  <- IV  
                sessionInitVector = DesfireCryptoEngine.AES_Encrypt(tmp, SessionCipherKey, dummy_iv);
                Array.ConstrainedCopy(sessionInitVector, 0, cipher, (16 * i), 16);
            }

            logger.debug("\tCipher {0}", BinConvert.ToHex(cipher));

            length = cipher.Length;

            if (length >= max_length)
                return;

            Array.ConstrainedCopy(cipher, 0, output, offset_out, length);
            output_length = length + offset_out;
        }

        /// <summary>
        /// NSIST Special Publication 800-38B
        /// </summary>
        /// <param name="cipher_key">cipher key</param>
        /// <param name="cipher_IV">init vector used to cipher</param>
        /// <param name="xor_last_block">last block used for last xor</param>
        /// <param name="data">data to cipher</param>
        /// <param name="length"></param>
        /// <param name="max_length"></param>
        void SP80038BEncrypt(byte[] cipher_key, byte[] cipher_IV, byte[] xor_last_block, ref byte[] data, ref int length, int max_length)
        {
            int actual_length;
            int block_size;
            int block_count;
            int i, j;
            /* dummy and init vector used */
            byte[] dummy_iv = new byte[16] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};


            if (data == null)
                return;

            if (cipher_IV == null)
                return;

            actual_length = length;

            /* Step 1 : padding */
            /* 
             * during the authentication itself(Cmd.AuthenticateEV2First and Cmd.AuthenticateEV2NonFirst),
             * where no padding is applied at all.
             */
            block_size = 16;
            while ((actual_length % block_size) != 0)
            {
                if (actual_length >= max_length)
                    return;
                data[actual_length++] = 0x00;
            }

            block_count = (actual_length / block_size);

            /* Keep last IV */
            for (i = 0; i < block_count; i++)
            {

#if _VERBOSE
    Console.WriteLine(string.Format("IN Block {0} {1} ", i, BinConvert.ToHex(data, (16 * i), 16)));
    Console.WriteLine(string.Format("CIPHER Block {0} {1} ", i, BinConvert.ToHex(cipher_IV, 0, 16)));
#endif
                /* P  <- P XOR IV for first */
                /* P  <- P XOR P(n-1) for other */
                for (j = 0; j < 16; j++)
                    data[16 * i + j] ^= (byte)(cipher_IV[j]);

                //2.
                byte[] tmp = new byte[block_size];
                Array.ConstrainedCopy(data, (16 * i), tmp, 0, block_size);

#if _VERBOSE
    Console.WriteLine(string.Format("XORED Block {0} {1} ", i, BinConvert.ToHex(tmp, 16)));
#endif

                if ((xor_last_block != null) && (i == (block_count - 1)))
                {
                    for (j = 0; j < 16; j++)
                        tmp[j] ^= (byte)(xor_last_block[j]);
#if _VERBOSE
    Console.WriteLine("SUBMAC " + BinConvert.ToHex(tmp, 16));
#endif
                }

                //3. P  <- IV  
                cipher_IV = DesfireCryptoEngine.AES_Encrypt(tmp, cipher_key,  dummy_iv);
                Array.ConstrainedCopy(cipher_IV, 0, data, (16 * i), 16);

#if _VERBOSE
    Console.WriteLine(string.Format("OUT Block {0} {1} ", i, BinConvert.ToHex(cipher_IV, 16)));
#endif
            }

            length = actual_length;

#if _VERBOSE
    Console.WriteLine(string.Format("Cipher result {0} {1} ", i, BinConvert.ToHex(data, length)));
#endif
        }
		
		
        public long AuthenticateEv2First_old(byte KeyNumber, byte[] KeyValue, byte[] PcdCaps2, out byte[] PcdCaps2_echo, out byte[] PiccCaps2)
        {
            long status;
            int t;
            byte[] abRndB = new byte[16];
            byte[] abRndA = new byte[16];
            byte[] IV = new byte[16];

            if (PcdCaps2 == null)
                PcdCaps2 = new byte[0];
            PcdCaps2_echo = null;
            PiccCaps2 = null;

            if (KeyValue == null)
                return DFCARD_LIB_CALL_ERROR;

            switch (KeyValue.Length)
            {
                case 16:
                    break;
                case 32:
                    break;
                default:
                    return DFCARD_LIB_CALL_ERROR;
            }

            logger.trace("AuthenticateEv2First({0:X02})", KeyNumber);
            if (LogSecrets)
                logger.debug("Key: {0}", BinConvert.ToHex(KeyValue));

            /* Each new Authenticate must invalidate the current authentication status. */
            /*
                * For the encryption during authentication(both Cmd.AuthenticateEV2First and
                * Cmd.AuthenticateEV2NonFirst), the IV will be 128 bits of 0.
                */
            InitSession(EAuthType.AES128_EV2, KeyNumber, KeyValue);

            /* Create the command string consisting of the command byte and the parameter byte. */
            xfer_length = 0;
            xfer_buffer[xfer_length++] = DF_AUTHENTICATE_EV2_FIRST;
            xfer_buffer[xfer_length++] = KeyNumber;
            xfer_buffer[xfer_length++] = (byte)PcdCaps2.Length;

            if (PcdCaps2.Length != 0)
            {
                Array.ConstrainedCopy(PcdCaps2, 0, xfer_buffer, xfer_length, PcdCaps2.Length);
                xfer_length += PcdCaps2.Length;
            }


            /* Send the command string to the PICC and get its response (1st frame exchange).
               The PICC has to respond with an DF_ADDITIONAL_FRAME status byte. */
            status = Command(0, WANTS_ADDITIONAL_FRAME, false);
            if (status != DF_OPERATION_OK)
                goto done;

            /* Check the number of bytes received, we expect 17 bytes. */
            if (xfer_length != 17)
            {
                /* Error: block with inappropriate number of bytes received from the card. */
                status = DFCARD_WRONG_LENGTH;
                goto done;
            }

            /* OK, we received the cryptogram E(Kx, RndB) from the PICC.
               Decipher E(Kx, RndB) to get RndB in xfer_buffer.
               Note that the status code has already been extracted from the queue. */

            t = 16;
            byte[] tmp = new byte[t];
            Array.ConstrainedCopy(xfer_buffer, INF + 1, tmp, 0, t);
            SP80038ADecrypt(SessionCipherKey, ref tmp, ref t);
            Array.ConstrainedCopy(tmp, 0, xfer_buffer, INF + 1, t);

            /* Store this RndB (is needed later on for generating the session key). */
            Array.ConstrainedCopy(xfer_buffer, INF + 1, abRndB, 0, 16);

#if _VERBOSE
      Console.WriteLine("abRndB " + BinConvert.ToHex(abRndB, 0, 16));
#endif

            /* Now the PCD has to generate RndA. */
            abRndA = randomGenerator.Get(16);

#if _VERBOSE
      Console.WriteLine("abRndA " + BinConvert.ToHex(abRndA, 0, 16));
#endif

            /* Start the second frame with a status byte indicating to the PICC that the Authenticate
               command is continued. E(Kx, RndA || RndB’)*/
            xfer_buffer[INF + 0] = DF_ADDITIONAL_FRAME;

            /* Append RndA and RndB' ( RndB' is generated by rotating RndB one byte to the left )
               after the status byte.  */
            Array.ConstrainedCopy(abRndA, 0, xfer_buffer, INF + 1, 16);
            Array.ConstrainedCopy(abRndB, 1, xfer_buffer, INF + 1 + 16, 15);
            xfer_buffer[INF + 1 + 31] = abRndB[0]; /* first byte move to last byte */
            xfer_length = 1 + 32;

            //Console.WriteLine("Xfer(clear) > " + BinConvert.ToHex(xfer_buffer, 33));

            /* Apply the DES send operation to the argument bytes before sending the second frame
               to the PICC ( do not include the status byte in the DES operation ). */
            t = 32;
            tmp = new byte[t];
            Array.ConstrainedCopy(xfer_buffer, 1, tmp, 0, t);

            SP80038BEncrypt(SessionCipherKey, IV, null, ref tmp, ref t, t);

            Array.ConstrainedCopy(tmp, 0, xfer_buffer, 1, t);

            /* Send the 2nd frame to the PICC and get its response. */
            status = Command(0, WANTS_OPERATION_OK, false);
            if (status != DF_OPERATION_OK)
                goto done;

            /* We should now have E(Kx, TI || RndA’ || PDcap2 || PCDcap2) in our buffer.
               RndA' was made from RndA by the PICC by rotating the string one byte to the left.
               Decipher E(Kx, TI || RndA’ || PDcap2 || PCDcap2) to get RndA' in xfer_buffer. */
            /* TI : 4 bytes,  RndA’ 16 bytes, PDcap2 6 bytes, PCDcap2 6 bytes) */

            /* copie RndA' */
            t = 32;
            tmp = new byte[t];
            Array.ConstrainedCopy(xfer_buffer, 1, tmp, 0, t);
            SP80038ADecrypt(SessionCipherKey, ref tmp, ref t);
            Array.ConstrainedCopy(tmp, 0, xfer_buffer, 1, t);

#if _VERBOSE
      Console.WriteLine("TI " + BinConvert.ToHex(xfer_buffer, 1, 4));
#endif
            /* Now we have TI || RndA’ || PDcap2 || PCDcap2 in our buffer.
               We have to check whether it matches our local copy of RndA.
               If one of the subsequent comparisons fails, we do not trust the PICC and therefore
               abort the authentication procedure ( no session key is generated ). */

            TransactionIdentifier = new byte[4];
            Array.ConstrainedCopy(xfer_buffer, INF + 1, TransactionIdentifier, 0, 4);

            /* init command counter like the PICC, LSB first */
            CmdCtr = 0x0000;
#if _VERBOSE
      Console.WriteLine("Init CmdCtr {0}", CmdCtr);
#endif

            /* Then compare the bytes 1 to bRndLen-1 of RndA with the first bRndLen-1 bytes in the queue. */
            for (int k = 0; k < 15; k++)
            {
                if (xfer_buffer[INF + 5 + k] != abRndA[1 + k])
                {
                    status = DFCARD_WRONG_KEY;
                    goto done;
                }
            }


            /* Then compare the leftmost byte of RndA with the last byte in the queue. */
            if (xfer_buffer[INF + 1 + 19] != abRndA[0])
            {
                status = DFCARD_WRONG_KEY;
                goto done;
            }

            PiccCaps2 = new byte[6];
            Array.ConstrainedCopy(xfer_buffer, INF + 20, PiccCaps2, 0, 6);

            PcdCaps2_echo = new byte[6];
            Array.ConstrainedCopy(xfer_buffer, INF + 26, PcdCaps2_echo, 0, 6);

            /* Generate session keys */
            /* --------------------- */
            switch (KeyValue.Length)
            {
                case 16:
                    GenerateSessionKeysEV2AES128(KeyValue, abRndA, abRndB);
                    break;
                case 32:
                    GenerateSessionKeysEV2AES256(KeyValue, abRndA, abRndB);
                    break;
            }

            /* Reset the init vector */
            CleanupInitVector();

            /* Initialize the CMAC calculator */
            InitCmacEv2();

            /* Success. */
            RememberAuthKey(KeyValue);
            return DF_OPERATION_OK;

        done:
            EndSecureSession();
            return status;
        }		
		
        void GenerateSessionKeysEV2AES128(byte[] KeyValue, byte[] abRndA, byte[] abRndB)
        {
            /* Desfire Ev2 */
            //SV1 = 0xA5 || 0x5A || 0x00 || 0x01 || 0x00 || 0x80 || RndA[15..14] || (RndA[13..8] ⊕ RndB[15..10])|| RndB[9..0] || RndA[7..0]
            byte[] SV1 = new byte[32];
            byte[] SV2 = new byte[32];
            byte[] rnda = new byte[6];
            byte[] rndb = new byte[6];


#if _VERBOSE
      Console.WriteLine("Key " + BinConvert.ToHex(KeyValue, 0, 16));
      Console.WriteLine("abRndA " + BinConvert.ToHex(abRndA, 0, 16));
      Console.WriteLine("abRndB " + BinConvert.ToHex(abRndB, 0, 16));
#endif

            Array.ConstrainedCopy(abRndA, 2, rnda, 0, 6);
            Array.ConstrainedCopy(abRndB, 0, rndb, 0, 6);

            for (int j = 0; j < 6; j++)
                rndb[j] ^= rnda[j];

            /* SV1 = 0xA5 || 0x5A || 0x00 || 0x01 || 0x00 || 0x80 || RndA[15..14] || (RndA[13..8] ⊕ RndB[15..10])|| RndB[9..0] || RndA[7..0] */
            SV1[0] = 0xA5; SV1[1] = 0x5A; SV1[2] = 0x00; SV1[3] = 0x01; SV1[4] = 0x00; SV1[5] = 0x80;

            /*RndA[15..14]*/
            Array.ConstrainedCopy(abRndA, 0, SV1, 6, 2);
            /*(RndA[13..8] ⊕ RndB[15..10])*/
            Array.ConstrainedCopy(rndb, 0, SV1, 8, 6);
            /* RndB[9..0] */
            Array.ConstrainedCopy(abRndB, 6, SV1, 14, 10);
            /*RndA[7..0] */
            Array.ConstrainedCopy(abRndA, 8, SV1, 24, 8);

            /* SV2 = 0x5A || 0xA5 || 0x00 || 0x01 || 0x00 || 0x80 || RndA[15..14] || (RndA[13..8] ⊕ RndB[15..10])|| RndB[9..0] || RndA[7..0] */
            SV2[0] = 0x5A; SV2[1] = 0xA5; SV2[2] = 0x00; SV2[3] = 0x01; SV2[4] = 0x00; SV2[5] = 0x80;
            Array.ConstrainedCopy(abRndA, 0, SV2, 6, 2);
            Array.ConstrainedCopy(rndb, 0, SV2, 8, 6);
            Array.ConstrainedCopy(abRndB, 6, SV2, 14, 10);
            Array.ConstrainedCopy(abRndA, 8, SV2, 24, 8);

#if _VERBOSE
      Console.WriteLine("SV1 " + BinConvert.ToHex(SV1, 0, 32));
      Console.WriteLine("SV2 " + BinConvert.ToHex(SV2, 0, 32));

#endif

            // 5. Calculate CMAC
            byte[] CMAC_IV = new byte[16];

            CalculateCMACEV2(KeyValue, CMAC_IV, SV2, out byte[] cmacKey);
            CalculateCMACEV2(KeyValue, CMAC_IV, SV1, out byte[] encKey);

            SetSessionKeys(encKey, cmacKey);

#if _VERBOSE
      Console.WriteLine("SessionMacKey " + BinConvert.ToHex(CMAC, 16));
      Console.WriteLine("SessionEnkKey " + BinConvert.ToHex(ENC, 16));
      Console.WriteLine("=================================================================");
#endif

        }

        void GenerateSessionKeysEV2AES256(byte[] KeyValue, byte[] abRndA, byte[] abRndB)
        {
            byte[] SV1a = new byte[32];
            byte[] SV1b = new byte[32];
            byte[] SV2a = new byte[32];
            byte[] SV2b = new byte[32];
            byte[] rnda = new byte[6];
            byte[] rndb = new byte[6];

            Array.ConstrainedCopy(abRndA, 2, rnda, 0, 6);
            Array.ConstrainedCopy(abRndB, 0, rndb, 0, 6);

            for (int j = 0; j < 6; j++)
                rndb[j] ^= rnda[j];

            /* Build SV1a */
            /* ---------- */

            SV1a[0] = 0xA5; SV1a[1] = 0x5A; SV1a[2] = 0x00; SV1a[3] = 0x01; SV1a[4] = 0x01; SV1a[5] = 0x00;
            Array.ConstrainedCopy(abRndA, 0, SV1a, 6, 2);
            Array.ConstrainedCopy(rndb, 0, SV1a, 8, 6);
            Array.ConstrainedCopy(abRndB, 6, SV1a, 14, 10);
            Array.ConstrainedCopy(abRndA, 8, SV1a, 24, 8);

            /* Build SV1b */
            /* ---------- */

            SV1b[0] = 0xA5; SV1b[1] = 0x5A; SV1b[2] = 0x00; SV1b[3] = 0x02; SV1b[4] = 0x01; SV1b[5] = 0x00;

            Array.ConstrainedCopy(abRndA, 0, SV1b, 6, 2);
            Array.ConstrainedCopy(rndb, 0, SV1b, 8, 6);
            Array.ConstrainedCopy(abRndB, 6, SV1b, 14, 10);
            Array.ConstrainedCopy(abRndA, 8, SV1b, 24, 8);

            /* Build SV2a */
            /* ---------- */

            SV2a[0] = 0x5A; SV2a[1] = 0xA5; SV2a[2] = 0x00; SV2a[3] = 0x01; SV2a[4] = 0x01; SV2a[5] = 0x00;
            Array.ConstrainedCopy(abRndA, 0, SV2a, 6, 2);
            Array.ConstrainedCopy(rndb, 0, SV2a, 8, 6);
            Array.ConstrainedCopy(abRndB, 6, SV2a, 14, 10);
            Array.ConstrainedCopy(abRndA, 8, SV2a, 24, 8);

            /* Build SV2b */
            /* ---------- */

            SV2b[0] = 0x5A; SV2b[1] = 0xA5; SV2b[2] = 0x00; SV2b[3] = 0x02; SV2b[4] = 0x01; SV2b[5] = 0x00;
            Array.ConstrainedCopy(abRndA, 0, SV2b, 6, 2);
            Array.ConstrainedCopy(rndb, 0, SV2b, 8, 6);
            Array.ConstrainedCopy(abRndB, 6, SV2b, 14, 10);
            Array.ConstrainedCopy(abRndA, 8, SV2b, 24, 8);

            // 5. Calculate CMAC
            byte[] CMAC_IV = new byte[16];

            CalculateCMACEV2(KeyValue, CMAC_IV, SV2a, out byte[] cmacKey_a);
            CalculateCMACEV2(KeyValue, CMAC_IV, SV2b, out byte[] cmacKey_b);
            CalculateCMACEV2(KeyValue, CMAC_IV, SV1a, out byte[] encKey_a);
            CalculateCMACEV2(KeyValue, CMAC_IV, SV1b, out byte[] encKey_b);

            SetSessionKeys(BinUtils.Concat(encKey_a, encKey_b), BinUtils.Concat(cmacKey_a, cmacKey_b));
        }		
		
		
        /**
 * @fn *   AuthenticateEv2First
 * @brief *   Perform authentication using the specified AES key on the currently
 * @details
 * *
 * @return *   DF_OPERATION_OK    : authentication succeed
 * @note *   AES keys are always 128-bit long.
 */
        public long AuthenticateEv2NonFirst_old(byte KeyNumber, byte[] KeyValue)
        {
            long status;
            int t;
            byte[] abRndB = new byte[16];
            byte[] abRndA = new byte[16];
            byte[] IV = new byte[16];

            if (KeyValue == null)
                return DFCARD_LIB_CALL_ERROR;

            logger.trace("AuthenticateEv2NonFirst({0:X02})", KeyNumber);
            if (LogSecrets)
                logger.debug("Key: {0}", BinConvert.ToHex(KeyValue));

#if _VERBOSE
      Console.WriteLine("AuthenticateEv2NonFirst IN {0}", CmdCtr);
#endif

            /* Initialize the cipher unit with the authentication key */
            InitSession(EAuthType.AES128_EV2, KeyNumber, KeyValue);

            /* Create the command string consisting of the command byte and the parameter byte. */
            xfer_length = 0;
            xfer_buffer[xfer_length++] = DF_AUTHENTICATHE_EV2_NONFIRST;
            xfer_buffer[xfer_length++] = KeyNumber;

            /* Send the command string to the PICC and get its response (1st frame exchange).
               The PICC has to respond with an DF_ADDITIONAL_FRAME status byte. */
            /*do not affect the CmdCtr(neither increasing, nor resetting)*/
            status = Command(0, WANTS_ADDITIONAL_FRAME, false);
#if _VERBOSE
      Console.WriteLine("AuthenticateEv2NonFirst {0}", CmdCtr);
#endif
            if (status != DF_OPERATION_OK)
                goto done;

            /* Check the number of bytes received, we expect 17 bytes. */
            if (xfer_length != 17)
            {
                /* Error: block with inappropriate number of bytes received from the card. */
                status = DFCARD_WRONG_LENGTH;
                goto done;
            }

            /* OK, we received the cryptogram E(Kx, RndB) from the PICC.
               Decipher E(Kx, RndB) to get RndB in xfer_buffer.
               Note that the status code has already been extracted from the queue. */

            t = 16;
            byte[] tmp = new byte[t];
            Array.ConstrainedCopy(xfer_buffer, INF + 1, tmp, 0, t);
            SP80038ADecrypt(SessionCipherKey, ref tmp, ref t);
            Array.ConstrainedCopy(tmp, 0, xfer_buffer, INF + 1, t);

            /* Store this RndB (is needed later on for generating the session key). */
            Array.ConstrainedCopy(xfer_buffer, INF + 1, abRndB, 0, 16);

            /* Now the PCD has to generate RndA. */
            abRndA = randomGenerator.Get(16);

            /* Start the second frame with a status byte indicating to the PICC that the Authenticate
               command is continued. E(Kx, RndA || RndB’)*/
            xfer_buffer[INF + 0] = DF_ADDITIONAL_FRAME;

            /* Append RndA and RndB' ( RndB' is generated by rotating RndB one byte to the left )
               after the status byte.  */
            Array.ConstrainedCopy(abRndA, 0, xfer_buffer, INF + 1, 16);
            Array.ConstrainedCopy(abRndB, 1, xfer_buffer, INF + 1 + 16, 15);
            xfer_buffer[INF + 1 + 31] = abRndB[0]; /* first byte move to last byte */
            xfer_length = 1 + 32;

            /* Apply the DES send operation to the argument bytes before sending the second frame
               to the PICC ( do not include the status byte in the DES operation ). */
            t = 32;
            tmp = new byte[t];
            Array.ConstrainedCopy(xfer_buffer, 1, tmp, 0, t);
            SP80038BEncrypt(SessionCipherKey, IV, null, ref tmp, ref t, t);
            Array.ConstrainedCopy(tmp, 0, xfer_buffer, 1, t);

            /* Send the 2nd frame to the PICC and get its response. */
            status = Command(0, WANTS_OPERATION_OK, false);
            if (status != DF_OPERATION_OK)
                goto done;

            /* We should now have E(Kx, RndA’) in our buffer.
               RndA' was made from RndA by the PICC by rotating the string one byte to the left.
               Decipher E(Kx,RndA’) to get RndA' in xfer_buffer. */
            t = 16;
            tmp = new byte[t];
            Array.ConstrainedCopy(xfer_buffer, 1, tmp, 0, t);
            SP80038ADecrypt(SessionCipherKey, ref tmp, ref t);
            Array.ConstrainedCopy(tmp, 0, xfer_buffer, 1, t);

            /* Now we have RndA’in our buffer.
               We have to check whether it matches our local copy of RndA.
               If one of the subsequent comparisons fails, we do not trust the PICC and therefore
               abort the authentication procedure ( no session key is generated ). */

            /* Then compare the bytes 1 to bRndLen-1 of RndA with the first bRndLen-1 bytes in the queue. */
            for (int k = 0; k < 15; k++)
            {
                if (xfer_buffer[INF + 1 + k] != abRndA[1 + k])
                {
                    status = DFCARD_WRONG_KEY;
                    goto done;
                }
            }

            /* Then compare the leftmost byte of RndA with the last byte in the queue. */
            if (xfer_buffer[INF + 1 + 15] != abRndA[0])
            {
                status = DFCARD_WRONG_KEY;
                goto done;
            }

            /* Desfire Ev2 */
            //SV1 = 0xA5 || 0x5A || 0x00 || 0x01 || 0x00 || 0x80 || RndA[15..14] || (RndA[13..8] ⊕ RndB[15..10])|| RndB[9..0] || RndA[7..0]
            byte[] SV1 = new byte[32];
            byte[] SV2 = new byte[32];
            byte[] rnda = new byte[6];
            byte[] rndb = new byte[6];

            Array.ConstrainedCopy(abRndA, 2, rnda, 0, 6);
            Array.ConstrainedCopy(abRndB, 0, rndb, 0, 6);

            for (int j = 0; j < 6; j++)
                rndb[j] ^= rnda[j];
            /* SV1 = 0xA5 || 0x5A || 0x00 || 0x01 || 0x00 || 0x80 || RndA[15..14] || (RndA[13..8] ⊕ RndB[15..10])|| RndB[9..0] || RndA[7..0] */
            SV1[0] = 0xA5; SV1[1] = 0x5A; SV1[2] = 0x00; SV1[3] = 0x01; SV1[4] = 0x00; SV1[5] = 0x80;
            Array.ConstrainedCopy(abRndA, 0, SV1, 6, 2);
            Array.ConstrainedCopy(rndb, 0, SV1, 8, 6);
            Array.ConstrainedCopy(abRndB, 6, SV1, 14, 10);
            Array.ConstrainedCopy(abRndA, 8, SV1, 24, 8);

            /* SV2 = 0x5A || 0xA5 || 0x00 || 0x01 || 0x00 || 0x80 || RndA[15..14] || (RndA[13..8] ⊕ RndB[15..10])|| RndB[9..0] || RndA[7..0] */
            SV2[0] = 0x5A; SV2[1] = 0xA5; SV2[2] = 0x00; SV2[3] = 0x01; SV2[4] = 0x00; SV2[5] = 0x80;
            Array.ConstrainedCopy(abRndA, 0, SV2, 6, 2);
            Array.ConstrainedCopy(rndb, 0, SV2, 8, 6);
            Array.ConstrainedCopy(abRndB, 6, SV2, 14, 10);
            Array.ConstrainedCopy(abRndA, 8, SV2, 24, 8);

            // 5. Calculate CMAC
            byte[] CMAC_IV = new byte[16];

            CalculateCMACEV2(KeyValue, CMAC_IV, SV2, out byte[] cmacKeyValue);
            CalculateCMACEV2(KeyValue, CMAC_IV, SV1, out byte[] encryptionKeyValue);

            SetSessionKeys(encryptionKeyValue, cmacKeyValue);

#if _VERBOSE
      Console.WriteLine("Mac session " + BinConvert.ToHex(CMAC, 16));
      Console.WriteLine("End session " + BinConvert.ToHex(ENC, 16));
#endif

            /* Reset the init vector */
            CleanupInitVector();

            /* Initialize the CMAC calculator */
            InitCmacEv2();



#if _VERBOSE
      Console.WriteLine("AuthenticateEv2NonFirst OUT {0}", CmdCtr);
#endif

            /* Success. */
            RememberAuthKey(KeyValue);
            return DF_OPERATION_OK;

        done:
            EndSecureSession();
            return status;
        }		
		
		
        public void test_nsist()
        {
            byte[] cmac;

            InitSession(EAuthType.AES128_EV2, 0, null);

            //byte[] test= new byte[] { 0x5E, 0x3F, 0x0F, 0x4A, 0xC5, 0x26, 0x3E, 0x5A, 0x68, 0xEB, 0xAD, 0xDB, 0x1B, 0x58, 0xB7, 0xBE, 0xED, 0xB7, 0x5E, 0x4A, 0xFF, 0x2D, 0x24, 0x95, 0xE1, 0x12, 0xCA, 0xC7, 0xA9, 0x81, 0xFA, 0x8D };
            byte[] test = new byte[] { 0xC6, 0xFA, 0x96, 0x1F, 0x44, 0xA2, 0xC7, 0x9F, 0x10, 0x46, 0xE2, 0x2B, 0x81, 0x11, 0x3D, 0xAF, 0x27, 0xF0, 0x6B, 0x5E, 0x71, 0xBC, 0x39, 0x95, 0x6B, 0xF4, 0xF5, 0x2D, 0x40, 0xF8, 0x68, 0xBB };
            byte[] appBKeyMaster0_16 = new byte[16] { 0x41, 0x70, 0x70, 0x2E, 0x42, 0x20, 0x4D, 0x61, 0x73, 0x74, 0x65, 0x72, 0x20, 0x4B, 0x65, 0x79 };
            byte[] ivv = new byte[16];
            int tt = 32;
            SP80038BEncrypt(appBKeyMaster0_16, ivv, null, ref test, ref tt, tt);

#if _VERBOSE
      Console.WriteLine("=========================================================");
      Console.WriteLine("====================== TEST 1 ===========================");
#endif

            /* nsist example 1 */
            byte[] key1 = new byte[] { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C };
            byte[] M1 = new byte[16];
            SetSessionCmacKey(key1);
            InitCmacEv2();
            ComputeCmacEV2(M1, 0, false, out cmac);
#if _VERBOSE
      Console.WriteLine("=========================================================");
      Console.WriteLine("==================== TEST 2 ==========================");
#endif

            /* nsist example 2 */
            byte[] key2 = new byte[] { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C };
            byte[] M2 = new byte[16] { 0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A };
            SetSessionCmacKey(key2);
            InitCmacEv2();
            ComputeCmacEv2(M2, false, out cmac);
#if _VERBOSE
      Console.WriteLine("=========================================================");
      Console.WriteLine("==================== TEST 3 ==============================");
#endif

            /* nsist example 3 */
            byte[] key3 = new byte[] { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C };
            byte[] M3 = new byte[20] { 0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A, 0xAE, 0x2D, 0x8A, 0x57 };
            SetSessionCmacKey(key3);
            InitCmacEv2();
            ComputeCmacEv2(M3, false, out cmac);

#if _VERBOSE
      Console.WriteLine("=========================================================");
      Console.WriteLine("===================== TEST 4 =============================");
#endif

            /* nsist example 1 */
            byte[] key4 = new byte[] { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C };
            byte[] M4 = new byte[64] {
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
        0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
        0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
        0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10 };
            SetSessionCmacKey(key4);
            InitCmacEv2();
            ComputeCmacEv2(M4, false, out cmac);

#if _VERBOSE
      Console.WriteLine("=========================================================");
      Console.WriteLine("===================== TEST 5 ============================");
#endif

            byte[] key = new byte[16] { 0x18, 0x5D, 0x0E, 0x3C, 0xEA, 0x4C, 0x0C, 0x32, 0xDF, 0xAD, 0x84, 0xB3, 0x41, 0x4A, 0x50, 0x54 };
            byte[] M = new byte[] { 0xBD, 0x02, 0x00, 0xB0, 0x4D, 0x6C, 0x11, 0x02, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00 };
            byte[] M0 = new byte[] { 0x3D, 0x01, 0x00, 0xB0, 0x4D, 0x6C, 0x11, 0x02, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15 };

            SetSessionCmacKey(key);
            InitCmacEv2();
            ComputeCmacEv2(M, false, out cmac);

#if _VERBOSE
      Console.WriteLine("=========================================================");
      Console.WriteLine("=================== TEST 6 ==============================");
#endif

            InitCmacEv2();
            ComputeCmacEv2(M0, false, out cmac);



#if _VERBOSE
      Console.WriteLine("=========================================================");
      Console.WriteLine("=================== TEST 7 ===============================");
#endif

            byte[] key5 = new byte[16];
            byte[] M5 = new byte[] { 0xA5, 0x5A, 0x00, 0x01, 0x00, 0x80, 0x87, 0x6D, 0xE9, 0x7B, 0x7F, 0x8D, 0xCF,
        0x2B, 0x2B, 0xA7, 0x7D, 0x10, 0xB2, 0x80, 0x25, 0xF2, 0x24, 0xE6, 0xAF, 0xBF, 0x56, 0x48, 0x34, 0xF9, 0x8F, 0x1E };

            byte[] M6 = new byte[] { 0x5A, 0xA5, 0x00, 0x01, 0x00, 0x80, 0x87, 0x6D, 0xE9, 0x7B, 0x7F, 0x8D, 0xCF,
        0x2B, 0x2B, 0xA7, 0x7D, 0x10, 0xB2, 0x80, 0x25, 0xF2, 0x24, 0xE6, 0xAF, 0xBF, 0x56, 0x48, 0x34, 0xF9, 0x8F, 0x1E };

            byte[] IV = new byte[16];

            CalculateCMACEV2(key5, IV, M5, out cmac);
            CalculateCMACEV2(key5, IV, M6, out cmac);

            SetSessionCmacKey(key5);
            InitCmacEv2();
            ComputeCmacEv2(M5, false, out cmac);

            InitCmacEv2();
            ComputeCmacEv2(M6, false, out cmac);


#if _VERBOSE
      Console.WriteLine("=========================================================");
      Console.WriteLine("==================== TEST 8 ==============================");
#endif

            byte[] plain_text = new byte[16];
            byte[] encKey = new byte[16] { 0x03, 0x0A, 0x8C, 0x76, 0xBB, 0xC9, 0x54, 0x51, 0x3A, 0x52, 0xB2, 0xAA, 0xD1, 0x61, 0xD1, 0x5B };
            plain_text = new byte[16] { 0xA5, 0x5A, 0xB0, 0x4D, 0x6C, 0x11, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

            Console.WriteLine("InitVectorEv2 Before AES_Encrypt_ECB " + BinConvert.ToHex(plain_text, 16));
            byte[] init = new byte[16] { 0x03, 0x0A, 0x8C, 0x76, 0xBB, 0xC9, 0x54, 0x51, 0x3A, 0x52, 0xB2, 0xAA, 0xD1, 0x61, 0xD1, 0x5B };
            byte[] result = DesfireCryptoEngine.AES_Encrypt_ECB(plain_text, encKey, init);
            Console.WriteLine("InitVectorEv2 After AES_Encrypt_ECB= " + BinConvert.ToHex(result, result.Length));

            TransactionIdentifier = new byte[4];
            SetSessionCipherKey(encKey);
            InitCmacEv2();
            int length = 0;
            int t = 16;
            byte[] tmp = new byte[48];


            Console.WriteLine("A CipherSP80038A Plain " + BinConvert.ToHex(plain_text, 16));
            SP80038AEncrypt(plain_text, 0, 16, 48, ref tmp, 0, ref t);
            Console.WriteLine("B CipherSP80038A Cipher " + BinConvert.ToHex(tmp, t));
            SP80038ADecrypt(encKey, ref plain_text, ref length, false);
            Console.WriteLine("C CipherSP80038A DeCipher " + BinConvert.ToHex(plain_text, 16));



            plain_text = new byte[16] { 0x3B, 0x7A, 0x63, 0xF3, 0x1B, 0xB6, 0x08, 0x84, 0xCC, 0xC0, 0x99, 0xE8, 0x36, 0xFB, 0x32, 0xAA };
            encKey = new byte[16] { 0xD2, 0xDB, 0x39, 0x03, 0x5F, 0xB4, 0x60, 0xA3, 0x1A, 0x46, 0xD9, 0xD1, 0x26, 0x71, 0xEB, 0x9A };

            length = 16;
            SP80038ADecrypt(encKey, ref plain_text, ref length, false);


        }		
		
		
        public bool DecodeAuthenticateEV2First1(byte[] pbCryptogram, byte[] KeyValue, out byte[] RndPicc)
        {
            RndPicc = null;

            if (pbCryptogram == null)
                return false;
            if (pbCryptogram[0] != 0xAF)
                return false;
            if (pbCryptogram.Length != 17)
                return false;

            RndPicc = SP80038ADecrypt(KeyValue, pbCryptogram, 1, 16);

            Logger.Info(BinConvert.ToHex(RndPicc));

            return true;
        }

        public bool DecodeAuthenticateEV2First2(byte[] pbCryptogram, byte[] KeyValue, out byte[] RndPicc, out byte[] RndPcd)
        {
            RndPicc = null;
            RndPcd = null;

            if (pbCryptogram == null)
                return false;
            if (pbCryptogram[0] != 0xAF)
                return false;
            if (pbCryptogram.Length != 33)
                return false;

            byte[] buffer = SP80038ADecrypt(KeyValue, pbCryptogram, 1, 32);

            Logger.Info(BinConvert.ToHex(buffer));

            RndPcd = BinUtils.Copy(buffer, 0, 16);
            RndPicc = BinUtils.Concat(BinUtils.Copy(buffer, 31, 1), BinUtils.Copy(buffer, 16, 15));

            return true;
        }

        public bool DecodeAuthenticateEV2First3(byte[] pbCryptogram, byte[] KeyValue, out byte[] RndPcd, out byte[] TransactionIdentifier, out byte[] PICCCaps2, out byte[] PCDCaps2)
        {
            RndPcd = null;
            TransactionIdentifier = null;
            PICCCaps2 = null;
            PCDCaps2 = null;

            if (pbCryptogram == null)
                return false;
            if (pbCryptogram[0] != 0x00)
                return false;
            if (pbCryptogram.Length != 33)
                return false;

            byte[] buffer = SP80038ADecrypt(KeyValue, pbCryptogram, 1, 32);

            Logger.Info(BinConvert.ToHex(buffer));

            TransactionIdentifier = BinUtils.Copy(buffer, 0, 4);
            RndPcd = BinUtils.Concat(BinUtils.Copy(buffer, 19, 1), BinUtils.Copy(buffer, 4, 15));

            PICCCaps2 = BinUtils.Copy(buffer, 20, 6);
            PCDCaps2 = BinUtils.Copy(buffer, 26, 6);

            return true;
        }
		