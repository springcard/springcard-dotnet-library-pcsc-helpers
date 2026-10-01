using System;
using SpringCard.LibCs;
using SpringCard.LibCs.Crypto;

namespace SpringCard.PCSC.CardEmulation
{
    public abstract partial class CardEmulDesfire
    {
        public class DesfireEV2Cipher : IDesfireCipher
        {
            protected CardEmulDesfire Card;

            private AES aesEnc;
            private AES aesCmac;

            private byte[] _SessionEncKey;
            public byte[] SessionEncKey
            { 
                get
                {
                    return _SessionEncKey;
                }
                protected set
                {
                    _SessionEncKey = value;
                    aesEnc = AES.Create(_SessionEncKey);
                }
            }

            private byte[] _SessionCmacKey;
            public byte[] SessionCmacKey
            {
                get
                {
                    return _SessionCmacKey;
                }
                protected set
                {
                    _SessionCmacKey = value;
                    aesCmac = AES.Create_Encrypt(_SessionCmacKey);
                }
            }

            protected byte[] CmacSubKey1;
            protected byte[] CmacSubKey2;
            protected byte[] InitVector = new byte[16];
            public byte[] TransactionIdentifier { get; protected set; }
            public ushort TransactionCounter { get; private set; }

            const int BLOCK_SIZE = 16;
            const byte RB_XOR_VALUE = 0x87;

            public int GetCmacSize()
            {
                return 8;
            }

            public int GetCrcSize()
            {
                return 4;
            }

            protected void ResetInitVector()
            {
                for (int i = 0; i < 16; i++)
                    InitVector[i] = 0;
            }

            public void SetTransactionIdentifier(byte[] TransactionIdentifier)
            {
                this.TransactionIdentifier = TransactionIdentifier;
            }

            public void IncrementCounter()
            {
                TransactionCounter++;
            }

            protected DesfireEV2Cipher(CardEmulDesfire Card)
            {
                this.Card = Card;
            }

            public DesfireEV2Cipher(CardEmulDesfire Card, byte[] KeyValue)
            {
                this.Card = Card;
                this.SessionEncKey = KeyValue;
                this.SessionCmacKey = KeyValue;

                Card.logger.trace("EV2 AES{0} Auth, key={1:X06}", 8 * KeyValue.Length, aesEnc.GetKvcDw());
            }

            public DesfireEV2Cipher(DesfireEV2Cipher Existing, byte[] KeyValue)
            {
                this.Card = Existing.Card;
                this.SessionEncKey = KeyValue;
                this.SessionCmacKey = KeyValue;
                this.TransactionIdentifier = Existing.TransactionIdentifier;
                this.TransactionCounter = Existing.TransactionCounter;
            }

            public int GetBlockSize()
            {
                return BLOCK_SIZE;
            }

            public bool CipherSend(ref byte[] data)
            {
                int totalLength = data.Length + 1;
                while (totalLength % BLOCK_SIZE != 0)
                    totalLength++;

                byte[] buffer = new byte[totalLength];
                Array.ConstrainedCopy(data, 0, buffer, 0, data.Length);
                buffer[data.Length] = 0x80;

                CipherSendEx(ref buffer, false);

                data = buffer;
                return true;
            }

            public bool CipherSendEx(ref byte[] data, bool blankIV)
            {
                return CipherSendEx(aesEnc, ref data, blankIV);
            }

            public bool CipherSendEx(AES aesCore, ref byte[] data, bool blankIV)
            {
                if (Card.logCrypto)
                {
                    Card.logger.debug("CipherSend {0}", BinConvert.ToHex(data));
                    Card.logger.debug(" Using key {0:X06}", aesCore.GetKvcDw());
                }

                byte[] send_iv = null;
                if (blankIV)
                {
                    send_iv = new byte[16];
                }
                else
                {
                    send_iv = MakeInitVector(EInitVectorRefreshMode.Send);
                }

                if (Card.logCrypto)
                    Card.logger.debug("  Using IV {0}", BinConvert.ToHex(send_iv));

                int block_count = data.Length / 16;
                byte[] dummy_iv = new byte[16];

                /* Keep last IV */
                for (int i = 0; i < block_count; i++)
                {
                    if (Card.logCrypto)
                    {
                        Card.logger.debug("Block {0}/{1}", i, block_count);
                        Card.logger.debug("\tPlain        {0}", BinConvert.ToHex(data, 16 * i, 16));
                        Card.logger.debug("\tIV           {0}", BinConvert.ToHex(send_iv));
                    }

                    for (int j = 0; j < 16; j++)
                        data[16 * i + j] ^= (byte)(send_iv[j]);  /* P  <- P XOR IV  */

                    if (Card.logCrypto)
                    {
                        Card.logger.debug("\tPlain XOR IV {0}", BinConvert.ToHex(data, 16 * i, 16));
                    }

                    //2.
                    byte[] tmp = new byte[16];
                    Array.ConstrainedCopy(data, (16 * i), tmp, 0, 16);
                    send_iv = aesCore.Encrypt(tmp);

                    if (Card.logCrypto)
                    {
                        Card.logger.debug("\tCipher       {0}", BinConvert.ToHex(send_iv));
                    }

                    //3.
                    Array.ConstrainedCopy(send_iv, 0, data, (16 * i), 16);// P  <- IV
                }

                if (Card.logCrypto)
                    Card.logger.debug("        -> {0}", BinConvert.ToHex(data));

                return true;
            }

            public bool Padd(ref byte[] buffer)
            {
                buffer = BinUtils.Concat(buffer, 0x80); /* Add padding byte 0x80 */
                while ((buffer.Length % BLOCK_SIZE) != 0)
                    buffer = BinUtils.Concat(buffer, 0x00); /* Add padding byte 0x00 */
                return true;
            }

            public bool CipherRecv(ref byte[] data)
            {
                return CipherRecvEx(ref data, false);
            }

            public bool CipherRecvEx(ref byte[] data, bool blankIV)
            {
                return CipherRecvEx(aesEnc, ref data, blankIV);
            }

            public bool CipherRecvEx(AES aesCore, ref byte[] data, bool blankIV)
            {
                if (Card.logCrypto)
                {
                    Card.logger.debug("CipherRecv {0}", BinConvert.ToHex(data));
                    Card.logger.debug(" Using Key {0:X06}", aesCore.GetKvcDw());
                }

                byte[] recv_iv = null;
                if (blankIV)
                {
                    recv_iv = new byte[16];
                }
                else
                {
                    recv_iv = MakeInitVector(EInitVectorRefreshMode.Recv);
                }

                if (Card.logCrypto)
                    Card.logger.debug("  Using IV {0}", BinConvert.ToHex(recv_iv));

                byte[] buffer = new byte[16];
                byte[] dummy_iv = new byte[16];

                int block_count = data.Length / 16;
                for (int i = 0; i < block_count; i++)
                {
                    //1.
                    Array.ConstrainedCopy(data, (16 * i), buffer, 0, 16);   // B  <- P

                    //2.
                    byte[] tmp = aesEnc.Decrypt(buffer);
                    Array.ConstrainedCopy(tmp, 0, data, (16 * i), 16);

                    //3. 
                    for (int j = 0; j < 16; j++)
                        data[16 * i + j] ^= (byte)(recv_iv[j]);  // P  <- P XOR IV           

                    //4. 
                    Array.ConstrainedCopy(buffer, 0, recv_iv, 0, 16);// IV <- B  
                }

                if (Card.logCrypto)
                    Card.logger.debug("        -> {0}", BinConvert.ToHex(data));
                return true;
            }

            public bool Unpadd(ref byte[] buffer)
            {
                while ((buffer.Length > 0) && (buffer[buffer.Length - 1] == 0x00))
                    buffer = BinUtils.Copy(buffer, 0, buffer.Length - 1);
                if ((buffer.Length == 0) || (buffer[buffer.Length - 1] != 0x80))
                    return false; /* Unpadd failed */
                buffer = BinUtils.Copy(buffer, 0, buffer.Length - 1);
                return true;
            }

            public void InitSession()
            {
                InitCmac();
            }

            protected void InitCmac()
            {
                byte bMSB;
                int i;

                ResetInitVector();

                if (Card.logCrypto)
                    Card.logger.debug("EV2.InitCmac ({0:X02}, {1})", RB_XOR_VALUE, BinConvert.ToHex(SessionCmacKey));

                CmacSubKey1 = new byte[BLOCK_SIZE];
                CmacSubKey2 = new byte[BLOCK_SIZE];

                // Generate the padding bytes for O-MAC by enciphering a zero block
                // with the actual session key:
                for (i = 0; i < CmacSubKey1.Length; i++)
                    CmacSubKey1[i] = 0;

                if (Card.logCrypto)
                    Card.logger.debug("InitCmac 0 {0}", BinConvert.ToHex(CmacSubKey1));

                CipherSendEx(aesCmac, ref CmacSubKey1, true);

                if (Card.logCrypto)
                    Card.logger.debug("InitCmac 1 {0}", BinConvert.ToHex(CmacSubKey1));

                // If the MSBit of the generated cipher == 1 -> K1 = (cipher << 1) ^ Rb ...
                // store MSB:
                bMSB = CmacSubKey1[0];

                // Shift the complete cipher for 1 bit ==> K1:
                byte tmp;
                for (i = 0; i < BLOCK_SIZE - 1; i++)
                {
                    tmp = (byte)((CmacSubKey1[i] << 1) & 0x00FE);
                    CmacSubKey1[i] = tmp;

                    // add the carry over bit:
                    CmacSubKey1[i] |= (byte)(((CmacSubKey1[i + 1] & 0x80) != 0) ? 0x01 : 0x00);
                }

                tmp = (byte)((CmacSubKey1[BLOCK_SIZE - 1] << 1) & 0x00FE);
                CmacSubKey1[BLOCK_SIZE - 1] = tmp;
                if ((bMSB & 0x80) != 0)
                {
                    // XOR with Rb:
                    CmacSubKey1[BLOCK_SIZE - 1] ^= RB_XOR_VALUE;
                }

                if (Card.logCrypto)
                    Card.logger.debug("   -> Key1 {0}", BinConvert.ToHex(CmacSubKey1));

                // store MSB:
                bMSB = CmacSubKey1[0];

                // Shift K1 ==> K2:
                for (i = 0; i < BLOCK_SIZE - 1; i++)
                {
                    CmacSubKey2[i] = (byte)((CmacSubKey1[i] << 1) & 0x00FE);
                    CmacSubKey2[i] |= (byte)(((CmacSubKey1[i + 1] & 0x80) != 0) ? 0x01 : 0x00);
                }
                CmacSubKey2[BLOCK_SIZE - 1] = (byte)((CmacSubKey1[BLOCK_SIZE - 1] << 1) & 0x00FE);

                if ((bMSB & 0x80) == 0x80)
                {
                    // XOR with Rb:
                    CmacSubKey2[BLOCK_SIZE - 1] ^= RB_XOR_VALUE;
                }

                if (Card.logCrypto)
                    Card.logger.debug("   -> Key2 {0}", BinConvert.ToHex(CmacSubKey2));

                ResetInitVector();
            }

            public byte[] ComputeCmacEx(byte[] buffer)
            {
                if (Card.logCrypto)
                    Card.logger.debug("  CalcCmac {0}", BinConvert.ToHex(buffer));

                // Adapt the crypto mode if the sessionkey is done in CBC_Send_Decrypt:
                // enCryptoMethod = (m_SessionKeyCryptoMethod == CRM_3DES_DF4 ? CRM_3DES_ISO:m_SessionKeyCryptoMethod);
                int block_count = buffer.Length / BLOCK_SIZE;
                if (buffer.Length % BLOCK_SIZE != 0)
                    block_count++;

                byte[] padded = new byte[block_count * BLOCK_SIZE];

                Array.ConstrainedCopy(buffer, 0, padded, 0, buffer.Length);

                /* Do the ISO padding and/or XORing */
                if (buffer.Length != padded.Length)
                {
                    /* Block incomplete -> padding */
                    padded[buffer.Length] = 0x80;

                    if (Card.logCrypto)
                    {
                        Card.logger.debug("           {0}", BinConvert.ToHex(padded));
                        string s = "";
                        for (int i = 0; i < BLOCK_SIZE * (block_count - 1); i += BLOCK_SIZE)
                            s += "                                ";
                        Card.logger.debug(" XOR Key 2 {0}{1}", s, BinConvert.ToHex(CmacSubKey2));
                    }

                    /* XOR the last bytes with CMAC_SubKey2 */
                    for (int i = 0; i < BLOCK_SIZE; i++)
                    {
                        padded[padded.Length - BLOCK_SIZE + i] ^= (byte)(CmacSubKey2[i]);
                    }
                }
                else
                {
                    /* Block complete -> no padding */

                    if (Card.logCrypto)
                    {
                        Card.logger.debug("           {0}", BinConvert.ToHex(padded));
                        string s = "";
                        for (int i = 0; i < BLOCK_SIZE * (block_count - 1); i += BLOCK_SIZE)
                            s += "                                ";
                        Card.logger.debug(" XOR Key 1 {0}{1}", s, BinConvert.ToHex(CmacSubKey1));
                    }

                    /* XOR the last bytes with CMAC_SubKey1 */
                    for (int i = 0; i < BLOCK_SIZE; i++)
                    {
                        padded[padded.Length - BLOCK_SIZE + i] ^= (byte)(CmacSubKey1[i]);
                    }
                }

                if (Card.logCrypto)
                    Card.logger.debug("           {0}", BinConvert.ToHex(padded));

                CipherSendEx(aesCmac, ref padded, true);

                // Save the current init vector, which is the last cipher block of the cryptogram:
                Array.ConstrainedCopy(padded, padded.Length - BLOCK_SIZE, InitVector, 0, BLOCK_SIZE);

                byte[] cmac = new byte[BLOCK_SIZE / 2];
                for (int i = 0; i < cmac.Length; i++)
                    cmac[i] = InitVector[2 * i + 1];

                if (Card.logCrypto)
                    Card.logger.debug("      CMAC {0}", BinConvert.ToHex(cmac));

                return cmac;
            }

            public byte[] ComputeCrc(byte[] buffer)
            {
                byte[] crc = new byte[4];
                DesfireEV1Cipher.ComputeCrc32(buffer, buffer.Length, ref crc); /* Same CRC32 as for Desfire EV1 */
                return crc;
            }

            public void AppendCrc(ref byte[] buffer)
            {
                byte[] crc = ComputeCrc(BinUtils.Concat(buffer, 0x00));
                buffer = BinUtils.Concat(buffer, crc);
            }

            public bool CheckCrc(byte[] buffer)
            {
                if (buffer.Length < 4)
                    return false;

                byte[] data = new byte[buffer.Length - 4];
                for (int i = 0; i < data.Length; i++)
                    data[i] = buffer[i];

                byte[] crc = ComputeCrc(data);

                for (int i = 0; i < 4; i++)
                    if (crc[i] != buffer[data.Length + i])
                        return false;

                return true;
            }

            public byte[] ComputeCmac(byte[] buffer)
            {
                int cmacSize = GetCmacSize();

                byte[] header = new byte[7];

                header[0] = 0;
                header[1] = (byte)(TransactionCounter % 0x0100);
                header[2] = (byte)(TransactionCounter / 0x0100);
                Array.ConstrainedCopy(TransactionIdentifier, 0, header, 3, 4);

                byte[] t = BinUtils.Concat(header, buffer);

                byte[] cmac = ComputeCmacEx(t);

                return cmac;
            }

            public void AppendCmac(ref byte[] buffer)
            {               
                byte[] cmac = ComputeCmac(buffer);
                buffer = BinUtils.Concat(buffer, cmac);
            }

            public bool CheckCmac(byte[] buffer)
            {
                int cmacSize = GetCmacSize();
                if (buffer.Length < cmacSize + 1)
                {
                    Card.logger.debug("Buffer is too short for a CMAC ({0}B)", buffer.Length);
                    return false;
                }

                byte[] header = new byte[7];

                header[0] = buffer[0];
                header[1] = (byte)(TransactionCounter % 0x0100);
                header[2] = (byte)(TransactionCounter / 0x0100);
                Array.ConstrainedCopy(TransactionIdentifier, 0, header, 3, 4);

                byte[] data = new byte[0];
                if (buffer.Length > cmacSize + 1)
                    data = BinUtils.Copy(buffer, 1, buffer.Length - cmacSize - 1);

                byte[] t = BinUtils.Concat(header, data);

                byte[] cmacCalc = ComputeCmacEx(t);

                byte[] cmacRecv = BinUtils.Copy(buffer, buffer.Length - cmacSize, cmacSize);

                for (int i = 0; i < cmacSize; i++)
                {
                    if (cmacCalc[i] != cmacRecv[i])
                    {
                        Card.logger.debug("Wrong CMAC [{0}]", TransactionCounter);
                        return false;
                    }
                }

                return true;
            }

            public void SendMessage(byte[] input, out byte[] output)
            {
                int totalLength = input.Length + 1;
                while (totalLength % BLOCK_SIZE != 0)
                    totalLength++;

                byte[] buffer = new byte[totalLength];
                Array.ConstrainedCopy(input, 0, buffer, 1, input.Length);
                buffer[input.Length] = 0x80;

                CipherSendEx(ref buffer, false);

                output = buffer;
            }

            public byte RecvMessage(byte[] input, out byte[] output)
            {
                throw new NotImplementedException("CardEmulDesfireEV2Cipher:RecvMessage");
            }
            public void GenerateSessionKeys128(byte[] abRndA, byte[] abRndB)
            {
                /*SV1 = 0xA5 || 0x5A || 0x00 || 0x01 || 0x00 || 0x80 || RndA[15..14] || (RndA[13..8] XOR RndB[15..10])|| RndB[9..0] || RndA[7..0] */
                byte[] SV1 = new byte[32];
                byte[] SV2 = new byte[32];
                byte[] rnda = new byte[6];
                byte[] rndb = new byte[6];

                Array.ConstrainedCopy(abRndA, 2, rnda, 0, 6);
                Array.ConstrainedCopy(abRndB, 0, rndb, 0, 6);

                for (int j = 0; j < 6; j++)
                    rndb[j] ^= rnda[j];

                /* SV1 = 0xA5 || 0x5A || 0x00 || 0x01 || 0x00 || 0x80 || RndA[15..14] || (RndA[13..8] XOR RndB[15..10])|| RndB[9..0] || RndA[7..0] */
                SV1[0] = 0xA5; SV1[1] = 0x5A; SV1[2] = 0x00; SV1[3] = 0x01; SV1[4] = 0x00; SV1[5] = 0x80;

                /* RndA[15..14] */
                Array.ConstrainedCopy(abRndA, 0, SV1, 6, 2);
                /* (RndA[13..8] XOR RndB[15..10]) */
                Array.ConstrainedCopy(rndb, 0, SV1, 8, 6);
                /* RndB[9..0] */
                Array.ConstrainedCopy(abRndB, 6, SV1, 14, 10);
                /* RndA[7..0] */
                Array.ConstrainedCopy(abRndA, 8, SV1, 24, 8);

                /* SV2 = 0x5A || 0xA5 || 0x00 || 0x01 || 0x00 || 0x80 || RndA[15..14] || (RndA[13..8] XOR RndB[15..10])|| RndB[9..0] || RndA[7..0] */
                SV2[0] = 0x5A; SV2[1] = 0xA5; SV2[2] = 0x00; SV2[3] = 0x01; SV2[4] = 0x00; SV2[5] = 0x80;
                Array.ConstrainedCopy(abRndA, 0, SV2, 6, 2);
                Array.ConstrainedCopy(rndb, 0, SV2, 8, 6);
                Array.ConstrainedCopy(abRndB, 6, SV2, 14, 10);
                Array.ConstrainedCopy(abRndA, 8, SV2, 24, 8);

                /* Initialize the CMAC */
                InitCmac();

                /* Calculate the two session keys */
                ComputeCmacEx(SV2);
                byte[] cmacKey = BinUtils.Copy(InitVector);

                if (Card.logCrypto)
                    Card.logger.debug("Session CMAC key (AES)={0}", BinConvert.ToHex(cmacKey));

                ComputeCmacEx(SV1);
                byte[] cipherKey = BinUtils.Copy(InitVector);

                if (Card.logCrypto)
                    Card.logger.debug("Session Cipher key (AES)={0}", BinConvert.ToHex(cipherKey));

                /* Remember the keys */
                SessionCmacKey = cmacKey;
                SessionEncKey = cipherKey;

                /* Initialize the CMAC */
                InitCmac();

                Card.logger.trace("EV2 AES128 Session, ENC={0:X06}, CMAC={1:X06}", aesEnc.GetKvcDw(), aesCmac.GetKvcDw());
            }

            public void GenerateSessionKeys256(byte[] abRndA, byte[] abRndB)
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

                /* Initialize the CMAC */
                InitCmac();

                /* Calculate the two session keys */
                ComputeCmacEx(SV2a);
                byte[] cmacKey_a = BinUtils.Copy(InitVector);
                ComputeCmacEx(SV2b);
                byte[] cmacKey_b = BinUtils.Copy(InitVector);
                byte[] cmacKey = BinUtils.Concat(cmacKey_a, cmacKey_b);

                if (Card.logCrypto)
                    Card.logger.debug("Session CMAC key (AES)={0}", BinConvert.ToHex(cmacKey));

                ComputeCmacEx(SV1a);
                byte[] cipherKey_a = BinUtils.Copy(InitVector);
                ComputeCmacEx(SV1b);
                byte[] cipherKey_b = BinUtils.Copy(InitVector);
                byte[] cipherKey = BinUtils.Concat(cipherKey_a, cipherKey_b);

                if (Card.logCrypto)
                    Card.logger.debug("Session Cipher key (AES)={0}", BinConvert.ToHex(cipherKey));

                /* Remember the keys */
                SessionCmacKey = cmacKey;
                SessionEncKey = cipherKey;

                /* Initialize the CMAC */
                InitCmac();

                Card.logger.trace("EV2 AES256 Session, ENC={0:X06}, CMAC={1:X06}", aesEnc.GetKvcDw(), aesCmac.GetKvcDw());
            }

            private enum EInitVectorRefreshMode
            {
                Recv,
                Send,
            }

            private byte[] MakeInitVector(EInitVectorRefreshMode mode)
            {
                /* NB: if receiving, the Transaction counter has already been incremented !!! */
                if (mode == EInitVectorRefreshMode.Recv)
                {
                    return MakeInitVector(mode, TransactionIdentifier, (ushort)(TransactionCounter - 1));
                }
                else
                {
                    return MakeInitVector(mode, TransactionIdentifier, TransactionCounter);
                }
            }

            private byte[] MakeInitVector(EInitVectorRefreshMode mode, byte[] TransactionIdentifier, ushort TransactionCounter)
            {
                byte[] buffer = new byte[16];

                switch (mode)
                {
                    case EInitVectorRefreshMode.Recv:
                        buffer[0] = 0xA5;
                        buffer[1] = 0x5A;
                        break;
                    case EInitVectorRefreshMode.Send:
                        buffer[0] = 0x5A;
                        buffer[1] = 0xA5;
                        break;
                    default:
                        throw new ArgumentOutOfRangeException(nameof(mode));
                }

                for (int i = 2; i < 6; i++)
                    buffer[i] = TransactionIdentifier[i - 2];

                /* CmdCtr LSB first */
                buffer[6] = (byte)(TransactionCounter & 0x00FF);
                buffer[7] = (byte)((TransactionCounter >> 8) & 0x00FF);

                for (int i = 8; i < 16; i++)
                    buffer[i] = 0x00;

                if (Card.logCrypto)
                {
                    Card.logger.debug("   Make IV {0}", BinConvert.ToHex(buffer));
                    Card.logger.debug("  With key {0}", BinConvert.ToHex(SessionEncKey));
                }

                buffer = aesEnc.Encrypt(buffer);

                if (Card.logCrypto)
                    Card.logger.debug("     IV <- {0}", BinConvert.ToHex(buffer));

                return buffer;
            }

        }
    }
}