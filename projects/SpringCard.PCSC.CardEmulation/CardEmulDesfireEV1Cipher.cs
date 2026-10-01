//#define _DEBUG_CIPHER
//#define _DEBUG_MAC

using System;
using System.Security.Cryptography;
using System.IO;
using System.Reflection;
using SpringCard.LibCs;
using System.Runtime.InteropServices;
using SpringCard.LibCs.Crypto;

namespace SpringCard.PCSC.CardEmulation
{
    public abstract partial class CardEmulDesfire
    {
        public abstract class DesfireEV1Cipher
        {
            protected CardEmulDesfire Card;
            protected bool IsAES = false;
            protected byte[] KeyValue;
            protected byte[] InitVector;
            protected byte[] CMACSubKey1;
            protected byte[] CMACSubKey2;

            protected DesfireEV1Cipher(CardEmulDesfire Card, bool IsAES, byte[] KeyValue)
            {
                this.Card = Card;
                this.IsAES = IsAES;
                this.KeyValue = KeyValue;
            }

            public static void UpdateDesfireCrc32(byte ch, ref UInt32 pdwCrc)
            {
                byte b;

                pdwCrc ^= ch;

                //  bit wise calcualtion of the CRC value
                for (b = 0; b < 8; b++)
                {
                    if ((pdwCrc & 0x00000001) != 0)
                    {
                        pdwCrc >>= 1;
                        pdwCrc ^= 0xEDB88320;
                    }
                    else
                    {
                        pdwCrc >>= 1;
                    }
                }
            }

            public static UInt32 ComputeCrc32(byte[] buffer, int size, ref byte[] crc)
            {
                UInt32 dwCrc = 0xFFFFFFFF;
                byte[] p = buffer;

                int offset = 0;
                do
                {
                    UpdateDesfireCrc32(p[offset++], ref dwCrc);
                } while ((--size) > 0);

                if (crc != null)
                {
                    crc[0] = (byte)((dwCrc) & 0x000000FF);
                    crc[1] = (byte)((dwCrc >> 8) & 0x000000FF);
                    crc[2] = (byte)((dwCrc >> 16) & 0x000000FF);
                    crc[3] = (byte)((dwCrc >> 24) & 0x000000FF);
                }

                return dwCrc;
            }

            public byte[] ComputeCrc(byte[] buffer)
            {
                byte[] crc = new byte[4];
                ComputeCrc32(buffer, buffer.Length, ref crc);
                return crc;
            }

            public void AppendCrc(ref byte[] buffer)
            {
                byte[] crc = ComputeCrc(BinUtils.Concat(buffer, 0x00)); /* With EV1 we must add the status when computing the CRC */
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

            protected abstract void EncryptBlock(ref byte[] buffer);

            public bool CipherSend(ref byte[] data)
            {
                return CipherSend(ref data, false);
            }

            public bool CipherSend(ref byte[] data, bool padd80)
            {
                int data_length = data.Length;
                if (padd80) data_length++;
                int block_size = IsAES ? 16 : 8;
                int block_count = data_length / block_size;
                if (data_length % block_size != 0)
                    block_count++;

                byte[] padded_data = new byte[block_count * block_size];

                Array.ConstrainedCopy(data, 0, padded_data, 0, data.Length);
                if (padd80)
                    padded_data[data.Length] = 0x80;

                data = padded_data;

                if (Card.logCrypto)
                {
                    Card.logger.debug("CipherSend {0}", BinConvert.ToHex(data));
                    Card.logger.debug("  With Key {0}", BinConvert.ToHex(KeyValue));
                    Card.logger.debug("   With IV {0}", BinConvert.ToHex(InitVector));
                }

                for (int block = 0; block < block_count; block++)
                {
                    byte[] buffer = new byte[block_size];

                    for (int i = 0; i < block_size; i++)
                        buffer[i] = (byte)(data[block_size * block + i] ^ InitVector[i]);

                    EncryptBlock(ref buffer);

                    for (int i = 0; i < block_size; i++)
                    {
                        InitVector[i] = buffer[i];
                        data[block_size * block + i] = buffer[i];
                    }
                }

                if (Card.logCrypto)
                {
                    Card.logger.debug("    Cipher {0}", BinConvert.ToHex(data));
                    Card.logger.debug("   Next IV {0}", BinConvert.ToHex(InitVector));
                }
                return true;
            }

            public bool Padd(ref byte[] buffer)
            {
                int block_size = IsAES ? 16 : 8;
                buffer = BinUtils.Concat(buffer, 0x80); /* Add padding byte 0x80 */
                while ((buffer.Length % block_size) != 0)
                    buffer = BinUtils.Concat(buffer, 0x00); /* Add padding byte 0x00 */
                return true;
            }

            protected abstract void DecryptBlock(ref byte[] buffer);

            public bool CipherRecv(ref byte[] data)
            {
                int block_size = IsAES ? 16 : 8;
                if (data.Length % block_size != 0)
                {
                    Card.logger.debug("CipherRecv {0} -> length={1}, KO", BinConvert.ToHex(data), data.Length);
                    return false;
                }
                int block_count = data.Length / block_size;

                if (Card.logCrypto)
                {
                    Card.logger.debug("CipherRecv {0}", BinConvert.ToHex(data));
                    Card.logger.debug("  With Key {0}", BinConvert.ToHex(KeyValue));
                    Card.logger.debug("   With IV {0}", BinConvert.ToHex(InitVector));
                }

                for (int block = 0; block < block_count; block++)
                {
                    byte[] iv = new byte[block_size];

                    for (int i = 0; i < block_size; i++)
                        iv[i] = data[block_size * block + i];

                    byte[] buffer = new byte[block_size];

                    for (int i = 0; i < block_size; i++)
                        buffer[i] = data[block_size * block + i];

                    DecryptBlock(ref buffer);

                    for (int i = 0; i < block_size; i++)
                        data[block_size * block + i] = (byte)(buffer[i] ^ InitVector[i]);

                    for (int i = 0; i < block_size; i++)
                        InitVector[i] = iv[i];
                }

                if (Card.logCrypto)
                {
                    Card.logger.debug("     Plain {0}", BinConvert.ToHex(data));
                    Card.logger.debug("   Next IV {0}", BinConvert.ToHex(InitVector));
                }
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

            public void IncrementCounter()
            {
                // Nothing to do
            }


            public void InitSession()
            {
                InitCmac();
            }

            protected void InitCmac()
            {
                byte rb_xor_value = (byte)(IsAES ? 0x87 : 0x1B);
                int block_size = (byte)(IsAES ? 16 : 8);

                CMACSubKey1 = new byte[block_size];
                CMACSubKey2 = new byte[block_size];

                byte[] abSavedInitVktr = new byte[InitVector.Length];

                // Save the InitVector:
                Array.ConstrainedCopy(InitVector, 0, abSavedInitVktr, 0, InitVector.Length);

                // Generate the padding bytes for O-MAC by enciphering a zero block
                // with the actual session key:
                for (int i = 0; i < CMACSubKey1.Length; i++)
                    CMACSubKey1[i] = 0;

                if (Card.logCrypto)
                    Card.logger.debug("\tstep0. subkey1={0}", BinConvert.ToHex(CMACSubKey1));

                CipherSend(ref CMACSubKey1);

                if (Card.logCrypto)
                    Card.logger.debug("\tstep1. subkey1={0}", BinConvert.ToHex(CMACSubKey1));

                // If the MSBit of the generated cipher == 1 -> K1 = (cipher << 1) ^ Rb ...
                // store MSB:
                byte bMSB = CMACSubKey1[0];

                // Shift the complete cipher for 1 bit ==> K1:
                byte tmp;
                for (int i = 0; i < block_size - 1; i++)
                {
                    tmp = (byte)((CMACSubKey1[i] << 1) & 0x00FE);
                    CMACSubKey1[i] = tmp;

                    // add the carry over bit:
                    CMACSubKey1[i] |= (byte)(((CMACSubKey1[i + 1] & 0x80) != 0) ? 0x01 : 0x00);
                }

                tmp = (byte)((CMACSubKey1[block_size - 1] << 1) & 0x00FE);
                CMACSubKey1[block_size - 1] = tmp;
                if ((bMSB & 0x80) != 0)
                {
                    // XOR with Rb:
                    CMACSubKey1[block_size - 1] ^= rb_xor_value;
                }

                if (Card.logCrypto)
                    Card.logger.debug("\tstep2. subkey1={0}", BinConvert.ToHex(CMACSubKey1));

                // store MSB:
                bMSB = CMACSubKey1[0];

                // Shift K1 ==> K2:
                for (int i = 0; i < block_size - 1; i++)
                {
                    CMACSubKey2[i] = (byte)((CMACSubKey1[i] << 1) & 0x00FE);
                    CMACSubKey2[i] |= (byte)(((CMACSubKey1[i + 1] & 0x80) != 0) ? 0x01 : 0x00);
                }
                CMACSubKey2[block_size - 1] = (byte)((CMACSubKey1[block_size - 1] << 1) & 0x00FE);

                if ((bMSB & 0x80) == 0x80)
                {
                    // XOR with Rb:
                    CMACSubKey2[block_size - 1] ^= rb_xor_value;
                }

                if (Card.logCrypto)
                    Card.logger.debug("\tstep3. subkey2={0}", BinConvert.ToHex(CMACSubKey2));

                // We have to restore the InitVector:
                Array.ConstrainedCopy(abSavedInitVktr, 0, InitVector, 0, InitVector.Length);

                if (Card.logCrypto)
                {
                    Card.logger.debug("CMAC SubKey1={0}", BinConvert.ToHex(CMACSubKey1));
                    Card.logger.debug("CMAC SubKey2={0}", BinConvert.ToHex(CMACSubKey2));
                }
            }

            public byte[] ComputeCmac(byte[] buffer)
            {
                if (Card.logCrypto)
                    Card.logger.debug("  CalcCMAC {0}", BinConvert.ToHex(buffer));

                // Adapt the crypto mode if the sessionkey is done in CBC_Send_Decrypt:
                // enCryptoMethod = (m_SessionKeyCryptoMethod == CRM_3DES_DF4 ? CRM_3DES_ISO:m_SessionKeyCryptoMethod);
                int block_size = IsAES ? 16 : 8;
                int block_count = buffer.Length / block_size;
                if (buffer.Length % block_size != 0)
                    block_count++;

                byte[] padded = new byte[block_count * block_size];

                Array.ConstrainedCopy(buffer, 0, padded, 0, buffer.Length);

                /* Do the ISO padding and/or XORing */
                if (buffer.Length != padded.Length)
                {
                    /* Block incomplete -> padding */
                    padded[buffer.Length] = 0x80;

                    if (Card.logCrypto)
                    {
                        Card.logger.debug("      Key2 {0}", BinConvert.ToHex(CMACSubKey2));
                        Card.logger.debug("      XOR  {0}", BinConvert.ToHex(padded));
                    }

                    /* XOR the last bytes with CMAC_SubKey2 */
                    for (int i = 0; i < block_size; i++)
                    {
                        padded[padded.Length - block_size + i] ^= (byte)(CMACSubKey2[i]);
                    }
                }
                else
                {
                    /* Block complete -> no padding */
                    if (Card.logCrypto)
                    {
                        Card.logger.debug("      Key1 {0}", BinConvert.ToHex(CMACSubKey1));
                        Card.logger.debug("      XOR  {0}", BinConvert.ToHex(padded));
                    }

                    /* XOR the last bytes with CMAC_SubKey1 */
                    for (int i = 0; i < block_size; i++)
                    {
                        padded[padded.Length - block_size + i] ^= (byte)(CMACSubKey1[i]);
                    }
                }

                CipherSend(ref padded);

                // Save the current init vector, which is the last cipher block of the cryptogram:
                Array.ConstrainedCopy(padded, padded.Length - block_size, InitVector, 0, block_size);

                byte[] cmac = new byte[8];
                for (int i = 0; i < 8; i++)
                    cmac[i] = InitVector[i];

                if (Card.logCrypto)
                    Card.logger.debug("      CMAC {0}", BinConvert.ToHex(cmac));
                return cmac;
            }

            public int GetCmacSize()
            {
                return 8;
            }

            public int GetCrcSize()
            {
                return 4;
            }

            public void AppendCmac(ref byte[] buffer)
            {
                byte[] cmac = ComputeCmac(BinUtils.Concat(buffer, 0x00)); /* We must include the status (0x00 for OK) in the CMAC, but at the end of the buffer */
                buffer = BinUtils.Concat(buffer, cmac);
            }

            public bool CheckCmac(byte[] buffer)
            {
                int cmacSize = GetCmacSize();
                if (buffer.Length < cmacSize)
                {
                    Card.logger.debug("Buffer is too short for a CMAC ({0}B)", buffer.Length);
                    return false;
                }

                byte[] t = BinUtils.Copy(buffer, 0, buffer.Length - cmacSize);
                byte[] cmacCalc = ComputeCmac(t);
                byte[] cmacRecv = BinUtils.Copy(buffer, buffer.Length - cmacSize, cmacSize);

                for (int i = 0; i < cmacSize; i++)
                {
                    if (cmacCalc[i] != cmacRecv[i])
                    {
                        Card.logger.debug("Wrong CMAC");
                        return false;
                    }
                }

                return true;
            }

            public void SendMessage(byte[] input, out byte[] output)
            {
                output = BinUtils.Copy(input);
                AppendCrc(ref output);
                CipherSend(ref output);
            }

            public byte RecvMessage(byte[] input, out byte[] output)
            {
                throw new NotImplementedException("DesfireEV1Cipher:RecvMessage");
            }
        }

        public class DesfireEV1AesCipher : DesfireEV1Cipher, IDesfireCipher
        {
            AES aesCore;

            public DesfireEV1AesCipher(CardEmulDesfire Card, byte[] KeyValue) : base(Card, true, KeyValue)
            {
                aesCore = AES.Create(KeyValue);
                InitVector = new byte[16];
            }

            public int GetBlockSize()
            {
                return 16;
            }

            protected override void EncryptBlock(ref byte[] buffer)
            {
                buffer = aesCore.Encrypt(buffer);
            }

            protected override void DecryptBlock(ref byte[] buffer)
            {
                buffer = aesCore.Decrypt(buffer);
            }
        }

        public class DesfireEV1TDesCipher : DesfireEV1Cipher, IDesfireCipher
        {
            private TDES_CORE core;

            public DesfireEV1TDesCipher(CardEmulDesfire Card, byte[] KeyValue) : base(Card, false, KeyValue)
            {
                core = new TDES_CORE(KeyValue);
                InitVector = new byte[8];
            }

            public int GetBlockSize()
            {
                return 8;
            }

            protected override void EncryptBlock(ref byte[] buffer)
            {
                string m = BinConvert.ToHex(buffer);
                core.Encrypt(ref buffer);
            }

            protected override void DecryptBlock(ref byte[] buffer)
            {
                string m = BinConvert.ToHex(buffer);
                core.Decrypt(ref buffer);
            }
        }
    }
}