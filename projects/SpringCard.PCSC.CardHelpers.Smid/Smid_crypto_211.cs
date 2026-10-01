using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Crypto.Macs;
using SpringCard.LibCs;
using SpringCard.LibCs.Crypto;
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Text;
using static SpringCard.LibCs.SysLog;


namespace SpringCard.PCSC.CardHelpers
{
   
    /// <summary>
    /// aes cbc 128 nist 800-38a
    /// </summary>
    public static class AesCbc38A
    {
        public static byte[] Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> plaintext)
        {
            ValidateKeyAndIv(key, iv);

            using var aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None;
            aes.Key = key.ToArray();
            aes.IV = iv.ToArray();

            using var enc = aes.CreateEncryptor();
            return enc.TransformFinalBlock(plaintext.ToArray(), 0, plaintext.Length);
        }

        public static byte[] Decrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> ciphertext)
        {
            ValidateKeyAndIv(key, iv);

            using var aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None;
            aes.Key = key.ToArray();
            aes.IV = iv.ToArray();

            using var dec = aes.CreateDecryptor();
            return dec.TransformFinalBlock(ciphertext.ToArray(), 0, ciphertext.Length);
        }

        private static void ValidateKeyAndIv(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
        {
            if (key.Length is not (16 or 24 or 32))
                throw new ArgumentException("Clé AES invalide (16/24/32 octets).", nameof(key));
            if (iv.Length != 16)
                throw new ArgumentException("IV CBC invalide (16 octets).", nameof(iv));
        }
    }


    public static class AesCmac80038B
    {
        /// <summary>
        /// Compute AES-CMAC per NIST SP 800-38B. Returns full 16-byte tag.
        /// Key length must be 16/24/32 bytes (AES-128/192/256).
        /// </summary>
        public static byte[] ComputeTag(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message)
        {
            if (key.Length is not (16 or 24 or 32))
                throw new ArgumentException("AES key must be 16/24/32 bytes.", nameof(key));

            // 1) Subkey generation: L = AES_K(0^128), then K1, K2 (Rb=0x87 for 128-bit block)
            Span<byte> L = stackalloc byte[16];
            Span<byte> K1 = stackalloc byte[16];
            Span<byte> K2 = stackalloc byte[16];

            EncryptEcbBlock(key, Zero16, L);
            GenerateSubkeys(L, K1, K2);

            // 2) Split into n blocks; if message empty => n=1 (special case in spec)
            int n = (message.Length + 15) / 16;
            if (n == 0) n = 1;

            bool lastBlockComplete = message.Length != 0 && (message.Length % 16 == 0);

            // X = 0^128
            Span<byte> X = stackalloc byte[16];
            X.Clear();

            // 3) Process blocks 1..n-1
            Span<byte> Mi = stackalloc byte[16];
            for (int i = 0; i < n - 1; i++)
            {                
                message.Slice(i * 16, 16).CopyTo(Mi);

                XorInPlace(Mi, X);
                EncryptEcbBlock(key, Mi, X); // X = AES_K(Mi xor X)
            }

            // 4) Last block: XOR with K1 if complete else pad and XOR with K2
            Span<byte> Mlast = stackalloc byte[16];
            if (lastBlockComplete)
            {
                message.Slice((n - 1) * 16, 16).CopyTo(Mlast);
                XorInPlace(Mlast, K1);
            }
            else
            {
                int lastLen = (message.Length == 0) ? 0 : message.Length - (n - 1) * 16;
                if (lastLen > 0)
                    message.Slice((n - 1) * 16, lastLen).CopyTo(Mlast);

                // CMAC padding: 0x80 then zeros
                Mlast[lastLen] = 0x80;
                XorInPlace(Mlast, K2);
            }

            XorInPlace(Mlast, X);

            byte[] tag = new byte[16];
            EncryptEcbBlock(key, Mlast, tag);
            return tag;
        }

        /// <summary>Verify (supports truncated tags). Throws nothing; returns true/false.</summary>
        public static bool VerifyTag(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, ReadOnlySpan<byte> expectedTag)
        {
            if (expectedTag.Length < 1 || expectedTag.Length > 16) return false;
            byte[] full = ComputeTag(key, message);
            return FixedTimeEquals(full.AsSpan(0, expectedTag.Length), expectedTag);
        }

        // ===== Internals =====

        private static ReadOnlySpan<byte> Zero16 => new byte[16];

        private static void EncryptEcbBlock(ReadOnlySpan<byte> key, ReadOnlySpan<byte> in16, Span<byte> out16)
        {
            if (in16.Length != 16 || out16.Length != 16)
                throw new ArgumentException("AES block must be 16 bytes.");

            using var aes = Aes.Create();
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None; // important: raw block encryption :contentReference[oaicite:1]{index=1}
            aes.Key = key.ToArray();

            using var enc = aes.CreateEncryptor();

            // Encrypt exactly one block
            byte[] src = in16.ToArray();
            byte[] dst = new byte[16];
            int n = enc.TransformBlock(src, 0, 16, dst, 0);
            if (n != 16) throw new CryptographicException("Unexpected AES block length.");

            dst.CopyTo(out16);
        }

        private static void GenerateSubkeys(ReadOnlySpan<byte> L, Span<byte> K1, Span<byte> K2)
        {
            const byte Rb = 0x87; // for 128-bit block (SP 800-38B) :contentReference[oaicite:2]{index=2}

            LeftShiftOneBit(L, K1);
            if ((L[0] & 0x80) != 0) K1[15] ^= Rb;

            LeftShiftOneBit(K1, K2);
            if ((K1[0] & 0x80) != 0) K2[15] ^= Rb;
        }

        private static void LeftShiftOneBit(ReadOnlySpan<byte> input, Span<byte> output)
        {
            byte carry = 0;
            for (int i = 15; i >= 0; i--)
            {
                byte b = input[i];
                output[i] = (byte)((b << 1) | carry);
                carry = (byte)(((b & 0x80) != 0) ? 1 : 0);
            }
        }

        private static void XorInPlace(Span<byte> a, ReadOnlySpan<byte> b)
        {
            for (int i = 0; i < 16; i++) a[i] ^= b[i];
        }

        private static bool FixedTimeEquals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
        {
            if (a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }
    }


    public partial class Smid
    {
        [Serializable]
        public class SmidCryptoContext211 : SmidCryptoContext, ISerializable
        {
            public const byte EnkKeyId = 0x01;
            public const byte CmacKeyId = 0x02;
            protected const byte RB_XOR_VALUE = 0x87;
            private bool _logCrypto = false;

            ushort _siteCode;
            byte[] _ivSessionEnc;
            byte[] _ivSessionDec;

            [NonSerialized]
            //AES aesEnc;
            private byte[] _SessionEncKey;
            protected byte[] SessionEncKey
            {
                get
                {
                    return _SessionEncKey;
                }
                set
                {
                    _SessionEncKey = value;
                }
            }

            [NonSerialized]
            //AES aesCmac;

            private byte[] _SessionCmacKey;
            protected byte[] SessionCmacKey
            {
                get
                {
                    return _SessionCmacKey;
                }
                set
                {
                    _SessionCmacKey = value;
                }
            }

            protected ReadOnlySpan<byte> selectKey(byte index)
            {
                if (index == EnkKeyId)
                    return SessionEncKey;
                if (index == CmacKeyId)
                    return SessionCmacKey;

                return null;
            }

            public SmidCryptoContext211(Smid smid, byte[] KeySecretValue, ushort SiteCode, byte[] Usi) : base(smid, SiteCode, Usi)
            {
                byte[] usiConcat = new byte[HCE_USI_LENGTH + 1];                

                if (KeySecretValue == null)
                    throw new NullReferenceException(nameof(KeySecretValue));
                if (KeySecretValue.Length != 16)
                    throw new ArgumentOutOfRangeException(nameof(KeySecretValue));

                if (Usi == null)
                {
                    logger.error("USI is NULL");
                    return;
                }

                //SmidCryptoTest();
                _siteCode = SiteCode;
                /* create D <- 0x01|USI */
                usiConcat[0] = 0x01;
                Array.Copy(Usi, 0, usiConcat, 1, HCE_USI_LENGTH);
                
                if (_logCrypto)
                    logger.trace("usiConcat   {0:X02}", BinConvert.ToHex(usiConcat));

                SessionCmacKey = SessionEncKey = AesCmac80038B.ComputeTag(KeySecretValue, usiConcat);
                if (_logCrypto)
                {
                    logger.trace("SessionCmacKey   {0:X02}", BinConvert.ToHex(SessionCmacKey, 16));
                    logger.trace("SessionEncKey    {0:X02}", BinConvert.ToHex(SessionEncKey, 16));
                }
            }

            public byte[] Encrypt(byte keyIndex, ReadOnlySpan<byte> initialCounterBlock, ReadOnlySpan<byte> plaintext)
                => AesCbc38A.Encrypt(this.selectKey(keyIndex), initialCounterBlock, plaintext);

            public byte[] Decrypt(byte keyIndex, ReadOnlySpan<byte> initialCounterBlock, ReadOnlySpan<byte> ciphertext)
                => AesCbc38A.Decrypt(this.selectKey(keyIndex), initialCounterBlock, ciphertext); // CTR decrypt = encrypt


            public bool SessionKeyGeneration(  byte[] salt,
                                        byte[] rndA,
                                        byte[] rndB)
            {
                byte[] ISV1 = new byte[48];
                byte[] ISV2 = new byte[48];
                byte cpt;
                byte[] cmac = new byte[16];

                if (salt == null)
                {
                    logger.trace("SessionKeyGeneration: salt is NULL");
                    return false;
                }
                if (_logCrypto)
                {
                    logger.trace("RndA   {0:X02}", BinConvert.ToHex(rndA, 16));
                    logger.trace("RndB   {0:X02}", BinConvert.ToHex(rndB, 16));
                }

                /* calculate KsesAuthEnc */
                for (cpt = 0; cpt < AES128_BLOCK_LENGTH; cpt++)
                {
                    ISV1[(cpt * 2)] = rndA[cpt];
                    ISV1[(cpt * 2) + 1] = rndB[cpt];
                }
                Array.Copy(salt, 0, ISV1, (2 * AES128_BLOCK_LENGTH), AES128_BLOCK_LENGTH);
                if (_logCrypto)
                    logger.trace("ISV1:   {0:X02}", BinConvert.ToHex(ISV1, 48));

                _SessionEncKey = AesCmac80038B.ComputeTag(SessionCmacKey, ISV1);
                if (_logCrypto)
                    logger.trace("_SessionEncKey:   {0:X02}", BinConvert.ToHex(_SessionEncKey, 16));


                /* calculate KsesAuthMac */
                for (cpt = 0; cpt < AES128_BLOCK_LENGTH; cpt++)
                {
                    ISV2[(cpt * 2)] = rndB[15 - cpt];
                    ISV2[(cpt * 2) + 1] = rndA[15 - cpt];
                }
                Array.Copy(salt, 0, ISV2, (2 * AES128_BLOCK_LENGTH), AES128_BLOCK_LENGTH);
                if (_logCrypto)
                    logger.trace("ISV2:   {0:X02}", BinConvert.ToHex(ISV1, 48));
                _SessionCmacKey = AesCmac80038B.ComputeTag(SessionCmacKey, ISV2);
                if (_logCrypto)
                    logger.trace("_SessionEncKey:   {0:X02}", BinConvert.ToHex(_SessionCmacKey, 16));

                _ivSessionDec = new byte[16];
                _ivSessionEnc = new byte[16];
                return true;
            }
            public void SmidCryptoTest()
            {
                byte[] key = new byte[] { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
                byte[] IV = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
                byte[] Plaintext = new byte[] { 
                    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51};

                byte[] Ciphertext = AesCbc38A.Encrypt(key, IV, Plaintext);
                if (_logCrypto)
                    logger.trace("Ciphertext   {0:X02}", BinConvert.ToHex(Ciphertext, 32));

                byte[] testKey = new byte[] { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
                byte[] test = new byte[] { 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06  };
                byte[] cmac = AesCmac80038B.ComputeTag(testKey, test);
                if (_logCrypto)
                    logger.trace("Cmac   {0:X02}", BinConvert.ToHex(cmac, 16));
            }

            public static byte[] Pad(ReadOnlySpan<byte> data, int lg, int blockSize = 16)
            {
                if (blockSize <= 0) throw new ArgumentOutOfRangeException(nameof(blockSize));

                int padLen = blockSize - (data.Length % blockSize);
                if (padLen == 0) padLen = blockSize; // (rarement utilisé en 7816, mais sûr: force un bloc)

                byte[] outBuf = new byte[data.Length + padLen];
                data.CopyTo(outBuf);

                outBuf[data.Length] = 0x80; // first padding byte
                                            // remaining bytes default to 0x00
                return outBuf;
            }

            /// <summary>
            /// Remove ISO/IEC 7816-4 padding. Throws if invalid.
            /// </summary>
            public static byte[] Unpad(ReadOnlySpan<byte> padded, int lg)
            {
                int i = lg - 1;

                // Skip trailing 0x00
                while (i >= 0 && padded[i] == 0x00) i--;

                // Must find 0x80
                if (i < 0 || padded[i] != 0x80)
                    throw new CryptographicException("Invalid ISO7816-4 padding.");

                byte[] result = new byte[i];
                padded.Slice(0, i).CopyTo(result);
                return result;
            }



            public bool IvCmdeData(ushort cmdCounter)
            {
                byte[] work_buffer = new byte[64];
                ushort ivSessionDecLength = 16;

                work_buffer[0] = 0xc3;
                work_buffer[1] = 0x69;
                work_buffer[2] = (byte)((_siteCode >> 8) & 0xFF);
                work_buffer[3] = (byte)((_siteCode >> 0) & 0xFF);
                work_buffer[4] = (byte)((cmdCounter >> 8) & 0xFF); /* CommandCtr MSB */
                work_buffer[5] = (byte)((cmdCounter >> 0) & 0xFF); /* CommandCtr LSB */
                Array.Copy(SMID_CMDE_DATA_PADDING, 0, work_buffer, 6, SMID_CMDE_DATA_PADDING.Length);
                if (_logCrypto)
                    logger.trace("IV source   {0:X02}", BinConvert.ToHex(work_buffer, SMID_CMDE_DATA_PADDING.Length + 6));

                work_buffer = Encrypt(EnkKeyId, _ivSessionEnc, work_buffer);
                if (_logCrypto)
                    logger.trace("IV used:   {0:X02}", BinConvert.ToHex(work_buffer, work_buffer.Length));

                Array.Copy(work_buffer, 0, _ivSessionEnc, 0, 16);
                if (_logCrypto)
                    logger.trace("IV for Command:   {0:X02}", BinConvert.ToHex(_ivSessionEnc, ivSessionDecLength));

                return true;
            }
            public bool cipherData(ushort cmdCounter,
                                byte[] input_data,
                                byte[] output_data,
                                uint output_data_length)
            {

                byte[] cmac = new byte[16];

                /* calculate IV for CBC mode */
                IvCmdeData(cmdCounter);
                if (_logCrypto)
                    logger.trace("Cipher Data:   {0:X02}", BinConvert.ToHex(input_data));
                
                byte[] enc_buffer = Pad(input_data, input_data.Length);
                if (_logCrypto)
                    logger.trace("Data to cipher (padded):   {0:X02}", BinConvert.ToHex(enc_buffer, 0, enc_buffer.Length));
                
                if ((enc_buffer.Length % 16) != 0)
                {
                    logger.trace("Cipher data length is not multiple of 16");
                    return false;
                }
                if (_logCrypto)
                    logger.trace("_ivSessionEnc:   {0:X02}", BinConvert.ToHex(_ivSessionEnc, 0, _ivSessionEnc.Length));
                byte[] cipher_buffer = Encrypt(EnkKeyId, _ivSessionEnc, enc_buffer);
                if (_logCrypto)
                    logger.trace("Ciphered data:   {0:X02}", BinConvert.ToHex(cipher_buffer, 0, cipher_buffer.Length));

                Array.Copy(cipher_buffer, 0, output_data, 0, cipher_buffer.Length);
                output_data_length = (uint)cipher_buffer.Length;

                byte[] work_buffer = new byte[5 + cipher_buffer.Length];
                /* create a copy of the cyphered data for the CMAC calculation */
                work_buffer[0] = 0x00; /* Status */
                work_buffer[1] = (byte)((cmdCounter >> 8) & 0xFF);          /* CommandCtr MSB */
                work_buffer[2] = (byte)((cmdCounter >> 0) & 0xFF);          /* CommandCtr LSB */
                work_buffer[3] = (byte)((_siteCode >> 8) & 0xFF);
                work_buffer[4] = (byte)((_siteCode >> 0) & 0xFF);
                Array.Copy(cipher_buffer, 0, work_buffer, 5, cipher_buffer.Length);

                if (_logCrypto)
                    logger.trace("CMAC source: :   {0:X02}", BinConvert.ToHex(work_buffer, 0, work_buffer.Length));
                cmac = AesCmac80038B.ComputeTag(SessionCmacKey, work_buffer);
                if (_logCrypto)
                    logger.trace("CMAC result: :   {0:X02}", BinConvert.ToHex(cmac, 0, 16));

                Array.Copy(cmac, 0, output_data, output_data_length, cmac.Length);
                output_data_length = (uint)cmac.Length;

                return true;
            }

            

            public bool IvRespData(ushort cmdCounter)
            {
                byte[] work_buffer = new byte[64];
                ushort ivSessionDecLength = 16;
                    
                work_buffer[0] = 0x69;
                work_buffer[1] = 0xc3;
                work_buffer[2] = (byte)((_siteCode >> 8) & 0xFF);
                work_buffer[3] = (byte)((_siteCode >> 0) & 0xFF);
                work_buffer[4] = (byte)((cmdCounter >> 8) & 0xFF); /* CommandCtr MSB */
                work_buffer[5] = (byte)((cmdCounter >> 0) & 0xFF); /* CommandCtr LSB */
                Array.Copy(SMID_RESP_DATA_PADDING, 0, work_buffer, 6, SMID_RESP_DATA_PADDING.Length);
                if (_logCrypto)
                    logger.trace("IV source   {0:X02}", BinConvert.ToHex(work_buffer, SMID_RESP_DATA_PADDING.Length + 6));

                ivSessionDecLength = 16;
                work_buffer = Encrypt(EnkKeyId, _ivSessionDec, work_buffer);
                if (_logCrypto)
                    logger.trace("work:   {0:X02}", BinConvert.ToHex(work_buffer, work_buffer.Length));

                Array.Copy(work_buffer, 0, _ivSessionDec, 0, 16);
                if (_logCrypto)
                    logger.trace("IV for Response:   {0:X02}", BinConvert.ToHex(_ivSessionDec, ivSessionDecLength));

                return true;
            }

            public bool DecipherData( ushort cmdCounter,
                                byte[] input_data,
                                byte[] output_data,
                                ref uint output_data_length)
            {
                
                byte[] cmac = new byte[16];
                int length;

                /* calculate IV for CBC mode */
                IvRespData(cmdCounter);
                if (_logCrypto)
                    logger.trace("Decipher Data:   {0:X02}", BinConvert.ToHex(input_data));

                /* remove status byte */
                length = input_data.Length;
                /* remove cmac */
                length -= 16;

                if ((length % 16) != 0)
                {
                    logger.trace("Decipher data length is not multiple of 16");
                    return false;
                }
                if (_logCrypto)
                {
                    logger.trace("Data to decipher:   {0:X02}", BinConvert.ToHex(input_data, 0, length));
                    logger.trace("_ivSessionDec:   {0:X02}", BinConvert.ToHex(_ivSessionDec, 0, _ivSessionDec.Length));
                }
                byte[] dec_buffer = Decrypt(EnkKeyId, _ivSessionDec, input_data);
                if (_logCrypto)
                    logger.trace("Deciphered data:   {0:X02}", BinConvert.ToHex(dec_buffer, 0, dec_buffer.Length));
                dec_buffer = Unpad(dec_buffer, length);
                if (_logCrypto)
                    logger.trace("Deciphered data:   {0:X02}", BinConvert.ToHex(dec_buffer, 0, dec_buffer.Length));
                
                Array.Copy(dec_buffer, 0, output_data, 0, dec_buffer.Length);
                output_data_length = (uint)dec_buffer.Length;

                byte[] work_buffer = new byte[5 + length];
                /* create a copy of the cyphered data for the CMAC calculation */
                work_buffer[0] = 0x00; /* Status */
                work_buffer[1] = (byte)((cmdCounter >> 8) &0xFF);          /* CommandCtr MSB */
                work_buffer[2] = (byte)((cmdCounter >> 0) &0xFF);          /* CommandCtr LSB */
                work_buffer[3] = (byte) ((_siteCode >> 8) & 0xFF);
                work_buffer[4] = (byte) ((_siteCode >> 0) & 0xFF);
                Array.Copy(input_data, 0, work_buffer, 5, length);
                length += 5;
                if (_logCrypto)
                    logger.trace("CMAC source: :   {0:X02}", BinConvert.ToHex(work_buffer, 0, work_buffer.Length));
                cmac = AesCmac80038B.ComputeTag(SessionCmacKey, work_buffer);
                if (_logCrypto)
                {
                    logger.trace("CMAC result: :   {0:X02}", BinConvert.ToHex(cmac, 0, 16));
                    logger.trace("CMAC expected: :   {0:X02}", BinConvert.ToHex(input_data, (input_data.Length - 16), 16));
                }

                /* compare CMACs */
                if (Comparebytes(input_data, (uint)(input_data.Length - 16), cmac, 0, 16) == false)
                {
                    logger.trace("CMAC differs\n");
                    LibraryError(SmidLibraryError.CmacDiffer);
                }

                return true;
            }
        }
    }
        
}
