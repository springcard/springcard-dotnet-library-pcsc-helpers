/*
 * Created by SharpDevelop.
 * User: Jerome Izaac
 * Date: 12/09/2017
 * Time: 14:22
 * 
 * To change this template use Tools | Options | Coding | Edit Standard Headers.
 */
using SpringCard.LibCs;
using System;
using System.Collections.Generic;
using System.Runtime.Serialization;
using System.Security.Cryptography;

namespace SpringCard.PCSC.CardHelpers
{
    /// <summary>
    /// Description of DESFire_mgmt.
    /// </summary>
    public partial class Desfire
    {
        [Serializable]
        public abstract class DesfireCryptoContext
        {
            protected Desfire desfire { get; private set; }
            protected ILogger logger { get; private set; }
            protected IRandomGenerator randomGenerator { get; private set; }

            public EPaddMode DefaultPaddMode { get; protected set; } = EPaddMode.Default;
            public EAuthType AuthType { get; protected set; } = EAuthType.NONE;
            public int KeySize{ get; protected set; }
            public int BlockSize { get; private set; }
            public int CmacSize { get; private set; }

            /* Serialization */
            public virtual void GetObjectData(SerializationInfo info, StreamingContext context)
            {
                info.AddValue("PaddMode", DefaultPaddMode);
                info.AddValue("AuthType", AuthType);
                info.AddValue("KeySize", KeySize);
                info.AddValue("BlockSize", BlockSize);
                info.AddValue("CmacSize", CmacSize);
            }

            /* Deserialization */
            protected DesfireCryptoContext(SerializationInfo info, StreamingContext context)
            {
                DefaultPaddMode = (EPaddMode)info.GetValue("PaddMode", typeof(EPaddMode));
                AuthType = (EAuthType)info.GetValue("AuthType", typeof(EAuthType));
                KeySize = (int)info.GetValue("KeySize", typeof(int));
                BlockSize = (int)info.GetValue("BlockSize", typeof(int));
                CmacSize = (int)info.GetValue("CmacSize", typeof(int));
            }

            protected DesfireCryptoContext(Desfire desfire, EAuthType AuthType, EPaddMode DefaultPaddMode, int BlockSize, int CmacSize)
            {
                SetCard(desfire);
                this.AuthType = AuthType;
                this.DefaultPaddMode = DefaultPaddMode;
                this.BlockSize = BlockSize;
                this.CmacSize = CmacSize;
            }

            internal void SetCard(Desfire desfire)
            {
                if (desfire == null)
                    throw new ArgumentNullException(nameof(desfire), "Desfire cannot be null");

                this.desfire = desfire;

                if (desfire.logger == null)
                {
                    this.logger = new Logger(this);
                }
                else if (desfire.logger is Logger)
                {
                    this.logger = new Logger(desfire.logger as Logger, this);
                }
                else
                {
                    this.logger = desfire.logger;
                }

                if (desfire.randomGenerator == null)
                {
                    this.randomGenerator = new DefaultRandomGenerator();
                }
                else
                {
                    this.randomGenerator = desfire.randomGenerator;
                }
            }

            public virtual void CipherRecv(ref byte[] data) { throw new NotImplementedException(); }
            public virtual void CipherSend(ref byte[] data) { throw new NotImplementedException(); }

            public enum EPaddMode
            {
                Default = -1, /* Use default */
                None = 0, /* The buffer is expected to already have the right size */
                Zeros, /* Padd only with 00 */
                Mark /* Padd with 80 and 00 */
            }

            readonly byte[] PaddingZeros = new byte[]{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            readonly byte[] PaddingMark = new byte[] { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

            public void Padd(ref byte[] buffer, EPaddMode mode = EPaddMode.Default)
            {
                if (desfire.logCrypto)
                    logger.debug("Padd {0} bytes ({1})", buffer.Length, mode);

                byte[] paddingBytes = null;

                if (mode == EPaddMode.Default)
                    mode = DefaultPaddMode;

                switch (mode)
                {
                    case EPaddMode.None:
                        /* No padding */
                        return;

                    case EPaddMode.Zeros:
                        paddingBytes = PaddingZeros;
                        break;

                    case EPaddMode.Mark:
                        paddingBytes = PaddingMark;
                        break;

                    case EPaddMode.Default:
                        throw new Exception("Padd invoked without specifying a default mode");                    
                }

                if (mode == EPaddMode.None)
                    return;

                int bufferLength = buffer.Length;

                if ((bufferLength % BlockSize) == 0)
                {
                    if (mode == EPaddMode.Zeros)
                        return; /* Padding not required */
                }

                int paddingLength = 1;
                while (((bufferLength + paddingLength) % BlockSize) != 0)
                    paddingLength++;

                /* Padd to reach a multiple of block size */
                buffer = BinUtils.Concat(buffer, BinUtils.Copy(paddingBytes, 0, paddingLength));
            }

            public void Padd(ref byte[] data, ref int length, int offset, EPaddMode mode = EPaddMode.Default)
            {
                byte[] buffer = BinUtils.Copy(data, offset, length - offset);
                Padd(ref buffer, mode);
                Array.Copy(buffer, 0, data, offset, buffer.Length);
                length = offset + buffer.Length;
            }

            public void Padd(ref byte[] data, ref int length, EPaddMode mode = EPaddMode.Default)
            {
                Padd(ref data, ref length, 0, mode);
            }

            public bool Unpadd(ref byte[] data, EPaddMode mode = EPaddMode.Default)
            {
                if (mode == EPaddMode.Default)
                    mode = DefaultPaddMode;

                switch (mode)
                {
                    case EPaddMode.None:
                        /* No padding */
                        return true;

                    case EPaddMode.Zeros:
                        break;

                    case EPaddMode.Mark:
                        break;

                    case EPaddMode.Default:
                        throw new Exception("Unpadd invoked without specifying a default mode");
                }

                if ((data.Length % BlockSize) != 0)
                    return false;

                if (mode == EPaddMode.Mark)
                {
                    int newLength = data.Length;

                    while ((newLength > 0) && (data[newLength - 1] == 0x00))
                        newLength--;
                    if (newLength <= 0)
                        return false; /* Padding is not .. 00 */
                    if (data[newLength - 1] != 0x80)
                        return false; /* Padding is not 80 .. 00 */
                    newLength--;
                    if ((data.Length - newLength) > BlockSize)
                        return false; /* Padding is too long */
                    data = BinUtils.Copy(data, 0, newLength);
                }

                return true;
            }

            public void CipherSend(ref byte[] data, ref int length, int offset)
            {
                byte[] buffer = BinUtils.Copy(data, offset, length - offset);
                if ((buffer.Length % BlockSize) != 0)
                    throw new Exception("Buffer has not been padded before invoking CipherSend");
                CipherSend(ref buffer);
                Array.Copy(buffer, 0, data, offset, buffer.Length);
                length = offset + buffer.Length;
            }

            public void CipherSend(ref byte[] data, ref int length)
            {
                byte[] buffer = BinUtils.Copy(data, 0, length);
                if ((buffer.Length % BlockSize) != 0)
                    throw new Exception("Buffer has not been padded before invoking CipherSend");
                CipherSend(ref buffer);
                Array.ConstrainedCopy(buffer, 0, data, 0, length);
            }

            public void CipherRecv(ref byte[] data, ref int length)
            {
                if ((length % BlockSize) != 0)
                    throw new InvalidOperationException();

                byte[] buffer = BinUtils.Copy(data, 0, length);

                CipherRecv(ref buffer);

                Array.ConstrainedCopy(buffer, 0, data, 0, buffer.Length);
                length = buffer.Length;
            }

            public abstract byte[] ComputeCmac(byte[] data);

            public abstract byte[] ComputeCmacSend(byte[] data);

            public byte[] ComputeCmacSend(byte[] data, int length)
            {
                return ComputeCmacSend(BinUtils.Copy(data, 0, length));
            }

            public byte[] ComputeCmacSend(byte[] data, int offset, int length)
            {
                return ComputeCmacSend(BinUtils.Copy(data, offset, length));
            }

            public abstract byte[] ComputeCmacRecv(byte[] data);

            public byte[] ComputeCmacRecv(byte[] data, int length)
            {
                return ComputeCmacRecv(BinUtils.Copy(data, 0, length));
            }

            public byte[] ComputeCmacRecv(byte[] data, int offset, int length)
            {
                return ComputeCmacRecv(BinUtils.Copy(data, offset, length));
            }

            public void AppendCmacSend(ref byte[] buffer, ref int length)
            {
                byte[] cmac = ComputeCmacSend(BinUtils.Copy(buffer, 0, length));
                Array.ConstrainedCopy(cmac, 0, buffer, length, cmac.Length);
                length += cmac.Length;
            }

            public void AppendCmacSend(ref byte[] buffer, ref int size, int offset, int length)
            {
                byte[] cmac = ComputeCmacSend(BinUtils.Copy(buffer, offset, length));
                Array.ConstrainedCopy(cmac, 0, buffer, offset + length, cmac.Length);
                size += cmac.Length;
            }

            public bool VerifyCmacRecv(byte[] buffer, int size)
            {
                if (size < CmacSize)
                    return false;

                int data_length = size - CmacSize;

                byte[] cmac_calc = ComputeCmacRecv(buffer, data_length);
                byte[] cmac_recv = BinUtils.Copy(buffer, data_length, CmacSize);

                for (int i=0; i< CmacSize; i++)
                    if (cmac_calc[i] != cmac_recv[i])
                        goto failed;

                return true;

            failed:
                logger.debug("CmacCalc   {0}", BinConvert.ToHex(cmac_calc));
                logger.debug("CmacRecv   {0}", BinConvert.ToHex(cmac_recv));
                return false;
            }

            public bool VerifyAndRemoveCmacRecv(byte[] buffer, ref int size)
            {
                if (!VerifyCmacRecv(buffer, size))
                    return false;

                size -= CmacSize;
                return true;
            }
        }
    }
}
