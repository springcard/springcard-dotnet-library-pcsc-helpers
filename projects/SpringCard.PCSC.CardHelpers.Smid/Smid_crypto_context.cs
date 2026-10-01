using SpringCard.LibCs;
using System;
using System.Collections.Generic;
using System.Runtime.Serialization;
using System.Text;

namespace SpringCard.PCSC.CardHelpers
{
    public partial class Smid
    {
        [Serializable]
        public abstract class SmidCryptoContext
        {
            public enum SmidKeyId : byte
            {
                AUTH = 0x01,
                ENK = 0x02,
                CMAC = 0x03,
            }
            protected Smid smid { get; private set; }
            protected ILogger logger { get; private set; }
            protected IRandomGenerator randomGenerator { get; private set; }

            public int KeySize { get; protected set; }
            public int BlockSize { get; private set; }
            public int CmacSize { get; private set; }

            //public byte[] IvSessionDec = new byte[16];
            public ushort SiteCode { get; private set; }
            public byte[] Usi = new byte[HCE_USI_LENGTH];


            /* Serialization */
            public virtual void GetObjectData(SerializationInfo info, StreamingContext context)
            {
                info.AddValue("SiteCode", SiteCode);
                info.AddValue("Usi", Usi);
                info.AddValue("KeySize", KeySize);
                info.AddValue("BlockSize", BlockSize);
                info.AddValue("CmacSize", CmacSize);
            }

            /* Deserialization */
            protected SmidCryptoContext(SerializationInfo info, StreamingContext context)
            {
                SiteCode = (ushort)info.GetValue("SiteCode", typeof(ushort));
                Usi = (byte[])info.GetValue("Usi", typeof(byte[]));
                KeySize = (int)info.GetValue("KeySize", typeof(int));
                BlockSize = (int)info.GetValue("BlockSize", typeof(int));
                CmacSize = (int)info.GetValue("CmacSize", typeof(int));
            }

            protected SmidCryptoContext(Smid smid, ushort SiteCode, byte[] Usi )
            {
                SetCard(smid);
                this.SiteCode = SiteCode;
                Array.Copy(Usi, this.Usi, HCE_USI_LENGTH);
                this.KeySize = 16;
                this.BlockSize = 16;
                this.CmacSize = 16;

            }
            internal void SetCard(Smid smid)
            {
                if (smid == null)
                    throw new ArgumentNullException(nameof(smid), "Smid cannot be null");

                this.smid = smid;

                if (smid.logger == null)
                {
                    this.logger = new Logger(this);
                }
                else if (smid.logger is Logger)
                {
                    this.logger = new Logger(smid.logger as Logger, this);
                }
                else
                {
                    this.logger = smid.logger;
                }

                if (smid.randomGenerator == null)
                {
                    this.randomGenerator = new DefaultRandomGenerator();
                }
                else
                {
                    this.randomGenerator = smid.randomGenerator;
                }
            }
        }
    }
}
