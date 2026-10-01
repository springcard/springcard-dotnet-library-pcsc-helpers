using SpringCard.LibCs;
using System;
using System.Security.Cryptography;


namespace SpringCard.PCSC.CardHelpers
{
    public partial class Desfire
    {
        public long SetConfiguration(byte Option, byte[] Data)
        {
            if (!InSecureSession())
                return LibraryError(DesfireLibraryError.InvalidParameter);
            if ((Data == null) || (Data.Length > 255))
                return LibraryError(DesfireLibraryError.InvalidParameter);

            xfer_length = 0;

            /* Create the info block containing the command code and the key number argument. */
            xfer_buffer[xfer_length++] = (byte)DesfireCommand.SET_CONFIGURATION;
            xfer_buffer[xfer_length++] = Option;

            if (Data != null)
            {
                Array.ConstrainedCopy(Data, 0, xfer_buffer, xfer_length, Data.Length);
                xfer_length += Data.Length;
            }

            if (SessionIsEV2OrGreater())
            {
                /* Cipher the data */
                Xfer_Padd_CipherSend(2);

                /* Add a CMAC */
                return Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
            else if (SessionIsEV1OrGreater())
            {
                /* Add the CRC */
                XferAppendCrc(2);

                /* Cipher the option, the data and the CRC */
                Xfer_Padd_CipherSend(2);
                return Command(0, DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
            else
            {
                return Command(0, DesfireCommandFlag.WANTS_OPERATION_OK);
            }
        }

        /* Option 0x00 */

        public long DisableCommandFormat()
        {
            return SetConfiguration(0x00, new byte[1] { 0x01 });
        }

        public long EnableRandomID()
        {
            return SetConfiguration(0x00, new byte[1] { 0x02 });
        }

        public long EnableRandomID(bool Legacy)
        {
            if (Legacy)
                return SetConfiguration(0x00, new byte[1] { 0x22 });
            else
                return SetConfiguration(0x00, new byte[1] { 0x02 });
        }

        public long SetPCMandatory()
        {
            return this.SetConfiguration(0x00, new byte[1] { 0x04 });
        }

        public long SetAuthVCMandatory()
        {
            return SetConfiguration(0x00, new byte[1] { 0x08 });
        }

        /* Option 0x01 */

        public long SetAppDefaultKey(byte[] KeyValue, byte KeyVersion)
        {
            byte[] buffer = new byte[KeyValue.Length + 1];

            if (buffer.Length > 25)
                return LibraryError(DesfireLibraryError.InvalidParameter);

            Array.Copy(KeyValue, 0, buffer, 0, KeyValue.Length);
            KeyValue[KeyValue.Length] = KeyVersion;

            return SetConfiguration(0x01, buffer);
        }

        /* Option 0x02 */

        public long SetUserATS(byte[] Ats)
        {
            return SetConfiguration(0x02, Ats);
        }

        /* Option 0x03 */

        public long SetUserSAK(byte Sak1, byte Sak2)
        {
            byte[] buffer = new byte[] { Sak1, Sak2 };
            return SetConfiguration(0x03, buffer);
        }

        /* Option 0x04 */

        public long DisableSecureMessagingEV0()
        {
            byte[] buffer = new byte[2] { 0x00, 0x01 };
            return this.SetConfiguration(0x04, buffer);
        }

        public long DisableSecureMessagingEV1()
        {
            byte[] buffer = new byte[2] { 0x00, 0x02 };
            return this.SetConfiguration(0x04, buffer);
        }

        public long DisableChainedWritingEV2()
        {
            byte[] b = new byte[2] { 0x00, 0x04 };
            return SetConfiguration(0x04, b);
        }

        /* Option 0x05 */
        public long SetCapabilityData(byte[] PiccCap)
        {
            return SetConfiguration(0x05, PiccCap);
        }

        public long SetCapabilityData(byte PiccCap12, byte PiccCap25, byte PiccCap26)
        {
            byte[] buffer = new byte[10];

            buffer[0] = 0; /* 79-72 */
            buffer[1] = 0; /* 71-64 */
            buffer[2] = 0; /* 63-56 */
            buffer[3] = PiccCap12; /* 55-48 Cap 1.2 */
            buffer[4] = 0; /* 47-40 */
            buffer[5] = 0; /* 39-32 */
            buffer[6] = 0; /* 31-24 */
            buffer[7] = 0; /* 23-16 */
            buffer[8] = PiccCap25; /* 15-8 Cap 2.5 */
            buffer[9] = PiccCap26; /* 7-0 Cap2.6 */

            return SetCapabilityData(buffer);        
        }

        public long SetCapabilityData(byte VCTID, byte PiccCap12, byte PiccCap22, byte PiccCap25, byte PiccCap26)
        {
            byte[] buffer = new byte[10];

            buffer[0] = 0; /* 79-72 */
            buffer[1] = VCTID; /* VCTID */
            buffer[2] = 0; /* 63-56 */
            buffer[3] = PiccCap12; /* 55-48 Cap 1.2 */
            buffer[4] = 0; /* 47-40 */
            buffer[5] = PiccCap22; /* 39-32 */
            buffer[6] = 0; /* 31-24 */
            buffer[7] = 0; /* 23-16 */
            buffer[8] = PiccCap25; /* 15-8 Cap 2.5 */
            buffer[9] = PiccCap26; /* 7-0 Cap2.6 */

            return SetCapabilityData(buffer);
        }

        /* Option 0x06 */

        private long SetVCIDDOrDFName(byte[] data, byte[] mac = null)
        {
            if ((data == null) || (data.Length > 17))
                return LibraryError(DesfireLibraryError.InvalidParameter);
            if ((mac != null) || (mac.Length != 8))
                return LibraryError(DesfireLibraryError.InvalidParameter);

            if (data.Length == 17)
            {
                if (data[0] != (data.Length - 1))
                    return LibraryError(DesfireLibraryError.InvalidParameter);
                if (mac == null)
                    return SetConfiguration(0x06, data);
                else
                    return SetConfiguration(0x06, BinUtils.Concat(data, mac));
            }
            else
            {
                byte[] buffer = new byte[17];
                buffer[0] = (byte)data.Length;
                Array.ConstrainedCopy(data, 0, buffer, 1, data.Length);
                return SetVCIDDOrDFName(buffer, mac);
            }
        }

        public long SetVCIID(byte[] VCIID)
        {
            return SetVCIDDOrDFName(VCIID);
        }

        public long SetDFName(byte[] DFName)
        {
            return SetVCIDDOrDFName(DFName);
        }

        public long SetDFName(string DFName)
        {
            if (string.IsNullOrEmpty(DFName) || (DFName.Length > 16))
                return LibraryError(DesfireLibraryError.InvalidParameter);
            return SetVCIDDOrDFName(StrUtils.ToBytes(DFName));
        }

        public long SetDFName(byte[] DFName, byte[] mac)
        {
            return SetVCIDDOrDFName(DFName, mac);
        }

        public long SetDFName(string DFName, byte[] mac)
        {
            if (string.IsNullOrEmpty(DFName) || (DFName.Length > 16))
                return LibraryError(DesfireLibraryError.InvalidParameter);
            return SetVCIDDOrDFName(StrUtils.ToBytes(DFName), mac);
        }

        /* Option 0x0C */

        public long SetUserATQA(byte[] AtqA)
        {
            return SetConfiguration(0x0C, AtqA);
        }


        public long SetMaxFrameSize(int size, bool useCid = false)
        {
            if ((size < 64) || (size % 64 != 0))
                return LibraryError(DesfireLibraryError.InvalidParameter);

            MaxFrameSize = size;
            FrameUseCid = useCid;
            return Success;
        }

        private int MaxDataInSize
        {
            get
            {
                int result = MaxFrameSize;
                if (IsoWrapping == DesfireIsoWrapping.Card)
                {
                    /* PCB(1) CLA(1) INS(1) p1(1) p2(1) Lc(1) ... Le(1) EDC(2)*/
                    result -= 10;
                }
                else
                {
                    /* PCB(1) OPCODE(1) ... EDC(2)*/
                    result -= 4;
                }
                if (FrameUseCid)
                    result -= 1;
                return result;
            }
        }
        
        private int MaxIsoDataInSize
        {
            get
            {
                int result = MaxFrameSize - 9;
                if (FrameUseCid)
                    result -= 1;
                return result;
            }
        }




        public long GetConfiguration(out ushort manufacturerData)
        {
            long status;

            manufacturerData = 0;

            xfer_length = 0;
            xfer_buffer[xfer_length++] = (byte)DesfireCommand.GET_CONFIGURATION;

            if (SessionIsEV2OrGreater())
            {
                /* Under active authentication, the command Cmd.GetFileSettings requires CommMode.MAC */
                status = Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
            else
            {
                /* Communicate the info block to the card and check the operation's return status. */
                /* The returned info block must contain 4 bytes, the status code and the requested */
                /* information.                                                                    */
                status = Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
            if (status != Success)
                return status;

            // TODO decrypt

            return Success;
        }

        public long GetConfiguration(byte option, out byte[] data)
        {
            long status;

            data = null;

            xfer_length = 0;
            xfer_buffer[xfer_length++] = (byte)DesfireCommand.GET_CONFIGURATION;
            xfer_buffer[xfer_length++] = option;

            if (SessionIsEV2OrGreater())
            {
                /* Under active authentication, the command Cmd.GetFileSettings requires CommMode.MAC */
                status = Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.APPEND_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
            else
            {
                /* Communicate the info block to the card and check the operation's return status. */
                /* The returned info block must contain 4 bytes, the status code and the requested */
                /* information.                                                                    */
                status = Command(0, DesfireCommandFlag.COMPUTE_COMMAND_CMAC | DesfireCommandFlag.CHECK_RESPONSE_CMAC | DesfireCommandFlag.WANTS_OPERATION_OK);
            }
            if (status != Success)
                return status;

            // TODO decrypt

            return Success;
        }
    }
}
