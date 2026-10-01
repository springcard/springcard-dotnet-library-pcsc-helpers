/*
 * Created by SharpDevelop.
 * User: Jerome Izaac
 * Date: 07/09/2017
 * Time: 16:45
 * 
 * To change this template use Tools | Options | Coding | Edit Standard Headers.
 */
using System;
using System.Net;
using SpringCard.LibCs;
using SpringCard.PCSC;
using SpringCard.PCSC.CardHelpers;

namespace SpringCard.PCSC.SelfTest
{
    class Program
    {
        public static void Usage()
        {
            Console.WriteLine("TestMifareDuoX.exe [options], where options are:");
            Console.WriteLine("\t -l: list available PC/SC couplers");
            Console.WriteLine("\t -r X: perform actions on PC/SC coupler X");
        }

        public static void Main(string[] args)
        {
            bool got_something = false;

            Logger.ReadArgs(args);

            Console.WriteLine("Doing self tests");

            if (!Desfire.VerifyPCSelfTest())
            {
                Logger.Error("VerifyPCSelfTest failed");
                return;
            }


            /* -------- 
            byte[] text = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
            //byte[] key = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
            byte[] key= {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            byte[] res = Crypto.TripleDES_Decrypt(text, key, iv);
            foreach (byte b in res)
              Console.Write(String.Format("{0:x02}", b));
            Console.Write("\n");


            return;

            -------- */


            for (int i = 0; i < args.Length; i++)
            {
                if (args[i].Equals("-l"))
                {
                    got_something = true;
                    for (int j = 0; j < SCARD.Readers.Length; j++)
                        Console.WriteLine("Reader 0: " + SCARD.Readers[j]);
                }
                if (args[i].Equals("-r") && ((i + 1) < args.Length))
                {
                    int index_reader;
                    got_something = true;

                    if (!Int32.TryParse(args[i + 1], out index_reader))
                    {
                        Console.WriteLine("Invalid argument");
                        Usage();
                    }
                    else
                    {
                        if (index_reader < SCARD.Readers.Length)
                        {
                            Console.WriteLine("Using reader {0}", SCARD.Readers[index_reader]);
                            if (!DESFireTest(SCARD.Readers[index_reader]))
                                Console.WriteLine("Test failed!");
                            else
                                Console.WriteLine("Test OK!");
                        }
                        else
                        {
                            Console.WriteLine("Specified PC/SC coupler doesn't exist");
                        }

                    }
                }
            }

            if (!got_something)
                Usage();
        }

        static readonly byte[] BlankKey_16 = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        static readonly byte[] TestKey0_16 = { 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8 };
        static readonly byte[] TestKey1A_16 = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
        static readonly byte[] TestKey1B_16 = { 13, 46, 79, 64, 31, 64, 97, 64, 17, 28, 39, 28, 17, 78, 54, 12 };

        static readonly byte[] BlankKey_32 = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        static readonly byte[] TestKey0_32 = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
        static readonly byte[] TestKey1A_32 = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
        static readonly byte[] TestKey1B_32 = { 13, 46, 79, 64, 31, 64, 97, 64, 17, 28, 39, 28, 17, 78, 54, 12, 13, 46, 79, 64, 31, 64, 97, 64, 17, 28, 39, 28, 17, 78, 54, 12 };

        static readonly byte[] ProximityKey_16 = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 };

        public static bool PrepareTest(Desfire desfire)
        {
            if (!MasterAuthentication(desfire))
                return false;
            if (!FormatPicc(desfire))
                return false;
            if (!MasterAuthentication(desfire))
                return false;
            return true;
        }
        public static bool MasterAuthentication(Desfire desfire)
        {
            const uint AID = 0;
            long rc;

            rc = desfire.SelectApplication(AID);
            if (rc != 0)
            {
                Console.WriteLine("SelectApplication({1:X06}) error {0} ({0:X})", rc, AID);
                return false;
            }

            rc = desfire.AuthenticateEv2First(0, BlankKey_16);
            if (rc == 0)
            {
                Console.WriteLine("Authenticate EV2 AES, blank key, OK");
                return true;
            }

            Console.WriteLine("Authenticate EV2 AES, blank key, err. {0} {0:X08}", rc);

            return false;
        }

        public static bool FormatPicc(Desfire desfire)
        {
            long rc = desfire.FormatPICC();
            if (rc != 0)
            {
                Console.WriteLine("FormatPICC error {0} ({0:X})", rc);
                return false;
            }

            return true;
        }

        public static bool ProximityCheck(Desfire desfire, int splitCount)
        {
            long rc;

            Console.WriteLine("PreparePC");

            rc = desfire.PreparePC(out byte bOption, out ushort wPubRespTime, out byte bPPS1);
            if (rc != 0)
            {
                Console.WriteLine("PreparePC error {0} ({0:X})", rc);
                return false;
            }

            Console.WriteLine("Option={0}", bOption);
            Console.WriteLine("PubRespTime={0}", wPubRespTime);
            Console.WriteLine("PPS1={0}", bPPS1);

            Console.WriteLine("ProximityCheck, split count={0}", splitCount);

            rc = desfire.ProximityCheck(splitCount, (75 * wPubRespTime) / 100, (105 * wPubRespTime) / 100);

            if (rc != 0)
            {
                Console.WriteLine("ProximityCheck error {0} ({0:X})", rc);
                return false;
            }

            Console.WriteLine("VerifyPC");

            rc = desfire.VerifyPC(ProximityKey_16);

            if (rc != 0)
            {
                Console.WriteLine("VerifyPC error {0} ({0:X})", rc);
                return false;
            }

            return true;
        }

        public static bool Benchmark(Desfire desfire, int count)
        {
            const int SIZE = 2048;
            const uint AID = 0xAAAAAA;
            const byte FID = 0x1;

            long rc = desfire.CreateApplication(AID, 0xFF, 0x00);
            if (rc != 0)
            {
                Console.WriteLine("CreateApplication({1:X06}) error {0} ({0:X})", rc, AID);
                return false;
            }

            rc = desfire.SelectApplication(AID);
            if (rc != 0)
            {
                Console.WriteLine("SelectApplication({1:X06}) error {0} ({0:X})", rc, AID);
                return false;
            }

            rc = desfire.CreateStdDataFile(FID, 0x0, 0xEEEE, SIZE);
            if (rc != 0)
            {
                Console.WriteLine("CreateStdDataFile({1:X}, {2}) error {0} ({0:X})", rc, FID, SIZE);
                return false;
            }

            DefaultRandomGenerator rng = new DefaultRandomGenerator();

            for (int i = 0; i < count; i++)
            {
                byte[] in_buffer = rng.Get(SIZE);

                rc = desfire.WriteData(FID, Desfire.DF_COMM_MODE_PLAIN, 0, in_buffer.Length, in_buffer);
                if (rc != 0)
                {
                    Console.WriteLine("WriteData({1:X}, {2}) error {0} ({0:X})", rc, FID, SIZE);
                    return false;
                }

                rc = desfire.ReadData(FID, Desfire.DF_COMM_MODE_PLAIN, 0, SIZE, out byte[] out_buffer);
                if (rc != 0)
                {
                    Console.WriteLine("ReadData({1:X}, {2}) error {0} ({0:X})", rc, FID, SIZE);
                    return false;
                }

                if (out_buffer == null)
                {
                    Console.WriteLine("ReadData({0:X}, {1}) returned an empty buffer", FID, SIZE);
                    return false;
                }
                else if (out_buffer.Length != SIZE)
                {
                    Console.WriteLine("ReadData({0:X}, {1}) returned a wrong length ({2} instead of {3})", FID, SIZE, out_buffer.Length, SIZE);
                    return false;
                }

                for (int j = 0; j < SIZE; j++)
                {
                    if (out_buffer[j] != in_buffer[j])
                    {
                        Console.WriteLine("ReadData/WriteData({0:X}, {1}) returned a wrong value at offset {2}", FID, SIZE, j);
                        Console.WriteLine("{0}", BinConvert.ToHex(in_buffer));
                        Console.WriteLine("{0}", BinConvert.ToHex(out_buffer));
                        return false;
                    }
                }
            }

            return true;
        }

        public static bool IsCardDesfire(Desfire desfire)
        {
            long rc = desfire.GetVersion(out Desfire.DF_VERSION_INFO VersionInfo);
            if (rc != Desfire.DF_OPERATION_OK)
            {
                Console.WriteLine("Desfire.GetVersion error {0} {0:X08}", rc);
                return false;
            }

            Console.WriteLine("HwVendorID={0:X02}", VersionInfo.bHwVendorID);
            Console.WriteLine("HwType={0:X02}.{1:X02}", VersionInfo.bHwType, VersionInfo.bHwSubType);
            Console.WriteLine("HwVersion={0:X02}.{1:X02}", VersionInfo.bHwMajorVersion, VersionInfo.bHwMinorVersion);
            Console.WriteLine("HwStorageSize={0:X02}", VersionInfo.bHwStorageSize);
            Console.WriteLine("HwProtocol={0:X02}", VersionInfo.bHwProtocol);

            Console.WriteLine("SwVendorID={0:X02}", VersionInfo.bSwVendorID);
            Console.WriteLine("SwType={0:X02}.{1:X02}", VersionInfo.bSwType, VersionInfo.bSwSubType);
            Console.WriteLine("SwVersion={0:X02}.{1:X02}", VersionInfo.bSwMajorVersion, VersionInfo.bSwMinorVersion);
            Console.WriteLine("SwStorageSize={0:X02}", VersionInfo.bSwStorageSize);
            Console.WriteLine("SwProtocol={0:X02}", VersionInfo.bSwProtocol);

            Console.WriteLine("UID={0}", BinConvert.ToHex(VersionInfo.abUid));

            Console.WriteLine("BatchNo={0}", BinConvert.ToHex(VersionInfo.abBatchNo));

            Console.WriteLine("Production={0}.{1:D03}", VersionInfo.bProductionYear, VersionInfo.bProductionCW);

            if ((VersionInfo.bHwVendorID == 0x04) && (VersionInfo.bSwVendorID == 0x04))
                return true;

            return false;
        }

        public static bool DESFireTest(string readerName)
        {
            SCardReader cardReader = new SCardReader(readerName);
            SCardChannel cardChannel = new SCardChannel(readerName);
            if (!cardChannel.Connect())
            {
                Console.WriteLine("Can't connect to target Card");
                return false;
            }

            Desfire desfire = new Desfire(cardChannel);
            desfire.SetLogger(new Logger());
            desfire.IsoWrapping(Desfire.DF_ISO_WRAPPING_CARD);

            if (!IsCardDesfire(desfire))
            {
                return false;
            }

            Console.WriteLine("Preparing the card for EV2 Test (AES128)");
            if (!PrepareTest(desfire))
            {
                return false;
            }

            Console.WriteLine("EV2 Test (AES128)");
            if (!EV2AES128Test(desfire))
            {
                return false;
            }
            Console.WriteLine("EV2 Test (AES128) OK");

            Console.WriteLine("Preparing the card for EV2 Test (AES256)");
            if (!PrepareTest(desfire))
            {
                return false;
            }

            Console.WriteLine("EV2 Test (AES256)");
            if (!EV2AES256Test(desfire))
            {
                return false;
            }
            Console.WriteLine("EV2 Test (AES256) OK");

            Console.WriteLine("Preparing the card for Benchmark");
            if (!PrepareTest(desfire))
            {
                return false;
            }

            Console.WriteLine("Running the benchmark");
            if (!Benchmark(desfire, 1))
            {
                return false;
            }
            Console.WriteLine("Benchmark OK");

            Console.WriteLine("Testing Proximity Check");
            for (int i = 0; i < 3; i++)
            {
                if (!ProximityCheck(desfire, 1 << i))
                    return false;
            }
            Console.WriteLine("Proximity Check OK");

            return true;
        }


        public static bool EV2AES128Test(Desfire desfire)
        {
            long rc;

            Console.WriteLine("-------------- CREATE APPLICATION -------------");
            rc = desfire.CreateApplication(1, 0x0F, 0x82);
            if (rc == 0)
            {
                Console.WriteLine("CreateApplication ok");
            }
            else
            {
                Console.WriteLine("CreateApplication ko - rc = " + rc);
                return false;
            }

            Console.WriteLine("-------------- SELECT APPLICATION -------------");
            rc = desfire.SelectApplication(1);
            if (rc == 0)
            {
                Console.WriteLine("SelectApplication ok");
            }
            else
            {
                Console.WriteLine("SelectApplication ko - rc = " + rc);
                return false;
            }

            Console.WriteLine("-------------- AUTHENTICATE ON APPLICATION -------------");
            rc = desfire.AuthenticateEv2First(0, BlankKey_16);
            if (rc == 0)
            {
                Console.WriteLine("AuthenticateEv2First ok");
            }
            else
            {
                Console.WriteLine("AuthenticateEv2First ko - rc = " + rc);
                return false;
            }

            rc = desfire.AuthenticateEv2NonFirst(0, BlankKey_16);
            if (rc == 0)
            {
                Console.WriteLine("AuthenticateEv2NonFirst ok");
            }
            else
            {
                Console.WriteLine("AuthenticateEv2NonFirst ko - rc = " + rc);
                return false;
            }

            rc = desfire.AuthenticateEv2First(0, BlankKey_16);
            if (rc == 0)
            {
                Console.WriteLine("AuthenticateEv2First ok");
            }
            else
            {
                Console.WriteLine("AuthenticateEv2First ko - rc = " + rc);
                return false;
            }

            rc = desfire.GetFreeMemory(out uint freeMem);
            if (rc == 0)
            {
                Console.WriteLine("GetFreeMemory ok");
            }
            else
            {
                Console.WriteLine("GetFreeMemory ko - rc = " + rc);
                return false;
            }

            rc = desfire.GetFreeMemory(out freeMem);
            if (rc == 0)
            {
                Console.WriteLine("GetFreeMemory ok");
            }
            else
            {
                Console.WriteLine("GetFreeMemory ko - rc = " + rc);
                return false;
            }

            rc = desfire.GetFreeMemory(out freeMem);
            if (rc == 0)
            {
                Console.WriteLine("GetFreeMemory ok");
            }
            else
            {
                Console.WriteLine("GetFreeMemory ko - rc = " + rc);
                return false;
            }


            Console.WriteLine("-------------- CHANGE KEY  0 -------------");

            rc = desfire.ChangeKeyAes(0, 0, TestKey0_16, null);
            if (rc == 0)
            {
                Console.WriteLine("ChangeKeyAes ok");
            }
            else
            {
                Console.WriteLine("ChangeKeyAes ko - rc = " + rc);
                return false;
            }

            Console.WriteLine("-------------- AUTHENTICATE WITH NEW KEY 0 -------------");
            rc = desfire.AuthenticateEv2First(0, TestKey0_16);
            if (rc == 0)
            {
                Console.WriteLine("AuthenticateEv2First ok");
            }
            else
            {
                Console.WriteLine("AuthenticateEv2First ko - rc = " + rc);
                return false;
            }

            Console.WriteLine("-------------- CHANGE KEY 1 -------------");
            rc = desfire.ChangeKeyAes(1, 0, TestKey1A_16, BlankKey_16);
            if (rc == 0)
            {
                Console.WriteLine("ChangeKeyAes ok");
            }
            else
            {
                Console.WriteLine("ChangeKeyAes ko - rc = " + rc);
                return false;
            }

            Console.WriteLine("-------------- AUTHENTICATE WITH KEY 1 -------------");
            rc = desfire.AuthenticateEv2First(1, TestKey1A_16);
            if (rc == 0)
            {
                Console.WriteLine("AuthenticateEv2First ok");
            }
            else
            {
                Console.WriteLine("AuthenticateEv2First ko - rc = " + rc);
                return false;
            }

            /*----------------------------------*/
            Console.WriteLine("-------------- AUTHENTICATE WITH NEW KEY 0 -------------");
            rc = desfire.AuthenticateEv2First(0, TestKey0_16);
            if (rc == 0)
            {
                Console.WriteLine("AuthenticateEv2First ok");
            }
            else
            {
                Console.WriteLine("AuthenticateEv2First ko - rc = " + rc);
                return false;
            }

            Console.WriteLine("-------------- CHANGE KEY 1 -------------");
            rc = desfire.ChangeKeyAes(1, 1, TestKey1B_16, TestKey1A_16);
            if (rc == 0)
            {
                Console.WriteLine("ChangeKeyAes ok");
            }
            else
            {
                Console.WriteLine("ChangeKeyAes ko - rc = " + rc);
                return false;
            }

            Console.WriteLine("-------------- AUTHENTICATE WITH KEY 1 -------------");
            rc = desfire.AuthenticateEv2First(1, TestKey1B_16);
            if (rc == 0)
            {
                Console.WriteLine("AuthenticateEv2First ok");
            }
            else
            {
                Console.WriteLine("AuthenticateEv2First ko - rc = " + rc);
                return false;
            }

            Console.WriteLine("-------------- AUTHENTICATE WITH NEW KEY 0 -------------");
            rc = desfire.AuthenticateEv2First(0, TestKey0_16);
            if (rc == 0)
            {
                Console.WriteLine("AuthenticateEv2First ok");
            }
            else
            {
                Console.WriteLine("AuthenticateEv2First ko - rc = " + rc);
                return false;
            }

            byte comm_mode = 3;

            Console.WriteLine("-------------- CREATE STD DATA FILE -------------");
            rc = desfire.CreateStdDataFile(1, comm_mode, 0x1000, 20);
            if (rc == 0)
            {
                Console.WriteLine("CreateStdDataFile ok");
            }
            else
            {
                Console.WriteLine("CreateStdDataFile ko - rc = " + rc);
                return false;
            }

            Console.WriteLine("-------------- READ DATA -------------");
            byte[] read = new byte[20];
            int done_count = read.Length;
            rc = desfire.ReadData(1, comm_mode, 0, 10, ref read, ref done_count);
            if (rc == 0)
            {
                Console.Write("ReadData ok, read: ");
                for (int k = 0; k < done_count; k++)
                    Console.Write(String.Format("{0:x02}", read[k]));
                Console.Write("\n");
            }
            else
            {
                Console.WriteLine("ReadData ko - rc = " + rc);
                return false;
            }

            Console.WriteLine("-------------- WRITE DATA -------------");
            byte[] data = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
            rc = desfire.WriteData(1, comm_mode, 0, 10, data);
            if (rc == 0)
            {
                Console.WriteLine("WriteData ok");
            }
            else
            {
                Console.WriteLine("WriteData ko - rc = " + rc);
                return false;
            }

            Console.WriteLine("-------------- AUTHENTICATE WITH KEY 1 -------------");
            rc = desfire.AuthenticateEv2First(1, TestKey1B_16);
            if (rc == 0)
            {
                Console.WriteLine("AuthenticateEv2First ok");
            }
            else
            {
                Console.WriteLine("AuthenticateEv2First ko - rc = " + rc);
                return false;
            }

            Console.WriteLine("-------------- READ DATA -------------");
            read = new byte[20];
            done_count = read.Length;
            rc = desfire.ReadData(1, comm_mode, 0, 10, ref read, ref done_count);
            if (rc == 0)
            {
                Console.Write("ReadData ok, read: ");
                for (int k = 0; k < done_count; k++)
                    Console.Write(String.Format("{0:x02}", read[k]));
                Console.Write("\n");
            }
            else
            {
                Console.WriteLine("ReadData ko - rc = " + rc);
                return false;
            }

            Console.WriteLine("-------------- CREATE RECORD FILE -------------");
            rc = desfire.CreateCyclicRecordFile(2, comm_mode, 0x1110, 10, 5);
            if (rc == 0)
            {
                Console.WriteLine("CreateCyclicRecordFile ok");
            }
            else
            {
                Console.WriteLine("CreateCyclicRecordFile ko - rc = " + rc);
                return false;
            }

            Console.WriteLine("-------------- WRITE RECORD 1  -------------");
            byte[] rec_to_write1 = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa };
            rc = desfire.WriteRecord(2, comm_mode, 0, 10, rec_to_write1);
            if (rc == 0)
            {
                Console.WriteLine("WriteRecord 1 ok");
            }
            else
            {
                Console.WriteLine("WriteRecord 1 ko - rc = " + rc);
                return false;
            }

            Console.WriteLine("-------------- COMMIT TRANSACTIONS -------------\n");
            rc = desfire.CommitTransaction();
            if (rc == 0)
            {
                Console.WriteLine("CommitTransaction ok");
            }
            else
            {
                Console.WriteLine("CommitTransaction ko - rc = " + rc);
                return false;
            }

            Console.WriteLine("-------------- WRITE RECORD 2  -------------");
            byte[] rec_to_write2 = { 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 };
            rc = desfire.WriteRecord(2, comm_mode, 0, 10, rec_to_write2);
            if (rc == 0)
            {
                Console.WriteLine("WriteRecord 2 ok");
            }
            else
            {
                Console.WriteLine("WriteRecord 2 ko - rc = " + rc);
                return false;
            }

            Console.WriteLine("-------------- GET FILES SETTINGS  -------------");
            byte file_type;
            byte comm_mode_read;
            ushort acces_rights;
            Desfire.DF_FILE_SETTINGS file_settings;
            rc = desfire.GetFileSettings(2, out file_type, out comm_mode_read, out acces_rights, out file_settings);
            if (rc == 0)
            {
                Console.WriteLine("GetFileSettings ok");
                Console.WriteLine("\tfile_type=" + file_type);
                Console.WriteLine("\tcomm_mode_read=" + comm_mode_read);
                Console.WriteLine("\tacces_rights=0x" + String.Format("{0:x04}", acces_rights));
                if (file_type == Desfire.DF_CYCLIC_RECORD_FILE)
                {
                    Console.WriteLine("\t\teRecordSize=" + file_settings.RecordFile.eRecordSize);
                    Console.WriteLine("\t\teMaxNRecords=" + file_settings.RecordFile.eMaxNRecords);
                    Console.WriteLine("\t\teCurrNRecords=" + file_settings.RecordFile.eCurrNRecords);
                }

            }
            else
            {
                Console.WriteLine("GetFileSettings ko - rc = " + rc);
                return false;
            }

            Console.WriteLine("-------------- COMMIT TRANSACTIONS -------------\n");
            rc = desfire.CommitTransaction();
            if (rc == 0)
            {
                Console.WriteLine("CommitTransaction ok");
            }
            else
            {
                Console.WriteLine("CommitTransaction ko - rc = " + rc);
                return false;
            }

            Console.WriteLine("-------------- GET FILES SETTINGS  -------------");
            rc = desfire.GetFileSettings(2, out file_type, out comm_mode_read, out acces_rights, out file_settings);
            if (rc == 0)
            {
                Console.WriteLine("GetFileSettings ok");
                Console.WriteLine("\tfile_type=" + file_type);
                Console.WriteLine("\tcomm_mode_read=" + comm_mode_read);
                Console.WriteLine("\tacces_rights=0x" + String.Format("{0:x04}", acces_rights));
                if (file_type == Desfire.DF_CYCLIC_RECORD_FILE)
                {
                    Console.WriteLine("\t\teRecordSize=" + file_settings.RecordFile.eRecordSize);
                    Console.WriteLine("\t\teMaxNRecords=" + file_settings.RecordFile.eMaxNRecords);
                    Console.WriteLine("\t\teCurrNRecords=" + file_settings.RecordFile.eCurrNRecords);
                }

            }
            else
            {
                Console.WriteLine("GetFileSettings ko - rc = " + rc);
                return false;
            }

            Console.WriteLine("-------------- AUTHENTICATE WITH KEY 1 -------------");
            rc = desfire.AuthenticateEv2First(1, TestKey1B_16);
            if (rc == 0)
            {
                Console.WriteLine("AuthenticateEv2First ok");
            }
            else
            {
                Console.WriteLine("AuthenticateEv2First ko - rc = " + rc);
                return false;
            }


            Console.WriteLine("-------------- READ RECORDS  -------------");
            byte[] rec_to_read = new byte[50];
            int record_count = 1;
            rc = desfire.ReadRecords(2, comm_mode, 0, 0, 10, ref rec_to_read, ref record_count);
            if (rc == 0)
            {
                Console.Write("ReadRecords ok, read: \n\t");
                for (int k = 0; k < record_count; k++)
                {
                    for (int l = 0; l < 10; l++)
                        Console.Write(String.Format("{0:x02}", rec_to_read[k * 10 + l]));
                    Console.Write("\n\t");
                }
                Console.Write("\n");

            }
            else
            {
                Console.WriteLine("ReadRecords ko - rc = " + rc);
                return false;
            }

            Console.WriteLine("-------------- AUTHENTICATE WITH NEW KEY 0 -------------");
            rc = desfire.AuthenticateEv2First(0, TestKey0_16);
            if (rc == 0)
            {
                Console.WriteLine("AuthenticateEv2First ok");
            }
            else
            {
                Console.WriteLine("AuthenticateEv2First ko - rc = " + rc);
                return false;
            }

            Console.WriteLine("-------------- CHANGE FILE SETTINGS  -------------");
            rc = desfire.ChangeFileSettings(2, 3, 0x0010);
            if (rc == 0)
            {
                Console.WriteLine("ChangeFileSettings ok");
            }
            else
            {
                Console.WriteLine("ChangeFileSettings ko - rc = " + rc);
                return false;
            }

            Console.WriteLine("-------------- AUTHENTICATE WITH KEY 1 -------------");
            rc = desfire.AuthenticateEv2First(1, TestKey1B_16);
            if (rc == 0)
            {
                Console.WriteLine("AuthenticateEv2First ok");
            }
            else
            {
                Console.WriteLine("AuthenticateEv2First ko - rc = " + rc);
                return false;
            }

            Console.WriteLine("-------------- READ RECORDS  -------------");
            rec_to_read = new byte[50];
            record_count = 1;
            rc = desfire.ReadRecords(2, comm_mode, 0, 0, 10, ref rec_to_read, ref record_count);
            if (rc == 0)
            {
                Console.Write("ReadRecords ok, read: \n\t");
                for (int k = 0; k < record_count; k++)
                {
                    for (int l = 0; l < 10; l++)
                        Console.Write(String.Format("{0:x02}", rec_to_read[k * 10 + l]));
                    Console.Write("\n\t");
                }
                Console.Write("\n");

            }
            else
            {
                Console.WriteLine("ReadRecords ko - rc = " + rc);
                return false;
            }

            Console.WriteLine("-------------- AUTHENTICATE WITH NEW KEY 0 -------------");
            rc = desfire.AuthenticateEv2First(0, TestKey0_16);
            if (rc == 0)
            {
                Console.WriteLine("AuthenticateEv2First ok");
            }
            else
            {
                Console.WriteLine("AuthenticateEv2First ko - rc = " + rc);
                return false;
            }


            Console.WriteLine("-------------- READ RECORDS  -------------");
            rec_to_read = new byte[50];
            record_count = 1;
            rc = desfire.ReadRecords(2, comm_mode, 0, 0, 10, ref rec_to_read, ref record_count);
            if (rc == 0)
            {
                Console.Write("ReadRecords ok, read: \n\t");
                for (int k = 0; k < record_count; k++)
                {
                    for (int l = 0; l < 10; l++)
                        Console.Write(String.Format("{0:x02}", rec_to_read[k * 10 + l]));
                    Console.Write("\n\t");
                }
                Console.Write("\n");

            }
            else
            {
                Console.WriteLine("ReadRecords ko - rc = " + rc);
                return false;
            }


            Console.WriteLine("-------------- CHANGE KEY SETTINGS -------------");
            rc = desfire.ChangeKeySettings(0x0f);
            if (rc == 0)
            {
                Console.WriteLine("ChangeKeySettings ok");
            }
            else
            {
                Console.WriteLine("ChangeKeySettings ko - rc = " + rc);
                return false;
            }

            return true;
        }

        public static bool EV2AES256Test(Desfire desfire)
        {
            {
                long rc;

                Console.WriteLine("-------------- CREATE APPLICATION -------------");
                rc = desfire.CreateApplication(1, 0x0F, 0xC2);
                if (rc == 0)
                {
                    Console.WriteLine("CreateApplication ok");
                }
                else
                {
                    Console.WriteLine("CreateApplication ko - rc = " + rc);
                    return false;
                }

                Console.WriteLine("-------------- SELECT APPLICATION -------------");
                rc = desfire.SelectApplication(1);
                if (rc == 0)
                {
                    Console.WriteLine("SelectApplication ok");
                }
                else
                {
                    Console.WriteLine("SelectApplication ko - rc = " + rc);
                    return false;
                }

                Console.WriteLine("-------------- AUTHENTICATE ON APPLICATION -------------");
                rc = desfire.AuthenticateEv2First(0, BlankKey_32);
                if (rc == 0)
                {
                    Console.WriteLine("AuthenticateEv2First ok");
                }
                else
                {
                    Console.WriteLine("AuthenticateEv2First ko - rc = " + rc);
                    return false;
                }

                rc = desfire.AuthenticateEv2NonFirst(0, BlankKey_32);
                if (rc == 0)
                {
                    Console.WriteLine("AuthenticateEv2NonFirst ok");
                }
                else
                {
                    Console.WriteLine("AuthenticateEv2NonFirst ko - rc = " + rc);
                    return false;
                }

                rc = desfire.AuthenticateEv2First(0, BlankKey_32);
                if (rc == 0)
                {
                    Console.WriteLine("AuthenticateEv2First ok");
                }
                else
                {
                    Console.WriteLine("AuthenticateEv2First ko - rc = " + rc);
                    return false;
                }

                rc = desfire.GetFreeMemory(out uint freeMem);
                if (rc == 0)
                {
                    Console.WriteLine("GetFreeMemory ok");
                }
                else
                {
                    Console.WriteLine("GetFreeMemory ko - rc = " + rc);
                    return false;
                }

                rc = desfire.GetFreeMemory(out freeMem);
                if (rc == 0)
                {
                    Console.WriteLine("GetFreeMemory ok");
                }
                else
                {
                    Console.WriteLine("GetFreeMemory ko - rc = " + rc);
                    return false;
                }

                rc = desfire.GetFreeMemory(out freeMem);
                if (rc == 0)
                {
                    Console.WriteLine("GetFreeMemory ok");
                }
                else
                {
                    Console.WriteLine("GetFreeMemory ko - rc = " + rc);
                    return false;
                }

                Console.WriteLine("-------------- CHANGE KEY  0 -------------");

                rc = desfire.ChangeKeyAes(0, 0, TestKey0_32, null);
                if (rc == 0)
                {
                    Console.WriteLine("ChangeKeyAes ok");
                }
                else
                {
                    Console.WriteLine("ChangeKeyAes ko - rc = " + rc);
                    return false;
                }

                Console.WriteLine("-------------- AUTHENTICATE WITH NEW KEY 0 -------------");
                rc = desfire.AuthenticateEv2First(0, TestKey0_32);
                if (rc == 0)
                {
                    Console.WriteLine("AuthenticateEv2First ok");
                }
                else
                {
                    Console.WriteLine("AuthenticateEv2First ko - rc = " + rc);
                    return false;
                }

                Console.WriteLine("-------------- CHANGE KEY 1 -------------");
                rc = desfire.ChangeKeyAes(1, 0, TestKey1A_32, BlankKey_32);
                if (rc == 0)
                {
                    Console.WriteLine("ChangeKeyAes ok");
                }
                else
                {
                    Console.WriteLine("ChangeKeyAes ko - rc = " + rc);
                    return false;
                }

                Console.WriteLine("-------------- AUTHENTICATE WITH KEY 1 -------------");
                rc = desfire.AuthenticateEv2First(1, TestKey1A_32);
                if (rc == 0)
                {
                    Console.WriteLine("AuthenticateEv2First ok");
                }
                else
                {
                    Console.WriteLine("AuthenticateEv2First ko - rc = " + rc);
                    return false;
                }

                /*----------------------------------*/
                Console.WriteLine("-------------- AUTHENTICATE WITH NEW KEY 0 -------------");
                rc = desfire.AuthenticateEv2First(0, TestKey0_32);
                if (rc == 0)
                {
                    Console.WriteLine("AuthenticateEv2First ok");
                }
                else
                {
                    Console.WriteLine("AuthenticateEv2First ko - rc = " + rc);
                    return false;
                }

                Console.WriteLine("-------------- CHANGE KEY 1 -------------");
                rc = desfire.ChangeKeyAes(1, 1, TestKey1B_32, TestKey1A_32);
                if (rc == 0)
                {
                    Console.WriteLine("ChangeKeyAes ok");
                }
                else
                {
                    Console.WriteLine("ChangeKeyAes ko - rc = " + rc);
                    return false;
                }

                Console.WriteLine("-------------- AUTHENTICATE WITH KEY 1 -------------");
                rc = desfire.AuthenticateEv2First(1, TestKey1B_32);
                if (rc == 0)
                {
                    Console.WriteLine("AuthenticateEv2First ok");
                }
                else
                {
                    Console.WriteLine("AuthenticateEv2First ko - rc = " + rc);
                    return false;
                }

                Console.WriteLine("-------------- AUTHENTICATE WITH NEW KEY 0 -------------");
                rc = desfire.AuthenticateEv2First(0, TestKey0_32);
                if (rc == 0)
                {
                    Console.WriteLine("AuthenticateEv2First ok");
                }
                else
                {
                    Console.WriteLine("AuthenticateEv2First ko - rc = " + rc);
                    return false;
                }

                byte comm_mode = 3;

                Console.WriteLine("-------------- CREATE STD DATA FILE -------------");
                rc = desfire.CreateStdDataFile(1, comm_mode, 0x1000, 20);
                if (rc == 0)
                {
                    Console.WriteLine("CreateStdDataFile ok");
                }
                else
                {
                    Console.WriteLine("CreateStdDataFile ko - rc = " + rc);
                    return false;
                }

                Console.WriteLine("-------------- READ DATA -------------");
                byte[] read = new byte[5];
                int done_count = read.Length;
                rc = desfire.ReadData(1, comm_mode, 0, 5, ref read, ref done_count);
                if (rc == 0)
                {
                    Console.Write("ReadData ok, read: ");
                    for (int k = 0; k < done_count; k++)
                        Console.Write(String.Format("{0:x02}", read[k]));
                    Console.Write("\n");
                }
                else
                {
                    Console.WriteLine("ReadData ko - rc = " + rc);
                    return false;
                }

                Console.WriteLine("-------------- READ DATA -------------");
                read = new byte[20];
                done_count = read.Length;
                rc = desfire.ReadData(1, comm_mode, 0, 10, ref read, ref done_count);
                if (rc == 0)
                {
                    Console.Write("ReadData ok, read: ");
                    for (int k = 0; k < done_count; k++)
                        Console.Write(String.Format("{0:x02}", read[k]));
                    Console.Write("\n");
                }
                else
                {
                    Console.WriteLine("ReadData ko - rc = " + rc);
                    return false;
                }

                Console.WriteLine("-------------- WRITE DATA -------------");
                byte[] data = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
                rc = desfire.WriteData(1, comm_mode, 0, 10, data);
                if (rc == 0)
                {
                    Console.WriteLine("WriteData ok");
                }
                else
                {
                    Console.WriteLine("WriteData ko - rc = " + rc);
                    return false;
                }

                Console.WriteLine("-------------- AUTHENTICATE WITH KEY 1 -------------");
                rc = desfire.AuthenticateEv2First(1, TestKey1B_32);
                if (rc == 0)
                {
                    Console.WriteLine("AuthenticateEv2First ok");
                }
                else
                {
                    Console.WriteLine("AuthenticateEv2First ko - rc = " + rc);
                    return false;
                }

                Console.WriteLine("-------------- READ DATA -------------");
                read = new byte[20];
                done_count = read.Length;
                rc = desfire.ReadData(1, comm_mode, 0, 10, ref read, ref done_count);
                if (rc == 0)
                {
                    Console.Write("ReadData ok, read: ");
                    for (int k = 0; k < done_count; k++)
                        Console.Write(String.Format("{0:x02}", read[k]));
                    Console.Write("\n");
                }
                else
                {
                    Console.WriteLine("ReadData ko - rc = " + rc);
                    return false;
                }

                Console.WriteLine("-------------- CREATE RECORD FILE -------------");
                rc = desfire.CreateCyclicRecordFile(2, comm_mode, 0x1110, 10, 5);
                if (rc == 0)
                {
                    Console.WriteLine("CreateCyclicRecordFile ok");
                }
                else
                {
                    Console.WriteLine("CreateCyclicRecordFile ko - rc = " + rc);
                    return false;
                }

                Console.WriteLine("-------------- WRITE RECORD 1  -------------");
                byte[] rec_to_write1 = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa };
                rc = desfire.WriteRecord(2, comm_mode, 0, 10, rec_to_write1);
                if (rc == 0)
                {
                    Console.WriteLine("WriteRecord 1 ok");
                }
                else
                {
                    Console.WriteLine("WriteRecord 1 ko - rc = " + rc);
                    return false;
                }

                Console.WriteLine("-------------- COMMIT TRANSACTIONS -------------\n");
                rc = desfire.CommitTransaction();
                if (rc == 0)
                {
                    Console.WriteLine("CommitTransaction ok");
                }
                else
                {
                    Console.WriteLine("CommitTransaction ko - rc = " + rc);
                    return false;
                }

                Console.WriteLine("-------------- WRITE RECORD 2  -------------");
                byte[] rec_to_write2 = { 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 };
                rc = desfire.WriteRecord(2, comm_mode, 0, 10, rec_to_write2);
                if (rc == 0)
                {
                    Console.WriteLine("WriteRecord 2 ok");
                }
                else
                {
                    Console.WriteLine("WriteRecord 2 ko - rc = " + rc);
                    return false;
                }

                Console.WriteLine("-------------- GET FILES SETTINGS  -------------");
                byte file_type;
                byte comm_mode_read;
                ushort acces_rights;
                Desfire.DF_FILE_SETTINGS file_settings;
                rc = desfire.GetFileSettings(2, out file_type, out comm_mode_read, out acces_rights, out file_settings);
                if (rc == 0)
                {
                    Console.WriteLine("GetFileSettings ok");
                    Console.WriteLine("\tfile_type=" + file_type);
                    Console.WriteLine("\tcomm_mode_read=" + comm_mode_read);
                    Console.WriteLine("\tacces_rights=0x" + String.Format("{0:x04}", acces_rights));
                    if (file_type == Desfire.DF_CYCLIC_RECORD_FILE)
                    {
                        Console.WriteLine("\t\teRecordSize=" + file_settings.RecordFile.eRecordSize);
                        Console.WriteLine("\t\teMaxNRecords=" + file_settings.RecordFile.eMaxNRecords);
                        Console.WriteLine("\t\teCurrNRecords=" + file_settings.RecordFile.eCurrNRecords);
                    }

                }
                else
                {
                    Console.WriteLine("GetFileSettings ko - rc = " + rc);
                    return false;
                }

                Console.WriteLine("-------------- COMMIT TRANSACTIONS -------------\n");
                rc = desfire.CommitTransaction();
                if (rc == 0)
                {
                    Console.WriteLine("CommitTransaction ok");
                }
                else
                {
                    Console.WriteLine("CommitTransaction ko - rc = " + rc);
                    return false;
                }

                Console.WriteLine("-------------- GET FILES SETTINGS  -------------");
                rc = desfire.GetFileSettings(2, out file_type, out comm_mode_read, out acces_rights, out file_settings);
                if (rc == 0)
                {
                    Console.WriteLine("GetFileSettings ok");
                    Console.WriteLine("\tfile_type=" + file_type);
                    Console.WriteLine("\tcomm_mode_read=" + comm_mode_read);
                    Console.WriteLine("\tacces_rights=0x" + String.Format("{0:x04}", acces_rights));
                    if (file_type == Desfire.DF_CYCLIC_RECORD_FILE)
                    {
                        Console.WriteLine("\t\teRecordSize=" + file_settings.RecordFile.eRecordSize);
                        Console.WriteLine("\t\teMaxNRecords=" + file_settings.RecordFile.eMaxNRecords);
                        Console.WriteLine("\t\teCurrNRecords=" + file_settings.RecordFile.eCurrNRecords);
                    }

                }
                else
                {
                    Console.WriteLine("GetFileSettings ko - rc = " + rc);
                    return false;
                }

                Console.WriteLine("-------------- AUTHENTICATE WITH KEY 1 -------------");
                rc = desfire.AuthenticateEv2First(1, TestKey1B_32);
                if (rc == 0)
                {
                    Console.WriteLine("AuthenticateEv2First ok");
                }
                else
                {
                    Console.WriteLine("AuthenticateEv2First ko - rc = " + rc);
                    return false;
                }


                Console.WriteLine("-------------- READ RECORDS  -------------");
                byte[] rec_to_read = new byte[50];
                int record_count = 1;
                rc = desfire.ReadRecords(2, comm_mode, 0, 0, 10, ref rec_to_read, ref record_count);
                if (rc == 0)
                {
                    Console.Write("ReadRecords ok, read: \n\t");
                    for (int k = 0; k < record_count; k++)
                    {
                        for (int l = 0; l < 10; l++)
                            Console.Write(String.Format("{0:x02}", rec_to_read[k * 10 + l]));
                        Console.Write("\n\t");
                    }
                    Console.Write("\n");

                }
                else
                {
                    Console.WriteLine("ReadRecords ko - rc = " + rc);
                    return false;
                }

                Console.WriteLine("-------------- AUTHENTICATE WITH NEW KEY 0 -------------");
                rc = desfire.AuthenticateEv2First(0, TestKey0_32);
                if (rc == 0)
                {
                    Console.WriteLine("AuthenticateEv2First ok");
                }
                else
                {
                    Console.WriteLine("AuthenticateEv2First ko - rc = " + rc);
                    return false;
                }

                Console.WriteLine("-------------- CHANGE FILE SETTINGS  -------------");
                rc = desfire.ChangeFileSettings(2, 3, 0x0010);
                if (rc == 0)
                {
                    Console.WriteLine("ChangeFileSettings ok");
                }
                else
                {
                    Console.WriteLine("ChangeFileSettings ko - rc = " + rc);
                    return false;
                }

                Console.WriteLine("-------------- AUTHENTICATE WITH KEY 1 -------------");
                rc = desfire.AuthenticateEv2First(1, TestKey1B_32);
                if (rc == 0)
                {
                    Console.WriteLine("AuthenticateEv2First ok");
                }
                else
                {
                    Console.WriteLine("AuthenticateEv2First ko - rc = " + rc);
                    return false;
                }

                Console.WriteLine("-------------- READ RECORDS  -------------");
                rec_to_read = new byte[50];
                record_count = 1;
                rc = desfire.ReadRecords(2, comm_mode, 0, 0, 10, ref rec_to_read, ref record_count);
                if (rc == 0)
                {
                    Console.Write("ReadRecords ok, read: \n\t");
                    for (int k = 0; k < record_count; k++)
                    {
                        for (int l = 0; l < 10; l++)
                            Console.Write(String.Format("{0:x02}", rec_to_read[k * 10 + l]));
                        Console.Write("\n\t");
                    }
                    Console.Write("\n");

                }
                else
                {
                    Console.WriteLine("ReadRecords ko - rc = " + rc);
                    return false;
                }

                Console.WriteLine("-------------- AUTHENTICATE WITH NEW KEY 0 -------------");
                rc = desfire.AuthenticateEv2First(0, TestKey0_32);
                if (rc == 0)
                {
                    Console.WriteLine("AuthenticateEv2First ok");
                }
                else
                {
                    Console.WriteLine("AuthenticateEv2First ko - rc = " + rc);
                    return false;
                }


                Console.WriteLine("-------------- READ RECORDS  -------------");
                rec_to_read = new byte[50];
                record_count = 1;
                rc = desfire.ReadRecords(2, comm_mode, 0, 0, 10, ref rec_to_read, ref record_count);
                if (rc == 0)
                {
                    Console.Write("ReadRecords ok, read: \n\t");
                    for (int k = 0; k < record_count; k++)
                    {
                        for (int l = 0; l < 10; l++)
                            Console.Write(String.Format("{0:x02}", rec_to_read[k * 10 + l]));
                        Console.Write("\n\t");
                    }
                    Console.Write("\n");

                }
                else
                {
                    Console.WriteLine("ReadRecords ko - rc = " + rc);
                    return false;
                }


                Console.WriteLine("-------------- CHANGE KEY SETTINGS -------------");
                rc = desfire.ChangeKeySettings(0x0f);
                if (rc == 0)
                {
                    Console.WriteLine("ChangeKeySettings ok");
                }
                else
                {
                    Console.WriteLine("ChangeKeySettings ko - rc = " + rc);
                    return false;
                }

                return true;
            }
            /*
            Desfire.AuthenticateIso         - DES ok    - NA
            Desfire.AuthenticateAes         - NA        - AES ok
            Desfire.ChangeKeySettings       - DES ok    - AES ok
            Desfire.ChangeKey               - DES ok    - AES ok
            Desfire.ChangeKeyAes            - DES ok    - AES ok
            Desfire.FormatPICC              - DES ok
            Desfire.CreateApplication       - DES ok
            Desfire.DeleteApplication       - DES ok
            Desfire.SelectApplication       - DES ok
            Desfire.ChangeFileSettings      - DES ok    - AES ok
            Desfire.CreateStdDataFile       - DES ok    - AES ok
            Desfire.CreateCyclicRecordFile  - DES ok    - AES ok
            Desfire.ReadData                - DES ok    - AES ok
            Desfire.WriteData               - DES ok    - AES ok
            Desfire.ReadRecords             - DES ok    - AES ok
            */
        }

    }
}