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
using System.Threading;
using Org.BouncyCastle.Utilities;
using SpringCard.LibCs;
using SpringCard.PCSC;
using SpringCard.PCSC.CardHelpers;

namespace SpringCard.PCSC.SelfTest
{
    partial class Program
    {
        readonly byte[] NullKey_24 = new byte[24];

        readonly byte[] RootKey1K = StrUtils.ToBytes("ABCDEFGHABCDEFGH");
        readonly byte[] RootKey2K = StrUtils.ToBytes("Card Master Key!");

        readonly byte[] RootKey1K_24 = StrUtils.ToBytes("ABCDEFGHABCDEFGHABCDEFGH");
        readonly byte[] RootKey2K_24 = StrUtils.ToBytes("Card Master Key!Card Mas");

        // readonly byte[] abRootKey3K = StrUtils.ToBytes("Card Master Key!        ");

        readonly byte[] TestKeyDes1K_16 = StrUtils.ToBytes("ABCDEFGHABCDEFGH");
        readonly byte[] TestKeyDes2K_16 = StrUtils.ToBytes("ABCDEFGHIJKLMNOP");

        readonly byte[] TestKeyDes1K_24 = StrUtils.ToBytes("ABCDEFGHABCDEFGHABCDEFGH");
        readonly byte[] TestKeyDes2K_24 = StrUtils.ToBytes("ABCDEFGHIJKLMNOPABCDEFGH");

        // readonly byte[] abTestKeyDes3K = StrUtils.ToBytes("ABCDEFGHIJKLMNOPQRSTUVWX");

        readonly byte[] AppBKeyMaster0_16 = StrUtils.ToBytes("App.B Master Key");
        readonly byte[] AppBKeyMaster1_16 = StrUtils.ToBytes("@qq/C!L`ruds!Kdx");
        readonly byte[] AppBChangeKey_16 = StrUtils.ToBytes("B's Chg Keys Key");

        readonly byte[] appBKeyMaster0_24 = StrUtils.ToBytes("App.B Master KeyApp. Key");
        readonly byte[] appBKeyMaster1_24 = StrUtils.ToBytes("@qq/C!L`ruds!Kdx@qq/!Kdx");
        readonly byte[] appBChangeKey_24 = StrUtils.ToBytes("B's Chg Keys KeyB's  Key");

        readonly byte[] AppBKey1_16 = StrUtils.ToBytes("App.B Key #1.   ");
        readonly byte[] AppBKey2_16 = StrUtils.ToBytes("App.B Key #2..  ");
        readonly byte[] AppBKey3_16 = StrUtils.ToBytes("App.B Key #3... ");
        readonly byte[] AppBKey4_16 = StrUtils.ToBytes("App.B Key #4....");

        readonly byte[] AppBKey1_24 = StrUtils.ToBytes("App.B Key #1.   .   .   ");
        readonly byte[] AppBKey2_24 = StrUtils.ToBytes("App.B Key #2..  ..  ..  ");
        readonly byte[] AppBKey3_24 = StrUtils.ToBytes("App.B Key #3... ... ... ");
        readonly byte[] AppBKey4_24 = StrUtils.ToBytes("App.B Key #4............");

        readonly byte[] AppCKey1_16 = StrUtils.ToBytes("App.C Key #1.   ");
        readonly byte[] AppCKey2_16 = StrUtils.ToBytes("App.C Key #2..  ");

        readonly byte[] AppCKey1_24 = StrUtils.ToBytes("App.C Key #1.   .   .   ");
        readonly byte[] AppCKey2_24 = StrUtils.ToBytes("App.C Key #2..  ..  ..  ");


        public enum DesfireEV1TestMode
        {
            Legacy,
            TDes2k,
            TDes3k,
            Aes
        }

        public void TestDesfireEV1(DesfireEV1 card, DesfireEV1TestMode iTestMode)
        {
            long rc;
            long lAmount;
            byte bCommMode, bKeyVersion;
            int eNRecordsRead;
            byte bFileType;
            byte bKeySettings, bKeyCount;
            uint[] adwApplicationList;
            byte[] abFileList;
            byte[] abDataBuffer;
            byte[] abCardUid;
            uint dwFreeBytes;
            ushort wAccessRights;
            int iTransaction, iFileIndex;
            bool fEv0OrLower = false;
            bool fEv2OrGreater = false;

            Desfire.DesfireFileSettings unFileSettings;

            //  After activating a DesFire card the currently selected 'application' is the card
            //  iTestMode (AID = 0). Therefore the next command is redundant.
            //  We use the command to check that the card is responding correctly.
            rc = card.SelectApplication(0);
            Check(rc);

            rc = card.GetFreeMemory(out dwFreeBytes);
            if (Desfire.IsCardError(rc) && (Desfire.GetCardError(rc) == Desfire.DesfireCardError.IllegalCommandCode))
            {
                Logger.Info("This is a Desfire EV0, not EV1");
                fEv0OrLower = true;
            }
            else
            {
                Check(rc);
            }

            rc = card.GetVersion(out Desfire.DesfireVersionInfo stVersionInfo);
            Check(rc);

            if (!quiet)
            {
                Console.WriteLine();
                Console.WriteLine("HwVendorID={0:X02}", stVersionInfo.HwVendorID);
                Console.WriteLine("HwType={0:X02}", stVersionInfo.HwType);
                Console.WriteLine("HwSubType={0:X02}", stVersionInfo.HwSubType);
                Console.WriteLine("HwMajorVersion={0:X02}", stVersionInfo.HwMajorVersion);
                Console.WriteLine("HwMinorVersion={0:X02}", stVersionInfo.HwMinorVersion);
                Console.WriteLine("HwStorageSize={0:X02}", stVersionInfo.HwStorageSize);
                Console.WriteLine("HwProtocol={0:X02}", stVersionInfo.HwProtocol);
                Console.WriteLine("SwVendorID={0:X02}", stVersionInfo.SwVendorID);
                Console.WriteLine("SwType={0:X02}", stVersionInfo.SwType);
                Console.WriteLine("SwSubType={0:X02}", stVersionInfo.SwSubType);
                Console.WriteLine("SwMajorVersion={0:X02}", stVersionInfo.SwMajorVersion);
                Console.WriteLine("SwMinorVersion={0:X02}", stVersionInfo.SwMinorVersion);
                Console.WriteLine("SwStorageSize={0:X02}", stVersionInfo.SwStorageSize);
                Console.WriteLine("SwProtocol={0:X02}", stVersionInfo.SwProtocol);
                Console.WriteLine("Uid={0:X02}:{1:X02}:{2:X02}:{3:X02}:{4:X02}:{5:X02}:{6:X02}", stVersionInfo.Uid[0], stVersionInfo.Uid[1], stVersionInfo.Uid[2], stVersionInfo.Uid[3], stVersionInfo.Uid[4], stVersionInfo.Uid[5], stVersionInfo.Uid[6]);
                Console.WriteLine("BatchNo={0:X02}:{1:X02}:{2:X02}:{3:X02}:{4:X02}", stVersionInfo.BatchNo[0], stVersionInfo.BatchNo[1], stVersionInfo.BatchNo[2], stVersionInfo.BatchNo[3], stVersionInfo.BatchNo[4]);
                Console.WriteLine("ProductionCW={0:X02}", stVersionInfo.ProductionCW);
                Console.WriteLine("ProductionYear={0:X02}", stVersionInfo.ProductionYear);
            }

            if (stVersionInfo.SwMajorVersion > 1)
                fEv2OrGreater = true;

            //  Which Card Master Key is currently in use ?
            //  Beginning with DesFire version 0.1 the GetKeyVersion command can help determining
            //  which key is currently effective.
            rc = card.GetKeyVersion(0, out bKeyVersion);
            Check(rc);

            //  Authenticate with the key which corresponds to the retieved key version.
            if (bKeyVersion == 0)
            {
                rc = card.Authenticate(0, NullKey_16);
                if (Desfire.IsCardError(rc) && (Desfire.GetCardError(rc) == Desfire.DesfireCardError.AuthenticationError))
                {
                    rc = card.AuthenticateEV1TDes(0, NullKey_16);
                    Check(rc);

                    //  Restore open key settings
                    rc = card.ChangeKeySettings(0xF);
                    Check(rc);

                    //  The key is configured for 3DES3K
                    //  obviously we cannot revert the config to 3DES2K, but a hook by AES permits it
                    rc = card.ChangeKey((byte) (Desfire.DesfireKeyType.AES128 | 0), 0xAE, RootKey2K, null);
                    Check(rc);
                    rc = card.AuthenticateEV1Aes(0, RootKey2K);
                }
                Check(rc);


            }
            else if (bKeyVersion == 0xAA)
            {
                rc = card.Authenticate(0, RootKey1K);
                if (Desfire.IsCardError(rc) && (Desfire.GetCardError(rc) == Desfire.DesfireCardError.AuthenticationError))
                {
                    rc = card.AuthenticateEV1TDes(0, RootKey1K);
                    Check(rc);

                    //  Restore open key settings
                    rc = card.ChangeKeySettings(0xF);
                    Check(rc);

                    //  The key is configured for 3DES3K
                    //  obviously we cannot revert the config to 3DES2K, but a hook by AES permits it
                    rc = card.ChangeKey((byte)Desfire.DesfireKeyType.AES128 | 0, 0xAE, RootKey2K, null);
                    Check(rc);
                    rc = card.AuthenticateEV1Aes(0, RootKey2K);
                }
                Check(rc);

            }
            else if (bKeyVersion == 0xC7)
            {
                rc = card.Authenticate(0, RootKey2K);
                if (Desfire.IsCardError(rc) && (Desfire.GetCardError(rc) == Desfire.DesfireCardError.AuthenticationError))
                {
                    rc = card.AuthenticateEV1TDes(0, RootKey2K);
                    Check(rc);

                    //  Restore open key settings
                    rc = card.ChangeKeySettings(0xF);
                    Check(rc);

                    //  The key is configured for 3DES3K
                    //  obviously we cannot revert the config to 3DES2K, but a hook by AES permits it
                    rc = card.ChangeKey((byte)Desfire.DesfireKeyType.AES128 | 0, 0xAE, RootKey2K, null);
                    Check(rc);
                    rc = card.AuthenticateEV1Aes(0, RootKey2K);
                }
                Check(rc);

            }
            else if (bKeyVersion == 0xAE)
            {
                rc = card.AuthenticateEV1Aes(0, RootKey2K);
                Check(rc);
            }
            else
            {
                //  Who knows the key ?
                Console.WriteLine("Sorry, the master key is unknown (version = {0:X02})", bKeyVersion);
                return;
            }

            if (bKeyVersion != 0)
            {
                //  Back to default (null) key
                rc = card.ChangeKey(0, NullKey_16, null);
                Check(rc);
            }

            //  Authenticate again
            rc = card.Authenticate(0, NullKey_16);
            Check(rc);

            if (doChangeMasterKey)
            {
                //  Try to allow to change the key
                rc = card.ChangeKeySettings(0xF);
                Check(rc);
            }

            //  List the existing applications
            rc = card.GetApplicationIDs(out adwApplicationList);
            Check(rc);

            if (adwApplicationList.Length > 0)
            {
                //  Startup with a blank card !!!
                rc = card.FormatPICC();
                Check(rc);
            }

            //  Authenticate again
            rc = card.Authenticate(0, NullKey_16);
            Check(rc);

            // Get the UID of the card
            if (!fEv0OrLower)
            {
                rc = card.GetCardUID(out abCardUid);
                Check(rc);
                Console.WriteLine();
                Console.WriteLine("UID: {0}", BinConvert.ToHex(abCardUid));
            }

            if (doChangeMasterKey)
            {
                //  Change the Card master key to a SingleDES key.
                rc = card.ChangeKey(0, RootKey1K, null);
                Check(rc);

                rc = card.GetKeyVersion(0, out bKeyVersion);
                Check(rc);

                if (iTestMode == DesfireEV1TestMode.Legacy)
                {
                    rc = card.Authenticate(0, RootKey1K);
                    Check(rc);
                    rc = card.ChangeKey(0, RootKey2K, null);
                    Check(rc);
                }
                else if (iTestMode == DesfireEV1TestMode.TDes2k)
                {
                    rc = card.AuthenticateEV1TDes(0, RootKey1K);
                    Check(rc);
                    rc = card.ChangeKey(0, RootKey2K, null);
                    Check(rc);
                }
                else if (iTestMode == DesfireEV1TestMode.TDes3k)
                {
                    rc = card.AuthenticateEV1TDes(0, RootKey1K_24);
                    Check(rc);
                    rc = card.ChangeKey((byte)Desfire.DesfireKeyType.TDES3K | 0, RootKey2K_24, null);
                    Check(rc);
                }
                else if (iTestMode == DesfireEV1TestMode.Aes)
                {
                    rc = card.AuthenticateEV1TDes(0, RootKey1K);
                    Check(rc);
                    rc = card.ChangeKey((byte)Desfire.DesfireKeyType.AES128 | 0, 0xAE, RootKey2K, null);
                    Check(rc);
                }
            }

            /*
            // Reconfigure the card
            {
                BYTE b = 0x02;
                //BYTE ats[] = { 0x06, 0x75, 0x77, 0x81, 0x02, 0xFF };
                //rc = desfire.SetConfiguration(0x02, ats, sizeof(ats));
                rc = desfire.SetConfiguration(0x00, ref b, 1);
                Check(rc);
            }
            */

            if (!fEv0OrLower)
            {
                rc = card.GetFreeMemory(out dwFreeBytes);
                Check(rc);
            }

            rc = card.GetKeyVersion(0, out bKeyVersion);
            Check(rc);
            rc = card.GetKeyVersion(0, out bKeyVersion);
            Check(rc);

            if (doChangeMasterKey)
            {
                if (iTestMode == DesfireEV1TestMode.Legacy)
                {
                    rc = card.Authenticate(0, RootKey2K);
                    Check(rc);
                }
                else if (iTestMode == DesfireEV1TestMode.TDes2k)
                {
                    rc = card.AuthenticateEV1TDes(0, RootKey2K);
                    Check(rc);
                }
                else if (iTestMode == DesfireEV1TestMode.TDes3k)
                {
                    rc = card.AuthenticateEV1TDes(0, RootKey2K_24);
                    Check(rc);
                }
                else if (iTestMode == DesfireEV1TestMode.Aes)
                {
                    rc = card.AuthenticateEV1Aes(0, RootKey2K);
                    Check(rc);
                }
            }

            rc = card.GetKeySettings(out bKeySettings, out bKeyCount);
            Check(rc);

            if (!fEv0OrLower)
            {
                rc = card.GetFreeMemory(out dwFreeBytes);
                Check(rc);
            }

            //  At this point we would like to begin with a blank card.
            rc = card.FormatPICC();
            Check(rc);

            if (!fEv0OrLower)
            {
                rc = card.GetFreeMemory(out dwFreeBytes);
                Check(rc);
            }

            //  Create three applications:

            //  Application A is the most open one.
            //  It has no keys and its key settings are least restrictive.
            //  Note: since there are no keys, the Change Keys key settting must be assigned
            //        the value 0xE or 0xF.
            if (iTestMode == DesfireEV1TestMode.Legacy)
            {
                rc = card.CreateApplication(0xAAAAAA, 0xFF, 0);
                Check(rc);
            }
            else if (iTestMode == DesfireEV1TestMode.TDes2k)
            {
                rc = card.CreateApplication(0xAAAAAA, 0xFF, 0);
                Check(rc);
            }
            else if (iTestMode == DesfireEV1TestMode.TDes3k)
            {
                rc = card.CreateApplication(0xAAAAAA, 0xFF, (byte)Desfire.DesfireKeyType.TDES3K | 0);
                Check(rc);
            }
            else if (iTestMode == DesfireEV1TestMode.Aes)
            {
                rc = card.CreateApplication(0xAAAAAA, 0xFF, (byte)Desfire.DesfireKeyType.AES128 | 0);
                Check(rc);
            }

            //  Application B's key settings can be changed at a later time.
            //  It has six keys.
            //  Authentication with a given key allows also to change that key.
            //  (the Change Keys key settting is 0xE)
            if (iTestMode == DesfireEV1TestMode.Legacy)
            {
                rc = card.CreateApplication(0xBBBBBB, 0xEF, 6);
                Check(rc);
            }
            else if (iTestMode == DesfireEV1TestMode.TDes2k)
            {
                rc = card.CreateApplication(0xBBBBBB, 0xEF, 6);
                Check(rc);
            }
            else if (iTestMode == DesfireEV1TestMode.TDes3k)
            {
                rc = card.CreateApplication(0xBBBBBB, 0xEF, (byte)Desfire.DesfireKeyType.TDES3K | 6);
                Check(rc);
            }
            else if (iTestMode == DesfireEV1TestMode.Aes)
            {
                rc = card.CreateApplication(0xBBBBBB, 0xEF, (byte)Desfire.DesfireKeyType.AES128 | 6);
                Check(rc);
            }

            //  Application C keeps everything private.
            //  Even getting its file directory is not publicly allowed.
            //  The application has the maximum of 14 keys.
            //  We make key #0xC the Change Keys key.
            if (iTestMode == DesfireEV1TestMode.Legacy)
            {
                rc = card.CreateApplication(0xCCCCCC, 0xC0, 14);
                Check(rc);
            }
            else if (iTestMode == DesfireEV1TestMode.TDes2k)
            {
                rc = card.CreateApplication(0xCCCCCC, 0xC0, 14);
                Check(rc);
            }
            else if (iTestMode == DesfireEV1TestMode.TDes3k)
            {
                rc = card.CreateApplication(0xCCCCCC, 0xC0, (byte)Desfire.DesfireKeyType.TDES3K | 14);
                Check(rc);
            }
            else if (iTestMode == DesfireEV1TestMode.Aes)
            {
                rc = card.CreateApplication(0xCCCCCC, 0xC0, (byte)Desfire.DesfireKeyType.AES128 | 14);
                Check(rc);
            }

            //  Verify that the applications have been created.
            rc = card.GetApplicationIDs(out adwApplicationList);
            Check(rc);

            if (!fEv0OrLower)
            {
                // The ISO DF=2000 application will allow ISO EFs
                rc = card.CreateApplication(0xFF2000, 0xFF, (byte)Desfire.DesfireApplicationSettings.KeySetting2.IsoEFIds, 0x2000, StrUtils.ToBytes("1TIC.ICA"));
                Check(rc);
                rc = card.CreateApplication(0xFF3000, 0xFF, (byte)Desfire.DesfireApplicationSettings.KeySetting2.IsoEFIds, 0x3000, StrUtils.ToBytes("2MPP.EPP"));
                Check(rc);
                rc = card.CreateApplication(0xFF4000, 0xFF, (byte)Desfire.DesfireApplicationSettings.KeySetting2.IsoEFIds, 0x4000, StrUtils.ToBytes("3JDA.JDA"));
                Check(rc);
                if (!fEv2OrGreater)
                {
                    // EV2 does not accept to create a DF with ID=3F00 (ISO MF), but EV1 is OK
                    rc = card.CreateApplication(0xFF3F00, 0xFF, (byte)Desfire.DesfireApplicationSettings.KeySetting2.IsoEFIds, 0x3F00, StrUtils.ToBytes("Test Master File"));
                    Check(rc);
                }

                // More applications
                if (dwFreeBytes > 4096)
                {
                    rc = card.CreateApplication(0xFFFF00, 0xFF, 0);
                    Check(rc);
                    rc = card.CreateApplication(0xFFFF01, 0xFF, 0);
                    Check(rc);
                    rc = card.CreateApplication(0xFFFF02, 0xFF, 0);
                    Check(rc);
                    rc = card.CreateApplication(0xFFFF03, 0xFF, 0);
                    Check(rc);
                    rc = card.CreateApplication(0xFFFF04, 0xFF, 0);
                    Check(rc);
                    rc = card.CreateApplication(0xFFFF05, 0xFF, 0);
                    Check(rc);
                    rc = card.CreateApplication(0xFFFF06, 0xFF, 0);
                    Check(rc);
                    rc = card.CreateApplication(0xFFFF07, 0xFF, 0);
                    Check(rc);
                    rc = card.CreateApplication(0xFFFF08, 0xFF, 0);
                    Check(rc);
                    rc = card.CreateApplication(0xFFFF0A, 0xFF, 0);
                    Check(rc);
                    rc = card.CreateApplication(0xFFFF0B, 0xFF, 0);
                    Check(rc);
                    rc = card.CreateApplication(0xFFFF0C, 0xFF, 0);
                    Check(rc);
                    rc = card.CreateApplication(0xFFFF0D, 0xFF, 0);
                    Check(rc);
                    rc = card.CreateApplication(0xFFFF0E, 0xFF, 0);
                    Check(rc);
                    rc = card.CreateApplication(0xFFFF0F, 0xFF, 0);
                    Check(rc);

                    rc = card.CreateApplication(0xFFFF10, 0xFF, 0);
                    Check(rc);
                    rc = card.CreateApplication(0xFFFF20, 0xFF, 0);
                    Check(rc);
                    rc = card.CreateApplication(0xFFFF30, 0xFF, 0);
                    Check(rc);
                    rc = card.CreateApplication(0xFFFF40, 0xFF, 0);
                    Check(rc);
                    rc = card.CreateApplication(0xFFFF50, 0xFF, 0);
                    Check(rc);
                    rc = card.CreateApplication(0xFFFF60, 0xFF, 0);
                    Check(rc);
                }

                //  Verify that the applications have been created.
                rc = card.GetApplicationIDs(out adwApplicationList);
                Check(rc);

                // Cleanup authentication state
                rc = card.SelectApplication(0);
                Check(rc);

                // Retrieve the list of applications
                rc = card.GetApplicationIDs(out adwApplicationList);
                Check(rc);

                if (!quiet)
                {
                    Console.WriteLine();
                    Console.WriteLine("{0} application(s) found:", adwApplicationList.Length);
                    for (int i = 0; i < adwApplicationList.Length; i++)
                        Console.WriteLine("\t- {0:X06}", adwApplicationList[i]);
                }

                // Retrieve the list of ISO DF
                rc = card.GetDFNames(out Desfire.DesfireIsoApplication[] astIsoApplications);
                Check(rc);

                if (!quiet)
                {
                    Console.WriteLine();
                    Console.WriteLine("{0} ISO application(s) found:", astIsoApplications.Length);
                    for (int i = 0; i < astIsoApplications.Length; i++)
                    {
                        int j;
                        Console.Write("- {0:X06} = ISO {1:X04}  ", astIsoApplications[i].Aid, astIsoApplications[i].IsoId);
                        for (j = 0; j < astIsoApplications[i].IsoName.Length; j++)
                            Console.Write("{0:X02}", astIsoApplications[i].IsoName[j]);
                        for (; j < 16; j++)
                            Console.Write("  ");
                        Console.Write("  ");
                        for (j = 0; j < astIsoApplications[i].IsoName.Length; j++)
                            if (astIsoApplications[i].IsoName[j] >= ' ')
                                Console.Write("{0}", (char) astIsoApplications[i].IsoName[j]);
                            else Console.Write(".");
                        Console.WriteLine();
                    }
                }

                // Create ISO files in ISO application 2000
                rc = card.SelectApplication(0xFF2000);
                Check(rc);

                rc = card.CreateIsoStdDataFile(1, 0x2001, 0, 0xEEEE, 32);
                Check(rc);

                rc = card.CreateIsoBackupDataFile(2, 0x2002, 0, 0xEEEE, 32);
                Check(rc);

                rc = card.CreateIsoLinearRecordFile(3, 0x2003, 0, 0xEEEE, 16, 4);
                Check(rc);

                rc = card.CreateIsoCyclicRecordFile(4, 0x2004, 0, 0xEEEE, 16, 4);
                Check(rc);

                //  Get the file IDs
                rc = card.GetFileIDs(out abFileList);
                Check(rc);

                if (!quiet)
                {
                    Console.WriteLine();
                    Console.WriteLine("{0} file(s) found:", abFileList.Length);
                    for (int i = 0; i < abFileList.Length; i++)
                        Console.WriteLine("\t- {0:X02}", abFileList[i]);
                }

                //  Get the ISO file IDs
                rc = card.GetIsoFileIDs(out ushort[] awIsoFiles);
                Check(rc);

                if (!quiet)
                {
                    Console.WriteLine();
                    Console.WriteLine("{0} ISO file(s) found:", awIsoFiles.Length);
                    for (int i = 0; i < awIsoFiles.Length; i++)
                        Console.WriteLine("\t- {0:X04}", awIsoFiles[i]);
                }
            }

            //  Create the files in application A:
            //  Since the application does not have any keys associated with it, the file access rights
            //  settings 0xE (public access granted) and 0xF (access denied) are the only permissable
            //  ones.
            rc = card.SelectApplication(0xAAAAAA);
            Check(rc);

            //  Create a the Standard Data file.
            rc = card.CreateStdDataFile(15, 0, 0xEEEE, 640);
            Check(rc);

            //  Create a 64 byte Backup file.
            rc = card.CreateBackupDataFile(5, 0, 0xEEEE, 64);
            Check(rc);

            //  Create a Value file allowing values from 0 to 1000.
            //  The initial value is 0.
            //  The Limited Credit feature is disabled.
            rc = card.CreateValueFile(4, 0, 0xEEEE, 0, 1000, 0, false);
            Check(rc);

            //  And finally create a Cyclic Record file capable of holding 10 records of 4 bytes each.
            rc = card.CreateCyclicRecordFile(0, 0, 0xEEEE, 4, 10);
            Check(rc);

            //  Fill the Standard Data file with some data.
            abDataBuffer = new byte[8192];
            for (int i = 0; i < abDataBuffer.Length; i++)
                abDataBuffer[i] = 0xDA;

            rc = card.WriteData(15, (byte)Desfire.DesfireCommMode.Plain, 0, 640, abDataBuffer);
            Check(rc);
            rc = card.WriteData(15, (byte)Desfire.DesfireCommMode.Plain, 0, 30, StrUtils.ToBytes("This is the 1st block written."));
            Check(rc);
            rc = card.WriteData(15, (byte)Desfire.DesfireCommMode.Plain, 34, 22, StrUtils.ToBytes("This is the 2nd block."));
            Check(rc);

            //  Then make the file permanently read-only.
            rc = card.ChangeFileSettings(15, (byte)Desfire.DesfireCommMode.Plain, 0xEFFF);
            Check(rc);

            //  Read part of the file's contents.
            rc = card.ReadData(15, (byte)Desfire.DesfireCommMode.Plain, 10, 50, out abDataBuffer);
            Check(rc);

            //  Get all data in one block. 
            //  Note: Must make sure that buffer is large enough for all data!!
            rc = card.ReadData(15, (byte)Desfire.DesfireCommMode.Plain, 0, 0, out abDataBuffer);
            Check(rc);

            //  Test different lengths
            for (int i = 45; i < 65; i++)
            {
                rc = card.ReadData(15, (byte)Desfire.DesfireCommMode.Plain, 0, i, out abDataBuffer);
                Check(rc);
            }

            //  Try to overwrite the file.
            //  Since we have made the file read-only, this should fail.
            rc = card.WriteData(15, (byte)Desfire.DesfireCommMode.Plain, 20, 5, StrUtils.ToBytes("Essai"));
            Check(rc, Desfire.DesfireCardError.PermissionDenied);

            //  Do 15 transactions.
            for (iTransaction = 0; iTransaction < 15; iTransaction++)
            {
                //  Write to the Backup Data file.
                string strBuffer = string.Format("{0:D02},", iTransaction);
                rc = card.WriteData(5, (byte)Desfire.DesfireCommMode.Plain, 3 * iTransaction, 3, StrUtils.ToBytes(strBuffer));
                Check(rc);

                //  Manipulate the Value file.
                rc = card.Credit(4, (byte)Desfire.DesfireCommMode.Plain, 100);
                Check(rc);
                rc = card.Debit(4, (byte)Desfire.DesfireCommMode.Plain, 93);
                Check(rc);

                //  Write to the Cyclic Record file.
                rc = card.WriteRecord(0, (byte)Desfire.DesfireCommMode.Plain, 2, 2, abDataBuffer);
                Check(rc);
                //  The following Write Record will write to the same record as above
                rc = card.WriteRecord(0, (byte)Desfire.DesfireCommMode.Plain, 0, 2, StrUtils.ToBytes("r."));
                Check(rc);

                //  Verify that the 'official' contents of the three files has not changed
                //  before the CommitTransaction command.
                //  Must make sure that buffer is large enough for all data!
                rc = card.ReadData(5, (byte)Desfire.DesfireCommMode.Plain, 0, 0, out abDataBuffer);
                Check(rc);
                rc = card.GetValue(4, (byte)Desfire.DesfireCommMode.Plain, out lAmount);
                Check(rc);

                //  Note: reading from an empty record file returns an error.
                //        beginning with version 0.1 this aborts the transaction.
                if (iTransaction != 0)
                {
                    rc = card.ReadRecords(0, (byte)Desfire.DesfireCommMode.Plain, 0, 0, 4, out abDataBuffer, out eNRecordsRead);
                    Check(rc);
                }
                //  Declare the transaction valid.
                rc = card.CommitTransaction();
                Check(rc);

                //  Verify that the transaction has become effective.
                //  Note: Must make sure that buffer is large enough for all data!
                rc = card.ReadData(5, (byte)Desfire.DesfireCommMode.Plain, 0, 0, out abDataBuffer);
                Check(rc);
                rc = card.GetValue(4, (byte)Desfire.DesfireCommMode.Plain, out lAmount);
                Check(rc);
                rc = card.ReadRecords(0, (byte)Desfire.DesfireCommMode.Plain, 0, 0, 4, out abDataBuffer, out eNRecordsRead);
                Check(rc);
            }

            //  Limited Credit has been disabled, so the following call should fail.
            rc = card.LimitedCredit2(4, 20);
            Check(rc, Desfire.DesfireCardError.PermissionDenied);

            //  Get the file IDs of the current application.
            rc = card.GetFileIDs(out abFileList);
            Check(rc);

            if (!quiet)
            {
                Console.WriteLine();
                Console.WriteLine("{0} file(s) found:", abFileList.Length);
                for (int i = 0; i < abFileList.Length; i++)
                    Console.WriteLine("\t- {0:X02}", abFileList[i]);
            }

            //  Get information about the application's files.
            //  Delete each file after retrieving information about it.
            for (iFileIndex = 0; iFileIndex < abFileList.Length; iFileIndex++)
            {
                rc = card.GetFileSettings(abFileList[iFileIndex], out bFileType, out bCommMode, out wAccessRights, out unFileSettings);
                Check(rc);
                rc = card.DeleteFile(abFileList[iFileIndex]);
                Check(rc);
            }

            //  Verify that there are no files in the application.
            rc = card.GetFileIDs(out abFileList);
            Check(rc);

            //  Delete application A.
            //  Since this application doesn't have an Application Master Key,
            //  this requires Card Master Key authentication.
            rc = card.SelectApplication(0);
            Check(rc);

            if (doChangeMasterKey)
            {
                if (iTestMode == DesfireEV1TestMode.Legacy)
                {
                    rc = card.Authenticate(0, RootKey2K);
                    Check(rc);
                }
                else if (iTestMode == DesfireEV1TestMode.TDes2k)
                {
                    rc = card.AuthenticateEV1TDes(0, RootKey2K);
                    Check(rc);
                }
                else if (iTestMode == DesfireEV1TestMode.TDes3k)
                {
                    rc = card.AuthenticateEV1TDes(0, RootKey2K_24);
                    Check(rc);
                }
                else if (iTestMode == DesfireEV1TestMode.Aes)
                {
                    rc = card.AuthenticateEV1Aes(0, RootKey2K);
                    Check(rc);
                }
            }
            else
            {
                rc = card.Authenticate(0, NullKey_16);
                Check(rc);
            }

            rc = card.DeleteApplication(0xAAAAAA);
            Check(rc);

            //  Verify that application A has been deleted.
            rc = card.GetApplicationIDs(out adwApplicationList);
            Check(rc);

            //  Changing application B's keys:
            rc = card.SelectApplication(0xBBBBBB);
            Check(rc);

            //  Use a TripleDES key as the Application Master Key.
            if (iTestMode == DesfireEV1TestMode.Legacy)
            {
                rc = card.Authenticate(0, NullKey_16);
                Check(rc);
            }
            else if (iTestMode == DesfireEV1TestMode.TDes2k)
            {
                rc = card.AuthenticateEV1TDes(0, NullKey_16);
                Check(rc);
            }
            else if (iTestMode == DesfireEV1TestMode.TDes3k)
            {
                rc = card.AuthenticateEV1TDes(0, NullKey_24);
                Check(rc);
            }
            else if (iTestMode == DesfireEV1TestMode.Aes)
            {
                rc = card.AuthenticateEV1Aes(0, NullKey_16);
                Check(rc);
            }

            //  Set the new application master key and get authenticated with it

            if (iTestMode == DesfireEV1TestMode.Legacy)
            {
                rc = card.ChangeKey(0, AppBKeyMaster0_16, null);
                Check(rc);
                rc = card.Authenticate(0, AppBKeyMaster0_16);
                Check(rc);
            }
            else if (iTestMode == DesfireEV1TestMode.TDes2k)
            {
                rc = card.ChangeKey(0, AppBKeyMaster0_16, null); // JDA
                Check(rc);
                rc = card.AuthenticateEV1TDes(0, AppBKeyMaster0_16);
                Check(rc);
            }
            else if (iTestMode == DesfireEV1TestMode.TDes3k)
            {
                rc = card.ChangeKey(0, appBKeyMaster0_24, null); // JDA
                Check(rc);
                rc = card.AuthenticateEV1TDes(0, appBKeyMaster0_24);
                Check(rc);
            }
            else if (iTestMode == DesfireEV1TestMode.Aes)
            {
                rc = card.ChangeKey(0, 0, AppBKeyMaster0_16, null); // JDA
                Check(rc);
                rc = card.AuthenticateEV1Aes(0, AppBKeyMaster0_16);
                Check(rc);
            }

            if (!fEv0OrLower)
            {
                rc = card.GetFreeMemory(out dwFreeBytes);
                Check(rc);
                rc = card.GetFreeMemory(out dwFreeBytes);
                Check(rc);
            }

            //  Beginning with DesFire version 0.1 we can query the version number of a key.
            rc = card.GetKeyVersion(0, out bKeyVersion);
            Check(rc);

            //  Authenticate with the new application master key.
            //  This time use the opposite parity in all key bytes (will not work for AES!).
            if (iTestMode == DesfireEV1TestMode.Legacy)
            {
                rc = card.Authenticate(0, AppBKeyMaster1_16);
                Check(rc);
            }
            else if (iTestMode == DesfireEV1TestMode.TDes2k)
            {
                rc = card.AuthenticateEV1TDes(0, AppBKeyMaster1_16);
                Check(rc);
            }
            else if (iTestMode == DesfireEV1TestMode.TDes3k)
            {
                rc = card.AuthenticateEV1TDes(0, appBKeyMaster1_24);
                Check(rc);
            }
            else if (iTestMode == DesfireEV1TestMode.Aes)
            {

            }

            //  Change key #1 to a different SingleDES key (both key halves are the same).
            //  Authentication with that key is necessary for changing it.
            if (iTestMode == DesfireEV1TestMode.Legacy)
            {
                rc = card.Authenticate(1, NullKey_16);
                Check(rc);
                rc = card.ChangeKey(1, TestKeyDes1K_16, null);
                Check(rc);
            }
            else if (iTestMode == DesfireEV1TestMode.TDes2k)
            {
                rc = card.AuthenticateEV1TDes(1, NullKey_16);
                Check(rc);
                rc = card.ChangeKey(1, TestKeyDes1K_16, null);
                Check(rc);
            }
            else if (iTestMode == DesfireEV1TestMode.TDes3k)
            {
                rc = card.AuthenticateEV1TDes(1, NullKey_24);
                Check(rc);
                rc = card.ChangeKey(1, TestKeyDes1K_24, null);
                Check(rc);
            }
            else if (iTestMode == DesfireEV1TestMode.Aes)
            {
                rc = card.AuthenticateEV1Aes(1, NullKey_16);
                Check(rc);
                rc = card.ChangeKey(1, 0x33, TestKeyDes1K_16, null);
                Check(rc);
            }

            //  Change key #5 to a TripeDES key.
            //  Authentication with that key is necessary for changing it.
            if (iTestMode == DesfireEV1TestMode.Legacy)
            {
                rc = card.Authenticate(5, NullKey_16);
                Check(rc);
                rc = card.ChangeKey(5, AppBChangeKey_16, null);
                Check(rc);
            }
            else if (iTestMode == DesfireEV1TestMode.TDes2k)
            {
                rc = card.AuthenticateEV1TDes(5, NullKey_16);
                Check(rc);
                rc = card.ChangeKey(5, AppBChangeKey_16, null);
                Check(rc);
            }
            else if (iTestMode == DesfireEV1TestMode.TDes3k)
            {
                rc = card.AuthenticateEV1TDes(5, NullKey_24);
                Check(rc);
                rc = card.ChangeKey(5, appBChangeKey_24, null);
                Check(rc);
            }
            else if (iTestMode == DesfireEV1TestMode.Aes)
            {
                rc = card.AuthenticateEV1Aes(5, NullKey_16);
                Check(rc);
                rc = card.ChangeKey(5, 0x77, AppBChangeKey_16, null);
                Check(rc);
            }

            //  Get authenticated again with appl's Master key
            if (iTestMode == DesfireEV1TestMode.Legacy)
            {
                rc = card.Authenticate(0, AppBKeyMaster0_16);
                Check(rc);
            }
            else if (iTestMode == DesfireEV1TestMode.TDes2k)
            {
                rc = card.AuthenticateEV1TDes(0, AppBKeyMaster0_16);
                Check(rc);
            }
            else if (iTestMode == DesfireEV1TestMode.TDes3k)
            {
                rc = card.AuthenticateEV1TDes(0, appBKeyMaster0_24);
                Check(rc);
            }
            else if (iTestMode == DesfireEV1TestMode.Aes)
            {
                rc = card.AuthenticateEV1Aes(0, AppBKeyMaster0_16);
                Check(rc);
            }

            if (!fEv0OrLower)
            {
                rc = card.GetFreeMemory(out dwFreeBytes);
                Check(rc);
                rc = card.GetFreeMemory(out dwFreeBytes);
                Check(rc);
            }

            //  Make key #5 the Change Keys Key.
            rc = card.ChangeKeySettings(0x5F);
            Check(rc);

            //  Verify the new key settings.
            rc = card.GetKeySettings(out bKeySettings, out bKeyCount);
            Check(rc);

            //  Change keys #1 through #4 using the three key procedure.
            //  Authentication with the Change Keys Key is now necessary for changing ordinary keys.
            if (iTestMode == DesfireEV1TestMode.Legacy)
            {
                rc = card.Authenticate(5, AppBChangeKey_16);
                Check(rc);
                rc = card.ChangeKey(1, AppBKey1_16, TestKeyDes1K_16);
                Check(rc);
                rc = card.ChangeKey(2, AppBKey2_16, NullKey_16);
                Check(rc);
                rc = card.ChangeKey(3, AppBKey3_16, NullKey_16);
                Check(rc);
                rc = card.ChangeKey(4, AppBKey4_16, NullKey_16);
                Check(rc);
            }
            else if (iTestMode == DesfireEV1TestMode.TDes2k)
            {
                rc = card.AuthenticateEV1TDes(5, AppBChangeKey_16);
                Check(rc);
                rc = card.ChangeKey(1, AppBKey1_16, TestKeyDes1K_16);
                Check(rc);
                rc = card.ChangeKey(2, AppBKey2_16, NullKey_16);
                Check(rc);
                rc = card.ChangeKey(3, AppBKey3_16, NullKey_16);
                Check(rc);
                rc = card.ChangeKey(4, AppBKey4_16, NullKey_16);
                Check(rc);
            }
            else if (iTestMode == DesfireEV1TestMode.TDes3k)
            {
                rc = card.AuthenticateEV1TDes(5, appBChangeKey_24);
                Check(rc);
                rc = card.ChangeKey(1, AppBKey1_24, TestKeyDes1K_24);
                Check(rc);
                rc = card.ChangeKey(2, AppBKey2_24, NullKey_24);
                Check(rc);
                rc = card.ChangeKey(3, AppBKey3_24, NullKey_24);
                Check(rc);
                rc = card.ChangeKey(4, AppBKey4_24, NullKey_24);
                Check(rc);
            }
            else if (iTestMode == DesfireEV1TestMode.Aes)
            {
                rc = card.AuthenticateEV1Aes(5, AppBChangeKey_16);
                Check(rc);
                rc = card.ChangeKey(1, 0x33, AppBKey1_16, TestKeyDes1K_16);
                Check(rc);
                rc = card.ChangeKey(2, 0x55, AppBKey2_16, NullKey_16);
                Check(rc);
                rc = card.ChangeKey(3, 0x33, AppBKey3_16, NullKey_16);
                Check(rc);
                rc = card.ChangeKey(4, 0x55, AppBKey4_16, NullKey_16);
                Check(rc);
            }

            //  For demonstrating the three possible communication modes we create an instance
            //  of each basic file type:
            //  a Data file:  Read = 1, Write = 2, ReadWrite = 3, ChangeConfig = 4
            //  a Value file: Debit = 1, LimitedCredit = 3, Credit = 2, ChangeConfig = 4
            //  and a Linear Record file: Read = 1, Write = 3, ReadWrite = 2, ChangeConfig = 4
            //  Note: Must make sure that buffer is large enough for all data!
            rc = card.CreateStdDataFile(14, 0, 0x1234, 100);
            Check(rc);
            rc = card.CreateValueFile(4, 0, 0x1324, -987654321, -1000, -1000000, true);
            Check(rc);
            rc = card.CreateLinearRecordFile(1, 0, 0x1324, 25, 4);
            Check(rc);

            if (!fEv0OrLower)
            {
                rc = card.GetFreeMemory(out dwFreeBytes);
                Check(rc);
            }

            //  Do 7 transactions.
            for (iTransaction = 0; iTransaction < 7; iTransaction++)
            {
                //  Change the communication mode for all files.
                bCommMode = (byte)(iTransaction % 3);
                if (bCommMode == 2) bCommMode = 3;

                //  This requires authentication with the key defined for changing the configuration.
                if (iTestMode == DesfireEV1TestMode.Legacy)
                {
                    rc = card.Authenticate(4, AppBKey4_16);
                    Check(rc);
                }
                else if (iTestMode == DesfireEV1TestMode.TDes2k)
                {
                    rc = card.AuthenticateEV1TDes(4, AppBKey4_16);
                    Check(rc);
                }
                else if (iTestMode == DesfireEV1TestMode.TDes3k)
                {
                    rc = card.AuthenticateEV1TDes(4, AppBKey4_24);
                    Check(rc);
                }
                else if (iTestMode == DesfireEV1TestMode.Aes)
                {
                    rc = card.AuthenticateEV1Aes(4, AppBKey4_16);
                    Check(rc);
                }

                rc = card.ChangeFileSettings(14, bCommMode, 0x1234);
                Check(rc);
                rc = card.ChangeFileSettings(4, bCommMode, 0x1324);
                Check(rc);
                rc = card.ChangeFileSettings(1, bCommMode, 0x1324);
                Check(rc);

                //  Authenticate with the key which allows reading the files
                if (iTestMode == DesfireEV1TestMode.Legacy)
                {
                    rc = card.Authenticate(1, AppBKey1_16);
                    Check(rc);
                }
                else if (iTestMode == DesfireEV1TestMode.TDes2k)
                {
                    rc = card.AuthenticateEV1TDes(1, AppBKey1_16);
                    Check(rc);
                }
                else if (iTestMode == DesfireEV1TestMode.TDes3k)
                {
                    rc = card.AuthenticateEV1TDes(1, AppBKey1_24);
                    Check(rc);
                }
                else if (iTestMode == DesfireEV1TestMode.Aes)
                {
                    rc = card.AuthenticateEV1Aes(1, AppBKey1_16);
                    Check(rc);
                }

                if (iTransaction < 3)
                {
                    //  Test different lengths
                    for (int i = 45; i < 65; i++)
                    {
                        rc = card.ReadData(14, bCommMode, 100 - i, i, out abDataBuffer);
                        Check(rc);
                    }
                    for (int i = 10; i <= 100; i += 10)
                    {
                        rc = card.ReadData(14, bCommMode, 100 - i, i, out abDataBuffer);
                        Check(rc);
                    }
                }

                rc = card.ReadData(14, bCommMode, 0, 0, out abDataBuffer);
                Check(rc);

                //  Authenticate with the key which allows writing to files and increasing the Value
                //  file's value.
                if (iTestMode == DesfireEV1TestMode.Legacy)
                {
                    rc = card.Authenticate(2, AppBKey2_16);
                    Check(rc);
                }
                else if (iTestMode == DesfireEV1TestMode.TDes2k)
                {
                    rc = card.AuthenticateEV1TDes(2, AppBKey2_16);
                    Check(rc);
                }
                else if (iTestMode == DesfireEV1TestMode.TDes3k)
                {
                    rc = card.AuthenticateEV1TDes(2, AppBKey2_24);
                    Check(rc);
                }
                else if (iTestMode == DesfireEV1TestMode.Aes)
                {
                    rc = card.AuthenticateEV1Aes(2, AppBKey2_16);
                    Check(rc);
                }

                //  Write to the Standard Data file.
                abDataBuffer = new byte[100];
                for (int i = 0; i < 100; i++)
                    abDataBuffer[i] = (byte)((iTransaction << 6) + i + 0);

                if (iTransaction < 3)
                {
                    rc = card.WriteData(14, bCommMode, 0, 8, abDataBuffer);
                    Check(rc);
                    rc = card.WriteData(14, bCommMode, 0, 16, abDataBuffer);
                    Check(rc);

                    rc = card.WriteData(14, bCommMode, 0, 1, abDataBuffer);
                    Check(rc);
                    rc = card.WriteData(14, bCommMode, 0, 2, abDataBuffer);
                    Check(rc);

                    for (int i = 1; i <= 100; i++)
                    {
                        rc = card.WriteData(14, bCommMode, 0, i, abDataBuffer);
                        Check(rc);
                    }

                    for (int i = 0; i < 100; i++)
                    {
                        rc = card.WriteData(14, bCommMode, i, 100 - i, abDataBuffer);
                        Check(rc);
                    }

                    rc = card.WriteData(14, bCommMode, 0, 10, abDataBuffer);
                    Check(rc);
                    rc = card.WriteData(14, bCommMode, 10, 10, abDataBuffer);
                    Check(rc);
                    rc = card.WriteData(14, bCommMode, 20, 20, abDataBuffer);
                    Check(rc);
                    rc = card.WriteData(14, bCommMode, 30, 30, abDataBuffer);
                    Check(rc);
                    rc = card.WriteData(14, bCommMode, 40, 40, abDataBuffer);
                    Check(rc);
                    rc = card.WriteData(14, bCommMode, 50, 50, abDataBuffer);
                    Check(rc);
                    rc = card.WriteData(14, bCommMode, 30, 70, abDataBuffer);
                    Check(rc);
                    rc = card.WriteData(14, bCommMode, 10, 90, abDataBuffer);
                    Check(rc);
                }

                rc = card.WriteData(14, bCommMode, 0, 100, abDataBuffer);
                Check(rc);

                string strBuffer = string.Format(" Transaction #{0} ", iTransaction);
                rc = card.WriteData(14, bCommMode, 5, StrUtils.ToBytes(strBuffer));
                Check(rc);

                //  Write to the Linear Record file.
                //  If it turns out, that the file is full, clear its contents and repeat writing.
                for (int i = 0; i < 2; i++)
                {
                    rc = card.WriteRecord(1, bCommMode, 0, StrUtils.ToBytes("0123456789012345678901234"));
                    if (rc == 0)
                        rc = card.WriteRecord(1, bCommMode, 5, StrUtils.ToBytes(strBuffer));
                    Check(rc, new Desfire.DesfireCardError[] { Desfire.Success, Desfire.DesfireCardError.BoundaryError });
                    if (rc == Desfire.Success)
                        break; // The record has been written

                    // Otherwise the file is full

                    // The current authentication status has been lost. We must get authenticated again
                    if (iTestMode == DesfireEV1TestMode.Legacy)
                    {
                        rc = card.Authenticate(2, AppBKey2_16);
                        Check(rc);
                    }
                    else if (iTestMode == DesfireEV1TestMode.TDes2k)
                    {
                        rc = card.AuthenticateEV1TDes(2, AppBKey2_16);
                        Check(rc);
                    }
                    else if (iTestMode == DesfireEV1TestMode.TDes3k)
                    {
                        rc = card.AuthenticateEV1TDes(2, AppBKey2_24);
                        Check(rc);
                    }
                    else if (iTestMode == DesfireEV1TestMode.Aes)
                    {
                        rc = card.AuthenticateEV1Aes(2, AppBKey2_16);
                        Check(rc);
                    }

                    //  Clear the record file.
                    rc = card.ClearRecordFile(1);
                    Check(rc);

                    //  It is not allowed to write to the file before a CommitTransaction.
                    //  So the following call will fail !
                    rc = card.WriteRecord(1, bCommMode, 5, 25, abDataBuffer);
                    Check(rc, Desfire.DesfireCardError.PermissionDenied);

                    // The current authentication status has been lost. We must get authenticated again
                    if (iTestMode == DesfireEV1TestMode.Legacy)
                    {
                        rc = card.Authenticate(2, AppBKey2_16);
                        Check(rc);
                    }
                    else if (iTestMode == DesfireEV1TestMode.TDes2k)
                    {
                        rc = card.AuthenticateEV1TDes(2, AppBKey2_16);
                        Check(rc);
                    }
                    else if (iTestMode == DesfireEV1TestMode.TDes3k)
                    {
                        rc = card.AuthenticateEV1TDes(2, AppBKey2_24);
                        Check(rc);
                    }
                    else if (iTestMode == DesfireEV1TestMode.Aes)
                    {
                        rc = card.AuthenticateEV1Aes(2, AppBKey2_16);
                        Check(rc);
                    }

                    //  Version 0.1 and above execute an implicit AbortTransaction after any
                    //  error. Therefore the ClearRecordFile has been cancelled. We have to repeat it.
                    rc = card.ClearRecordFile(1);
                    Check(rc);

                    //  After the following the Record file is again ready for data.
                    rc = card.CommitTransaction();
                    Check(rc);
                }

                //  Modify the Value file.
                rc = card.Debit(4, bCommMode, 1300);
                Check(rc);
                rc = card.Credit(4, bCommMode, 20);
                Check(rc);
                rc = card.Debit(4, bCommMode, 1700);
                Check(rc);

                //  Make all changes current.
                rc = card.CommitTransaction();
                Check(rc);

                //  Return the whole debited amount to the Value File.
                rc = card.LimitedCredit(4, bCommMode, 3000);
                Check(rc);

                //  Make the change current.
                rc = card.CommitTransaction();
                Check(rc);


                //  Authenticate with the key which allows reading files and retrieving the Value
                //  file's value.
                if (iTestMode == DesfireEV1TestMode.Legacy)
                {
                    rc = card.Authenticate(1, AppBKey1_16);
                    Check(rc);
                }
                else if (iTestMode == DesfireEV1TestMode.TDes2k)
                {
                    rc = card.AuthenticateEV1TDes(1, AppBKey1_16);
                    Check(rc);
                }
                else if (iTestMode == DesfireEV1TestMode.TDes3k)
                {
                    rc = card.AuthenticateEV1TDes(1, AppBKey1_24);
                    Check(rc);
                }
                else if (iTestMode == DesfireEV1TestMode.Aes)
                {
                    rc = card.AuthenticateEV1Aes(1, AppBKey1_16);
                    Check(rc);
                }

                //  Read the first half of the Standard Data file's data specifying the exact
                //  number of bytes to read.
                rc = card.ReadData(14, bCommMode, 0, 50, out abDataBuffer);
                Check(rc);
                //  Read the second half of the data with an open read (give me all data available).
                rc = card.ReadData(14, bCommMode, 50, 0, out abDataBuffer);
                Check(rc);

                //  Get the Value file's current balance.
                rc = card.GetValue(4, bCommMode, out lAmount);
                Check(rc);

                //  Get the number of records in the Linear Record file.
                rc = card.GetFileSettings(1, out bFileType, out bCommMode, out wAccessRights, out unFileSettings);
                Check(rc);

                //  Read the oldest record from the file.
                rc = card.ReadRecords(1, bCommMode, unFileSettings.RecordFile.CurrentRecordCount - 1, 1, unFileSettings.RecordFile.RecordSize, out abDataBuffer, out eNRecordsRead);
                Check(rc);

                //  Read all records from the file.
                rc = card.ReadRecords(1, bCommMode, 0, 0, unFileSettings.RecordFile.RecordSize, out abDataBuffer, out eNRecordsRead);
                Check(rc);
            }

            //  Get the file IDs of the current application.
            rc = card.GetFileIDs(out abFileList);
            Check(rc);

            //  Get information about the application's files.
            //  Delete each file after retrieving information about it.
            for (iFileIndex = 0; iFileIndex < abFileList.Length; iFileIndex++)
            {
                rc = card.GetFileSettings(abFileList[iFileIndex], out bFileType, out bCommMode, out wAccessRights, out unFileSettings);
                Check(rc);
                rc = card.DeleteFile(abFileList[iFileIndex]);
                Check(rc);
            }

            //  Verify that there are no files in the application.
            rc = card.GetFileIDs(out abFileList);
            Check(rc);

            //  Delete application B.
            //  This time we can (and do) use the Application Master Key.
            if (iTestMode == DesfireEV1TestMode.Legacy)
            {
                rc = card.Authenticate(0, AppBKeyMaster0_16);
                Check(rc);
            }
            else if (iTestMode == DesfireEV1TestMode.TDes2k)
            {
                rc = card.AuthenticateEV1TDes(0, AppBKeyMaster0_16);
                Check(rc);
            }
            else if (iTestMode == DesfireEV1TestMode.TDes3k)
            {
                rc = card.AuthenticateEV1TDes(0, appBKeyMaster0_24);
                Check(rc);
            }
            else if (iTestMode == DesfireEV1TestMode.Aes)
            {
                rc = card.AuthenticateEV1Aes(0, AppBKeyMaster0_16);
                Check(rc);
            }

            rc = card.DeleteApplication(0xBBBBBB);
            Check(rc);

            rc = card.SelectApplication(0);
            Check(rc);

            //  Verify that application B has been deleted.
            rc = card.GetApplicationIDs(out adwApplicationList);
            Check(rc);

            if (dwFreeBytes < 2000)
            {
                rc = card.SelectApplication(0);
                Check(rc);

                if (doChangeMasterKey)
                {
                    if (iTestMode == DesfireEV1TestMode.Legacy)
                    {
                        rc = card.Authenticate(0, RootKey2K);
                        Check(rc);
                    }
                    else if (iTestMode == DesfireEV1TestMode.TDes2k)
                    {
                        rc = card.AuthenticateEV1TDes(0, RootKey2K);
                        Check(rc);
                    }
                    else if (iTestMode == DesfireEV1TestMode.TDes3k)
                    {
                        rc = card.AuthenticateEV1TDes(0, RootKey2K_24);
                        Check(rc);
                    }
                    else if (iTestMode == DesfireEV1TestMode.Aes)
                    {
                        rc = card.AuthenticateEV1Aes(0, RootKey2K);
                        Check(rc);
                    }
                }
                else
                {
                    rc = card.SelectApplication(0);
                    Check(rc);

                    if (iTestMode == DesfireEV1TestMode.Legacy)
                    {
                        rc = card.Authenticate(0, NullKey_16);
                        Check(rc);
                    }
                    else if (iTestMode == DesfireEV1TestMode.TDes2k)
                    {
                        rc = card.AuthenticateEV1TDes(0, NullKey_16);
                        Check(rc);
                    }
                    else if (iTestMode == DesfireEV1TestMode.TDes3k)
                    {
                        rc = card.AuthenticateEV1TDes(0, NullKey_24);
                        Check(rc);
                    }
                    else if (iTestMode == DesfireEV1TestMode.Aes)
                    {
                        rc = card.AuthenticateEV1Aes(0, NullKey_16);
                        Check(rc);
                    }
                }


                rc = card.FormatPICC();
                Check(rc);

                if (iTestMode == DesfireEV1TestMode.Legacy)
                {
                    rc = card.CreateApplication(0xCCCCCC, 0xC0, 14);
                    Check(rc);
                }
                else if (iTestMode == DesfireEV1TestMode.TDes2k)
                {
                    rc = card.CreateApplication(0xCCCCCC, 0xC0, 14);
                    Check(rc);
                }
                else if (iTestMode == DesfireEV1TestMode.TDes3k)
                {
                    rc = card.CreateApplication(0xCCCCCC, 0xC0, (byte)Desfire.DesfireKeyType.TDES3K | 14);
                    Check(rc);
                }
                else if (iTestMode == DesfireEV1TestMode.Aes)
                {
                    rc = card.CreateApplication(0xCCCCCC, 0xC0, (byte)Desfire.DesfireKeyType.AES128 | 14);
                    Check(rc);
                }
            }

            //  Working with a larger file (a Cyclic Record File) using application C:
            rc = card.SelectApplication(0xCCCCCC);
            Check(rc);

            //  Define keys #1 and #2 using the Change Keys key (#12).
            if (iTestMode == DesfireEV1TestMode.Legacy)
            {
                rc = card.Authenticate(12, NullKey_16);
                Check(rc);
                rc = card.ChangeKey(1, AppCKey1_16, NullKey_16);
                Check(rc);
                rc = card.ChangeKey(2, AppCKey2_16, NullKey_16);
                Check(rc);
                // Back to master key
                rc = card.Authenticate(0, NullKey_16);
                Check(rc);
            }
            else if (iTestMode == DesfireEV1TestMode.TDes2k)
            {
                rc = card.AuthenticateEV1TDes(12, NullKey_16);
                Check(rc);
                rc = card.ChangeKey(1, AppCKey1_16, NullKey_16);
                Check(rc);
                rc = card.ChangeKey(2, AppCKey2_16, NullKey_16);
                Check(rc);
                // Back to master key
                rc = card.AuthenticateEV1TDes(0, NullKey_16);
                Check(rc);
            }
            else if (iTestMode == DesfireEV1TestMode.TDes3k)
            {
                rc = card.AuthenticateEV1TDes(12, NullKey_24);
                Check(rc);
                rc = card.ChangeKey(1, AppCKey1_24, NullKey_24);
                Check(rc);
                rc = card.ChangeKey(2, AppCKey2_24, NullKey_24);
                Check(rc);
                // Back to master key
                rc = card.AuthenticateEV1TDes(0, NullKey_24);
                Check(rc);
            }
            else if (iTestMode == DesfireEV1TestMode.Aes)
            {
                rc = card.AuthenticateEV1Aes(12, NullKey_16);
                Check(rc);
                rc = card.ChangeKey(1, 0, AppCKey1_16, NullKey_16);
                Check(rc);
                rc = card.ChangeKey(2, 0, AppCKey2_16, NullKey_16);
                Check(rc);
                // Back to master key
                rc = card.AuthenticateEV1Aes(0, NullKey_16);
                Check(rc);
            }

            //  Create the file - it has 16 records of 100 bytes
            rc = card.CreateCyclicRecordFile(6, 0, 0x12E0, 100, 16);
            Check(rc);

            //  Do 50 transactions.
            for (iTransaction = 0; iTransaction < 50; iTransaction++)
            {
                //  Change the file's communication mode.
                bCommMode = (byte)(iTransaction % 3);
                if (bCommMode == 2)
                    bCommMode++;

                //  This requires authentication with the key defined for changing the configuration.
                //  For this file it is the Application Master Key.
                if (iTestMode == DesfireEV1TestMode.Legacy)
                {
                    rc = card.Authenticate(0, NullKey_16);
                    Check(rc);
                }
                else if (iTestMode == DesfireEV1TestMode.TDes2k)
                {
                    rc = card.AuthenticateEV1TDes(0, NullKey_16);
                    Check(rc);
                }
                else if (iTestMode == DesfireEV1TestMode.TDes3k)
                {
                    rc = card.AuthenticateEV1TDes(0, NullKey_24);
                    Check(rc);
                }
                else if (iTestMode == DesfireEV1TestMode.Aes)
                {
                    rc = card.AuthenticateEV1Aes(0, NullKey_16);
                    Check(rc);
                }

                rc = card.ChangeFileSettings(6, bCommMode, 0x12E0);
                Check(rc);

                //  The file can be written using either the Write access key (0x.2..) or the
                //  Read/Write key (0x..E.).
                //  A valid authentication with key #2 causes the communication to take place in
                //  the mode defined with ChangeFileSettings above.
                //  Not being authenticated with key #2 causes the Read/Write access right to be used
                //  forcing the communication to plain mode.
                if ((iTransaction & 0x04) != 0)
                {
                    if (iTestMode == DesfireEV1TestMode.Legacy)
                    {
                        rc = card.Authenticate(2, AppCKey2_16);
                        Check(rc);
                    }
                    else if (iTestMode == DesfireEV1TestMode.TDes2k)
                    {
                        rc = card.AuthenticateEV1TDes(2, AppCKey2_16);
                        Check(rc);
                    }
                    else if (iTestMode == DesfireEV1TestMode.TDes3k)
                    {
                        rc = card.AuthenticateEV1TDes(2, AppCKey2_24);
                        Check(rc);
                    }
                    else if (iTestMode == DesfireEV1TestMode.Aes)
                    {
                        rc = card.AuthenticateEV1Aes(2, AppCKey2_16);
                        Check(rc);
                    }
                }
                else
                    bCommMode = 0;

                //  Write a new record.
                abDataBuffer = new byte[100];
                string strBuffer = string.Format(" Transaction #{0} !TEST!?!TEST! ", iTransaction);
                BinUtils.CopyTo(abDataBuffer, StrUtils.ToBytes(strBuffer));
                rc = card.WriteRecord(6, bCommMode, 0, 100, abDataBuffer);

                //  Cancel every 7th WriteRecord operation.
                if (iTransaction % 7 == 0)
                    rc = card.AbortTransaction();
                else
                    rc = card.CommitTransaction();

                Check(rc, new Desfire.DesfireCardError[] { Desfire.Success, Desfire.DesfireCardError.NoChange, Desfire.DesfireCardError.CommandAborted });
            }

            //  Read each individual record using the designated read key.
            //  Note that increasing the offset lets us go back in the record history.
            //  Note also that only 16-1 records (one less than specified in CreateCyclicRecordFile)
            //  can be accessed.
            bCommMode = 1;

            if (iTestMode == DesfireEV1TestMode.Legacy)
            {
                rc = card.Authenticate(1, AppCKey1_16);
                Check(rc);
            }
            else if (iTestMode == DesfireEV1TestMode.TDes2k)
            {
                rc = card.AuthenticateEV1TDes(1, AppCKey1_16);
                Check(rc);
            }
            else if (iTestMode == DesfireEV1TestMode.TDes3k)
            {
                rc = card.AuthenticateEV1TDes(1, AppCKey1_24);
                Check(rc);
            }
            else if (iTestMode == DesfireEV1TestMode.Aes)
            {
                rc = card.AuthenticateEV1Aes(1, AppCKey1_16);
                Check(rc);
            }

            for (int i = 0; i < 16; i++)
            {
                rc = card.ReadRecords(6, bCommMode, i, 1, 100, out abDataBuffer, out eNRecordsRead);
                Check(rc, new Desfire.DesfireCardError[] { Desfire.Success, Desfire.DesfireCardError.BoundaryError });
            }

            //  Following the Boundary Error we lose the authentication - so we must get authenticated again
            if (iTestMode == DesfireEV1TestMode.Legacy)
            {
                rc = card.Authenticate(1, AppCKey1_16);
                Check(rc);
            }
            else if (iTestMode == DesfireEV1TestMode.TDes2k)
            {
                rc = card.AuthenticateEV1TDes(1, AppCKey1_16);
                Check(rc);
            }
            else if (iTestMode == DesfireEV1TestMode.TDes3k)
            {
                rc = card.AuthenticateEV1TDes(1, AppCKey1_24);
                Check(rc);
            }
            else if (iTestMode == DesfireEV1TestMode.Aes)
            {
                rc = card.AuthenticateEV1Aes(1, AppCKey1_16);
                Check(rc);
            }

            rc = card.ReadRecords(6, bCommMode, 0, 1, 100, out abDataBuffer, out eNRecordsRead);
            Check(rc);

            //  Read the whole record file with a single ReadRecords call.
            rc = card.ReadRecords(6, bCommMode, 0, 15, 100, out abDataBuffer, out eNRecordsRead);
            Check(rc);

            rc = card.ReadRecords(6, bCommMode, 0, 0, 100, out abDataBuffer, out eNRecordsRead);
            Check(rc);

            //  Change the master key settings such that master key authentication will be required
            //  for all card operations.
            //  Leave the ChangeConfiguration bit (bit 3) set to allow undoing the change.
            rc = card.SelectApplication(0);
            Check(rc);

            if (doChangeMasterKey)
            {
                if (iTestMode == DesfireEV1TestMode.Legacy)
                {
                    rc = card.Authenticate(0, RootKey2K);
                    Check(rc);
                }
                else if (iTestMode == DesfireEV1TestMode.TDes2k)
                {
                    rc = card.AuthenticateEV1TDes(0, RootKey2K);
                    Check(rc);
                }
                else if (iTestMode == DesfireEV1TestMode.TDes3k)
                {
                    rc = card.AuthenticateEV1TDes(0, RootKey2K_24);
                    Check(rc);
                }
                else if (iTestMode == DesfireEV1TestMode.Aes)
                {
                    rc = card.AuthenticateEV1Aes(0, RootKey2K);
                    Check(rc);
                }

                rc = card.ChangeKeySettings(0x8);
                Check(rc);

                //  Clear the authentication state and try to get application IDs.
                //  Also try to delete application C or to create a new application.
                rc = card.SelectApplication(0);
                Check(rc);

                //  The following three calls will report an Authentication Error (0xAE).
                rc = card.GetApplicationIDs(out adwApplicationList);
                Check(rc, Desfire.DesfireCardError.AuthenticationError);
                rc = card.DeleteApplication(0xCCCCCC);
                Check(rc, Desfire.DesfireCardError.AuthenticationError);

                // This one must fail
                rc = card.CreateApplication(0xDDDDDD, 0xEF, 0);
                Check(rc, Desfire.DesfireCardError.AuthenticationError);

                //  With authentication all three should work.
                if (iTestMode == DesfireEV1TestMode.Legacy)
                {
                    rc = card.Authenticate(0, RootKey2K);
                    Check(rc);
                }
                else if (iTestMode == DesfireEV1TestMode.TDes2k)
                {
                    rc = card.AuthenticateEV1TDes(0, RootKey2K);
                    Check(rc);
                }
                else if (iTestMode == DesfireEV1TestMode.TDes3k)
                {
                    rc = card.AuthenticateEV1TDes(0, RootKey2K_24);
                    Check(rc);
                }
                else if (iTestMode == DesfireEV1TestMode.Aes)
                {
                    rc = card.AuthenticateEV1Aes(0, RootKey2K);
                    Check(rc);
                }
            }
            else
            {
                rc = card.Authenticate(0, NullKey_16);
                Check(rc);
            }

            rc = card.GetApplicationIDs(out adwApplicationList);
            Check(rc);
            rc = card.DeleteApplication(0xCCCCCC);
            Check(rc);
            rc = card.CreateApplication(0xDDDDDD, 0xEF, 0);
            Check(rc);

            if (doChangeMasterKey)
            {
                //  Change the master key settings back to the default which is least restrictive.
                rc = card.ChangeKeySettings(0xF);
                Check(rc);

                //  Change the Card master key back to the 0 key.
                if (iTestMode == DesfireEV1TestMode.Legacy)
                {
                    rc = card.Authenticate(0, RootKey2K);
                    Check(rc);
                }
                else if (iTestMode == DesfireEV1TestMode.TDes2k)
                {
                    rc = card.AuthenticateEV1TDes(0, RootKey2K);
                    Check(rc);
                }
                else if (iTestMode == DesfireEV1TestMode.TDes3k)
                {
                    rc = card.AuthenticateEV1TDes(0, RootKey2K_24);
                    Check(rc);

                    //  for obvious reasons we cannot revert the config to 3DES2K, but a hook by AES permits it
                    rc = card.ChangeKey((byte)Desfire.DesfireKeyType.AES128 | 0, 0xAE, RootKey2K, null);
                    Check(rc);
                    rc = card.AuthenticateEV1Aes(0, RootKey2K);
                    Check(rc);

                }
                else if (iTestMode == DesfireEV1TestMode.Aes)
                {
                    rc = card.AuthenticateEV1Aes(0, RootKey2K);
                    Check(rc);
                }

                rc = card.ChangeKey(0, NullKey_16, null);
                Check(rc);
            }

            //  Delete all demonstration data from the card.
            rc = card.Authenticate(0, NullKey_16);
            Check(rc);

            if (!fEv0OrLower)
            {
                rc = card.GetFreeMemory(out dwFreeBytes);
                Check(rc);
            }

            rc = card.FormatPICC();
            Check(rc);

            Console.WriteLine();
        }
    }
}
