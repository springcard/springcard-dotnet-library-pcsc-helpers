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
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using SpringCard.LibCs;
using SpringCard.PCSC;
using SpringCard.PCSC.CardHelpers;

namespace SpringCard.PCSC.SelfTest
{
    partial class Program
    {
        readonly byte[] NullKey_16 = new byte[16];

        readonly byte[] TestDesKey = StrUtils.ToBytes("ABCDEFGHABCDEFGH");
        readonly byte[] TestTDesKey = StrUtils.ToBytes("Card Master Key!");

        public void Check(long rc, Desfire.DesfireCardError allowed_status)
        {
            Check(rc, new Desfire.DesfireCardError[] { allowed_status });
        }

        public void Check(long rc, Desfire.DesfireCardError[] allowed_status = null)
        {
            string errorMsg;
            Desfire.DesfireCardError cardStatus = Desfire.DesfireCardError.Unknown;
            Desfire.DesfireLibraryError libraryStatus = Desfire.DesfireLibraryError.Unknown;

            if (rc != Desfire.Success)
            {
                if (Desfire.IsCardError(rc))
                {
                    cardStatus = Desfire.GetCardError(rc);
                    errorMsg = string.Format("rc={0} {1:X02} ({2})", rc, (byte)cardStatus, cardStatus);
                }
                else if (Desfire.IsLibraryError(rc))
                {
                    libraryStatus = Desfire.GetLibraryError(rc);
                    errorMsg = string.Format("rc={0} {1:X02} ({2})", rc, (byte)libraryStatus, libraryStatus);
                }
                else
                {
                    errorMsg = string.Format("rc={0}", rc);
                }
            }
            else
            {
                errorMsg = string.Format("rc={0} (Success)", rc);
            }

            if (allowed_status == null)
            {
                if (rc == 0)
                    goto ok;

                Console.WriteLine();
                Logger.Fatal(errorMsg);
            }
            else
            {
                for (int i = 0; i < allowed_status.Length; i++)
                    if (cardStatus == allowed_status[i])
                        goto ok;

                string hintMsg = "";
                for (int i = 0; i < allowed_status.Length; i++)
                {
                    if (hintMsg.Length > 0) hintMsg += " or ";
                    hintMsg += string.Format("{0:X02} ({1})", (byte)allowed_status[i], allowed_status[i]);
                }

                Console.WriteLine();
                Logger.Fatal("{0} [expected {1}]", errorMsg, hintMsg);
            }

            throw new Exception("Test failed");

        ok:
            if (!quiet)
                Console.Write(".");
        }


        public void TestDesfireEV0(DesfireEV0 card)
        {
            long rc;
            long lAmount;
            byte bCommMode, bKeyVersion;
            int eNRecordsRead, eOffset;
            byte[] abCardMasterKey;
            byte bStdDataFileID, bFileType;
            byte bKeySettings, bKeyCount;
            uint[] adwApplicationList;
            byte[] abFileList;
            byte[] abDataBuffer;
            ushort wDesFireSoftwareVersion, wAccessRights;
            int iTransaction, iFileIndex;

            Desfire.DesfireFileSettings unFileSettings;

        next_run:

            //  After activating a DesFire card the currently selected 'application' is the card
            //  level (AID = 0). Therefore the next command is redundant.
            //  We use the command to check that the card is responding correctly.
            rc = card.SelectApplication(0);
            Check(rc);

            //  Get the card's version information.
            rc = card.GetVersion(out Desfire.DesfireVersionInfo stVersionInfo);
            Check(rc);
            wDesFireSoftwareVersion = (ushort)(stVersionInfo.SwMajorVersion << 8 | stVersionInfo.SwMinorVersion);


            //  Which Card Master Key is currently in use ?
            //  Beginning with DesFire version 0.1 the GetKeyVersion command can help determining
            //  which key is currently effective.
            rc = card.GetKeyVersion(0, out bKeyVersion);
            Check(rc);

            //  Authenticate with the key which corresponds to the retieved key version.
            if (bKeyVersion == 0)
                rc = card.Authenticate(0, NullKey_16);
            else if (bKeyVersion == 0xAA)
                rc = card.Authenticate(0, TestDesKey);
            else if (bKeyVersion == 0xC7)
                rc = card.Authenticate(0, TestTDesKey);
            else
            {
                //  Who knows the key ?
                Console.WriteLine("Sorry, the master key is unknown (version = {0:X02})", bKeyVersion);
                return;
            }
            Check(rc);

            if (bKeyVersion != 0x00)
            {
                Console.WriteLine("Current master key version is {0:X02}", bKeyVersion);
                rc = card.GetKeySettings(out bKeySettings, out bKeyCount);
                Check(rc);
                Console.WriteLine("Root application key settings are {0:X02} {1:X02}", bKeySettings, bKeyCount);

                //  Try to allow to change the key
                rc = card.ChangeKeySettings(0xF);
                Check(rc);

                //  Back to blank key
                rc = card.ChangeKey(0, NullKey_16, null);
                Check(rc);

                //  Authenticate again
                rc = card.Authenticate(0, NullKey_16);
                Check(rc);

                //  Startup with a blank card !!!
                Console.WriteLine("Formatting the tag\n");
                rc = card.FormatPICC();
                Check(rc);

                goto next_run;
            }

            if (doChangeMasterKey)
            {
                //  Change the Card master key to a SingleDES key.
                abCardMasterKey = TestDesKey;
                rc = card.ChangeKey(0, abCardMasterKey, null);
                Check(rc);
                rc = card.GetKeyVersion(0, out bKeyVersion);
                Check(rc);
                rc = card.Authenticate(0, abCardMasterKey);
                Check(rc);

                //  Change the Card master key to a TripleDES key.
                abCardMasterKey = TestTDesKey;
                rc = card.ChangeKey(0, abCardMasterKey, null);
                Check(rc);
                rc = card.GetKeyVersion(0, out bKeyVersion);
                Check(rc);
                rc = card.Authenticate(0, abCardMasterKey);
                Check(rc);
            }
            else
            {
                //  Authenticate again
                abCardMasterKey = NullKey_16;
                rc = card.Authenticate(0, abCardMasterKey);
                Check(rc);
            }

            //  At this point we would like to begin with a blank card.
            rc = card.FormatPICC();
            Check(rc);

            //  Create three applications:

            //  Authentication is not necessary in the default configuration.
            //  Clear the authentication state to show this.
            rc = card.SelectApplication(0);
            Check(rc);

            //  Application A is the most open one.
            //  It has no keys and its key settings are least restrictive.
            //  Note: since there are no keys, the Change Keys key settting must be assigned
            //        the value 0xE or 0xF.
            rc = card.CreateApplication(0xAAAAAA, 0xFF, 0);
            Check(rc);

            //  Application B's key settings can be changed at a later time.
            //  It has six keys.
            //  Authentication with a given key allows also to change that key.
            //  (the Change Keys key settting is 0xE)
            rc = card.CreateApplication(0xBBBBBB, 0xEF, 6);
            Check(rc);

            //  Application C keeps everything private.
            //  Even getting its file directory is not publicly allowed.
            //  The application has the maximum of 14 keys.
            //  We make key #0xC the Change Keys key.
            rc = card.CreateApplication(0xCCCCCC, 0xC0, 14);
            Check(rc);

            //  Verify, that the applications which have been just created exist.
            rc = card.GetApplicationIDs(out adwApplicationList);
            Check(rc);

            //  Create the files in application A:
            //  Since the application does not have any keys associated with it, the file access rights
            //  settings 0xE (public access granted) and 0xF (access denied) are the only permissable
            //  ones.
            rc = card.SelectApplication(0xAAAAAA);
            Check(rc);

            //  Create a the Standard Data file.
            bStdDataFileID = 15;
            rc = card.CreateStdDataFile(bStdDataFileID, 0, 0xEEEE, 550);
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
            abDataBuffer = new byte[550];
            for (int i = 0; i < abDataBuffer.Length; i++)
                abDataBuffer[i] = 0xDA;
            rc = card.WriteData(bStdDataFileID, (byte)Desfire.DesfireCommMode.Plain, 0, abDataBuffer.Length, abDataBuffer);
            Check(rc);
            rc = card.WriteData(bStdDataFileID, (byte)Desfire.DesfireCommMode.Plain, 0, 30, StrUtils.ToBytes("This is the 1st block written."));
            Check(rc);
            rc = card.WriteData(bStdDataFileID, (byte)Desfire.DesfireCommMode.Plain, 34, 22, StrUtils.ToBytes("This is the 2nd block."));
            Check(rc);

            //  Then make the file permanently read-only.
            rc = card.ChangeFileSettings(bStdDataFileID, (byte)Desfire.DesfireCommMode.Plain, 0xEFFF);
            Check(rc);

            //  Read part of the file's contents.
            rc = card.ReadData(bStdDataFileID, (byte)Desfire.DesfireCommMode.Plain, 10, 50, out abDataBuffer);
            Check(rc);

            //  Get all data in one block. 
            //  Note: Must make sure that buffer is large enough for all data!!
            rc = card.ReadData(bStdDataFileID, (byte)Desfire.DesfireCommMode.Plain, 0, 0, out abDataBuffer);
            Check(rc);

            //  Try to overwrite the file.
            //  Since we have made the file read-only, this should fail.
            rc = card.WriteData(bStdDataFileID, (byte)Desfire.DesfireCommMode.Plain, 20, 5, StrUtils.ToBytes("Test!"));
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
            rc = card.Authenticate(0, abCardMasterKey);
            Check(rc);
            rc = card.DeleteApplication(0xAAAAAA);
            Check(rc);

            //  Verify that application A has been deleted.
            rc = card.GetApplicationIDs(out adwApplicationList);
            Check(rc);

            //  Changing application B's keys:
            rc = card.SelectApplication(0xBBBBBB);
            Check(rc);

            //  Use a TripleDES key as the Application Master Key.
            rc = card.Authenticate(0, NullKey_16);
            Check(rc);
            rc = card.ChangeKey(0, StrUtils.ToBytes("App.B Master Key"), null);
            Check(rc);

            //  Beginning with DesFire version 0.1 we can query the version number of a key.
            rc = card.GetKeyVersion(0, out bKeyVersion);
            Check(rc);

            //  Authenticate with the new application master key.
            //  This time use the opposite parity in all key bytes.
            rc = card.Authenticate(0, StrUtils.ToBytes("@qq/C!L`ruds!Kdx"));
            Check(rc);

            //  Change key #1 to a different SingleDES key (both key halves are the same).
            //  Authentication with that key is necessary for changing it.
            rc = card.Authenticate(1, NullKey_16);
            Check(rc);
            rc = card.ChangeKey(1, StrUtils.ToBytes("SglDES_1SglDES_1"), null);
            Check(rc);

            //  Change key #5 to a TripeDES key.
            //  Authentication with that key is necessary for changing it.
            rc = card.Authenticate(5, NullKey_16);
            Check(rc);
            rc = card.ChangeKey(5, StrUtils.ToBytes("B's Chg Keys Key"), null);
            Check(rc);

            //  Make key #5 the Change Keys Key.
            rc = card.Authenticate(0, StrUtils.ToBytes("App.B Master Key"));
            Check(rc);
            rc = card.ChangeKeySettings(0x5F);
            Check(rc);

            //  Verify the new key settings.
            rc = card.GetKeySettings(out bKeySettings, out bKeyCount);
            Check(rc);

            //  Change keys #1 through #4 using the three key procedure.
            //  Authentication with the Change Keys Key is now necessary for changing ordinary keys.
            rc = card.Authenticate(5, StrUtils.ToBytes("B's Chg Keys Key"));
            Check(rc);
            rc = card.ChangeKey(1, StrUtils.ToBytes("App.B Key #1.   "), StrUtils.ToBytes("SglDES_1SglDES_1"));
            Check(rc);
            rc = card.ChangeKey(2, StrUtils.ToBytes("App.B Key #2..  "), NullKey_16);
            Check(rc);
            rc = card.ChangeKey(3, StrUtils.ToBytes("App.B Key #3... "), NullKey_16);
            Check(rc);
            rc = card.ChangeKey(4, StrUtils.ToBytes("App.B Key #4...."), NullKey_16);
            Check(rc);

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

            //  Do 7 transactions.
            for (iTransaction = 0; iTransaction < 7; iTransaction++)
            {
                //  Change the communication mode for all files.
                bCommMode = (byte)(iTransaction % 3);
                if (bCommMode == 2)
                    bCommMode++;

                //  This requires authentication with the key defined for changing the configuration.
                rc = card.Authenticate(4, StrUtils.ToBytes("App.B Key #4...."));
                Check(rc);
                rc = card.ChangeFileSettings(14, bCommMode, 0x1234);
                Check(rc);
                rc = card.ChangeFileSettings(4, bCommMode, 0x1324);
                Check(rc);
                rc = card.ChangeFileSettings(1, bCommMode, 0x1324);
                Check(rc);

                //  Authenticate with the key which allows writing to files and increasing the Value
                //  file's value.
                rc = card.Authenticate(2, StrUtils.ToBytes("App.B Key #2..  "));
                Check(rc);

                //  Write to the Standard Data file.
                abDataBuffer = new byte[100];
                for (int i = 0; i < 100; i++)
                    abDataBuffer[i] = (byte)(iTransaction + i);
                rc = card.WriteData(14, bCommMode, 0, 100, abDataBuffer);
                Check(rc);

                string strDataBuffer = string.Format(" Transaction #{0} ", iTransaction);
                rc = card.WriteData(14, bCommMode, 5, strDataBuffer.Length, StrUtils.ToBytes(strDataBuffer));
                Check(rc);

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
                        rc = card.WriteData(14, bCommMode, i, 100-i, abDataBuffer);
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

                //  Write to the Linear Record file.
                //  If it turns out, that the file is full, clear its contents and repeat writing.
                for (int i = 0; i < 2; i++)
                {
                    rc = card.WriteRecord(1, bCommMode, 0, 25, StrUtils.ToBytes("0123456789012345678901234"));
                    if (rc == 0)
                    {
                        strDataBuffer = string.Format(" Transaction #{0} ", iTransaction);
                        rc = card.WriteRecord(1, bCommMode, 5, strDataBuffer.Length, StrUtils.ToBytes(strDataBuffer));
                    }
                    Check(rc, new Desfire.DesfireCardError[] { Desfire.Success, Desfire.DesfireCardError.BoundaryError });
                    if (rc == Desfire.Success)
                        break; // The record has been written

                    // Otherwise the file is full

                    //  Clear the record file.
                    rc = card.ClearRecordFile(1);
                    Check(rc);

                    //  It is not allowed to write to the file before a CommitTransaction.
                    //  So the following call will fail !
                    rc = card.WriteRecord(1, bCommMode, 5, strDataBuffer.Length, StrUtils.ToBytes(strDataBuffer));
                    Check(rc, Desfire.DesfireCardError.PermissionDenied);

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
                rc = card.Authenticate(1, StrUtils.ToBytes("App.B Key #1.   "));
                Check(rc);

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
                rc = card.ReadRecords(1, bCommMode, unFileSettings.RecordFile.CurrentRecordCount - 1, 1, unFileSettings.RecordFile. RecordSize, out abDataBuffer, out eNRecordsRead);
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
            for (iFileIndex = 0; iFileIndex< abFileList.Length; iFileIndex++)
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
            rc = card.Authenticate(0, StrUtils.ToBytes("App.B Master Key"));
            Check(rc);
            rc = card.DeleteApplication(0xBBBBBB);
            Check(rc);

            //  Verify that application B has been deleted.
            rc = card.GetApplicationIDs(out adwApplicationList);
            Check(rc);

            //  Working with a larger file (a Cyclic Record File) using application C:
            rc = card.SelectApplication(0xCCCCCC);
            Check(rc);

            //  Define keys #1 and #2 using the Change Keys key (#12).
            rc = card.Authenticate(12, NullKey_16);
            Check(rc);

            rc = card.ChangeKey(1, StrUtils.ToBytes("App.C Key #1.   "), NullKey_16);
            Check(rc);

            rc = card.ChangeKey(2, StrUtils.ToBytes("App.C Key #2..  "), NullKey_16);
            Check(rc);

            //  Create the file.
            rc = card.Authenticate(0, NullKey_16);
            Check(rc);

            rc = card.CreateCyclicRecordFile(6, 0, 0x12E0, 100, 22);
            Check(rc);

            //  Do 50 transactions.
            for (iTransaction = 0; iTransaction< 50; iTransaction++)
            {
                //  Change the file's communication mode.
                bCommMode = (byte)(iTransaction % 3);
                if (bCommMode == 2)
                    bCommMode++;

                //  This requires authentication with the key defined for changing the configuration.
                //  For this file it is the Application Master Key.
                rc = card.Authenticate(0, NullKey_16);
                Check(rc);
                rc = card.ChangeFileSettings(6, bCommMode, 0x12E0);
                Check(rc);

                //  The file can be written using either the Write access key (0x.2..) or the
                //  Read/Write key (0x..E.).
                //  A valid authentication with key #2 causes the communication to take place in
                //  the mode defined with ChangeFileSettings above.
                //  Not being authenticated with key #2 causes the Read/Write access right to be used
                //  forcing the communication to plain mode.
                if ((iTransaction & 4) != 0)
                {
                    rc = card.Authenticate(2, StrUtils.ToBytes("App.C Key #2..  "));
                    Check(rc);
                }
                else
                    bCommMode = 0;

                //  Write a new record.
                abDataBuffer = new byte[100];
                for (int i=0; i<100; i++)
                    abDataBuffer[i] = (byte) '_';
                abDataBuffer[0] = (byte)iTransaction;
                abDataBuffer[99] = (byte)iTransaction;

                byte[] tmpDataBuffer = StrUtils.ToBytes(string.Format(" Transaction #%d ", iTransaction));
                Array.Copy(tmpDataBuffer, 0, abDataBuffer, 5, tmpDataBuffer.Length);

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
            //  Note also that only 22-1 records (one less than specified in CreateCyclicRecordFile)
            //  can be accessed.
            bCommMode = 1;
            rc = card.Authenticate(1, StrUtils.ToBytes("App.C Key #1.   "));
            Check(rc);

            for (eOffset = 0; eOffset < 22; eOffset++)
            {
                rc = card.ReadRecords(6, bCommMode, eOffset, 1, 100, out abDataBuffer, out eNRecordsRead);
                Check(rc, new Desfire.DesfireCardError[] { Desfire.Success, Desfire.DesfireCardError.BoundaryError });
            }

            //  Read the whole record file with a single ReadRecords call.
            //eNRecordsRead = sizeof(abDataBuffer);
            //rc = desfire.ReadRecords( 6, bCommMode, 0, 0, 100, abDataBuffer, &eNRecordsRead );
            //Check(rc);

            //  Change the master key settings such that master key authentication will be required
            //  for all card operations.
            //  Leave the ChangeConfiguration bit (bit 3) set to allow undoing the change.
            rc = card.SelectApplication(0);
            Check(rc);
            rc = card.Authenticate(0, abCardMasterKey);
            Check(rc);

            if (doChangeMasterKey)
            {
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
                rc = card.CreateApplication(0xDDDDDD, 0xEF, 0);
                Check(rc, Desfire.DesfireCardError.AuthenticationError);

                //  With authentication all three should work.
                rc = card.Authenticate(0, abCardMasterKey);
                Check(rc);
                rc = card.GetApplicationIDs(out adwApplicationList);
                Check(rc);
                rc = card.DeleteApplication(0xCCCCCC);
                Check(rc);
                rc = card.CreateApplication(0xDDDDDD, 0xEF, 0);
                Check(rc);

                //  Change the master key settings back to the default which is least restrictive.
                rc = card.ChangeKeySettings(0xF);
                Check(rc);

                //  Change the Card master key back to the 0 key.
                rc = card.Authenticate(0, abCardMasterKey);
                Check(rc);
                rc = card.ChangeKey(0, NullKey_16, null);
                Check(rc);
            }

            //  Delete all demonstration data from the card.
            rc = card.Authenticate(0, NullKey_16);
            Check(rc);
            rc = card.FormatPICC();
            Check(rc);
        }
    }
}
