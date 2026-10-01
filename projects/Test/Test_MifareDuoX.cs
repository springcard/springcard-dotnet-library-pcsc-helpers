/*
 * SpringCard DESFire Library (C#)
 * Copyright (c) SpringCard SAS, 2008-2025
 *
 * This file is part of the SpringCard DESFire library.
 * See LICENSE.txt for license details and restrictions.
 *
 */
using System;
using System.Diagnostics;
using SpringCard.LibCs;
using SpringCard.PCSC.CardHelpers;
using static SpringCard.PCSC.CardHelpers.Desfire;

namespace SpringCard.PCSC.SelfTest
{
    partial class Program
    {
        readonly byte[] NullKey_32 = new byte[32];
        readonly byte[] AppBKeyMaster0_32 = StrUtils.ToBytes("App.B Master Key is now AES256!!");
        readonly byte[] TestKeyDes1K_32   = StrUtils.ToBytes("ABCDEFGHABCDEFGHABCDEFGHABCDEFGH");
        readonly byte[] AppBChangeKey_32  = StrUtils.ToBytes("B's Chg Keys Key is now AES256!!");
        readonly byte[] AppBKey1_32       = StrUtils.ToBytes("App.B Key #1.   .   .   .   .   ");
        readonly byte[] AppBKey2_32       = StrUtils.ToBytes("App.B Key #2..  ..  ..  ..  ..  ");
        readonly byte[] AppBKey3_32       = StrUtils.ToBytes("App.B Key #3... ... ... ... ... ");
        readonly byte[] AppBKey4_32       = StrUtils.ToBytes("App.B Key #4....................");
        readonly byte[] AppCKey1_32       = StrUtils.ToBytes("App.C Key #1.   .   .   .   .   ");
        readonly byte[] AppCKey2_32       = StrUtils.ToBytes("App.C Key #2..  ..  ..  ..  ..  ");

        #region ECC

        public void TestMifareDuoXEcc(MifareDuoX card)
        {
            byte[] CARootPriKeyNXP = BinConvert.HexToBytes("51711459434A0C68386C42B54B8A01E8546B037E2C1953BD6FA63DDF1E074B06");
            byte[] CARootPubKeyNXP = BinConvert.HexToBytes("04D00D763909DE8017376DF143124AB251D926B040E1173D04C62FE8C1ADA0F2BC20865E605C6971F3293DEEBD93019712BDF1AD1EEC5C9C39E25C7D05005B49F5");

            byte[] PiccLTPriKeyNXP = BinConvert.HexToBytes("50FF451C5824781D57755C5B02CB563F150644FA693235806625123717F05D28");
            byte[] PiccLTPubKeyNXP = BinConvert.HexToBytes("040889CA87F0E97C088C596F3F50EEC82D295549BB2B20956176F3B5B0B2EC5F8F559396958821F723A3C46684EC2B9BDB74D4F3B69D3F8F195EB0E9C8CA911836");
            byte[] PiccCertificateNXPWithPrefix = BinConvert.HexToBytes("470100308201433081EAA003020102020ACCCCCCCCCCCCCCCCCCCC300A06082A8648CE3D040302301B31193017060355040A0C10CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC3022180F31393730303130313030303030305A180F39393939313233313233353935395A302F31143012060355042D030B00CCCCCCCCCCCCCCCCCCCC31173015060355040D0C0ECCCCCCCCCCCCCCCCCCCCCCCCCCCC3059301306072A8648CE3D020106082A8648CE3D030107034200040889CA87F0E97C088C596F3F50EEC82D295549BB2B20956176F3B5B0B2EC5F8F559396958821F723A3C46684EC2B9BDB74D4F3B69D3F8F195EB0E9C8CA911836300A06082A8648CE3D0403010348003045022037DCF93C46E012AC2D14738D04BB3D71BC7DDCE85DDA3A23AA2F3F31C25340A402210082389BEC11BCB0EC560D6C8AB601183E5F800E7BD50E68185B3BE60665335EC3");

            byte[] PcdLTPriKeyNXP = BinConvert.HexToBytes("C28276FC8DB6CF1040B635E3E5BACCE0EFA32FAA03C812B340916BB306CC2972");
            byte[] PcdCertificateNXP = BinConvert.HexToBytes("308201283081D0A00302010202040102BD16300A06082A8648CE3D0403023020311E301C060355042D0315003F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F301E170D3231303230333231313534305A170D3235313230383231313534305A301A31183016060355042D030F0072656164657220656E646C6561663059301306072A8648CE3D020106082A8648CE3D030107034200040C5E10F8F81588695F1B05707FB8F0BA69F70026D9159B04C69255EA486DEE331FFE6A17AE8DB65F4A13801CD744726255D1F0C2B20506DCEE1479E885C3C394300A06082A8648CE3D040302034700304402200873D566987981257752DA7930B68BEFD39BE17118ED3217AC421B1B06BF2D6602206E2A840D42D3F1A19453E5894B6A36DC56298BEE504416F72970A55CDEA28153");
            byte[] PcdEPriKeyNXP = BinConvert.HexToBytes("00D7E7F70C7F1EB3AFCD9A27A98463C84C2A4FFD2177D5A5C4378F9B27AD489376");

            byte[] CardUid;
            DesfireVersionInfo VersionInfo;
            uint FreeBytes;
            byte KeyVersion;
            byte KeySettings;
            byte KeyCount;
            uint[] ApplicationList;

            Stopwatch bench;
            long rc;

            //  After activating a DesFire card the currently selected 'application' is the card
            //  iTestMode (AID = 0). Therefore the next command is redundant.
            //  We use the command to check that the card is responding correctly.
            rc = card.SelectApplication(0);
            Check(rc);

            rc = card.GetFreeMemory(out FreeBytes);
            Check(rc);

            //  Which Card Master Key is currently in use ?
            //  Beginning with DesFire version 0.1 the GetKeyVersion command can help determining
            //  which key is currently effective.
            rc = card.GetKeyVersion(0, out KeyVersion);
            Check(rc);
            logger.trace("Master Key Version is {0:X02}", KeyVersion);

            //  Authenticate with the key which corresponds to the retieved key version.
            if (KeyVersion == 0)
            {
                rc = card.AuthenticateEV2First(0, NullKey_16);
                Check(rc);
            }
            else if (KeyVersion == 0xAE)
            {
                rc = card.AuthenticateEV2First(0, RootKey2K);
                Check(rc);
                rc = card.ChangeKey((byte)Desfire.DesfireKeyType.AES128, 0x00, NullKey_16, RootKey2K);
                Check(rc);
            }
            else
            {
                //  Who knows the key ?
                Console.WriteLine("Sorry, the master key is unknown (version = {0:X02})", KeyVersion);
                return;
            }

            if (doChangeMasterKey)
            {
                if (KeyVersion != 0)
                {
                    //  Back to default (null) key
                    rc = card.ChangeKey(0, 0, NullKey_16, null);
                    Check(rc);
                }

                //  Authenticate again
                rc = card.AuthenticateEV2First(0, NullKey_16);
                Check(rc);

                //  Try to allow to change the key
                rc = card.ChangeKeySettings(0xF);
                Check(rc);
            }

            //  List the existing applications
            rc = card.GetApplicationIDs(out ApplicationList);
            Check(rc);

            if (ApplicationList.Length > 0)
            {
                //  Startup with a blank card !!!
                rc = card.FormatPICC();
                Check(rc);
            }

            //  Authenticate again
            rc = card.AuthenticateEV2First(0, NullKey_16);
            Check(rc);

            // Get the UID of the card
            rc = card.GetCardUID(out CardUid);
            Check(rc);
            Console.WriteLine();
            Console.WriteLine("UID: {0}", BinConvert.ToHex(CardUid));

            // Get the UID of the card again (to verify the IV) */
            rc = card.GetCardUID(out CardUid);
            Check(rc);

            //  Authenticate again
            rc = card.AuthenticateEV2NonFirst(0, NullKey_16);
            Check(rc);

            //  Authenticate again
            rc = card.AuthenticateEV2NonFirst(0, NullKey_16);
            Check(rc);

            if (doChangeMasterKey)
            {
                rc = card.GetKeyVersion(0, out KeyVersion);
                Check(rc);

                rc = card.ChangeKey((byte)Desfire.DesfireKeyType.AES128, 0xAE, RootKey2K, null);
                Check(rc);
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

            rc = card.GetFreeMemory(out FreeBytes);
            Check(rc);

            rc = card.GetKeyVersion(0, out KeyVersion);
            Check(rc);
            rc = card.GetKeyVersion(0, out KeyVersion);
            Check(rc);

            if (doChangeMasterKey)
            {
                rc = card.AuthenticateEV2First(0, RootKey2K);
                Check(rc);
            }

            rc = card.GetKeySettings(out KeySettings, out KeyCount);
            Check(rc);

            rc = card.GetFreeMemory(out FreeBytes);
            Check(rc);

            //  At this point we would like to begin with a blank card.
            rc = card.FormatPICC();
            Check(rc);

            rc = card.GetFreeMemory(out FreeBytes);
            Check(rc);

            /* NXP AN14215 § 4.1.5.1 */
            /* --------------------- */

            rc = card.CreateApplication(0x332211, 0xEF, 0x82);
            Check(rc);

            rc = card.GetApplicationIDs(out ApplicationList);
            Check(rc);

            rc = card.SelectApplication(0x332211);
            Check(rc);

            bench = Stopwatch.StartNew();
            rc = card.AuthenticateEV2First(0, NullKey_16);
            bench.Stop();
            Check(rc);
            Console.WriteLine($"\nAuthenticateEV2First: {bench.ElapsedMilliseconds}ms");

            /* Insert NXP test data in the card under number 0 */
            /* ----------------------------------------------- */

            rc = card.ImportPrivateKey(0x00,
                MifareDuoXEccCurve.NistP256,
                MifareDuoXKeyPairPolicy.PiccAuth | MifareDuoXKeyPairPolicy.MutualAuth | MifareDuoXKeyPairPolicy.Sign,
                MifareDuoXAccessRights.Create(0,
                DesfireCommMode.Full),
                100,
                PiccLTPriKeyNXP);
            Check(rc);

            rc = card.ManageCARootKey(0x00,
                MifareDuoXEccCurve.NistP256,
                MifareDuoXCARootKeyAccessRights.Create(0x0003),
                MifareDuoXAccessRights.Create(0, DesfireCommMode.Full),
                MifareDuoXAccessRights.Create(0xE, DesfireCommMode.Plain),
                CARootPubKeyNXP,
                DesfireCommMode.Full);
            Check(rc);

            rc = card.CreateStdDataFile(0x00, (byte)DesfireCommMode.Plain, 0xEEEE, 0x00300);
            Check(rc);

            rc = card.WriteData(0x00, (byte)DesfireCommMode.Plain, PiccCertificateNXPWithPrefix);
            Check(rc);

            /* Insert NXP test data in the card under number 1 */
            /* ----------------------------------------------- */

            rc = card.ImportPrivateKey(0x01,
                MifareDuoXEccCurve.NistP256,
                MifareDuoXKeyPairPolicy.PiccAuth | MifareDuoXKeyPairPolicy.MutualAuth | MifareDuoXKeyPairPolicy.Sign,
                MifareDuoXAccessRights.Create(0, DesfireCommMode.Full),
                10000,
                PiccLTPriKeyNXP);
            Check(rc);

            rc = card.ManageCARootKey(0x01,
                MifareDuoXEccCurve.NistP256,
                MifareDuoXCARootKeyAccessRights.Create(0x0003),
                MifareDuoXAccessRights.Create(0, DesfireCommMode.Full),
                MifareDuoXAccessRights.Create(0xE, DesfireCommMode.Full),
                CARootPubKeyNXP, DesfireCommMode.Full);
            Check(rc);

            rc = card.CreateStdDataFile(0x01, (byte)DesfireCommMode.Plain, 0xEEEE, 0x00300);
            Check(rc);

            rc = card.WriteData(0x01, (byte)DesfireCommMode.Plain, PiccCertificateNXPWithPrefix);
            Check(rc);

            /* Testing IsoGeneralAuthenticate, step by step */
            /* -------------------------------------------- */

            byte[] PcdOptions = new byte[] { 0x80, 0x00, 0x00, 0x00 };

            ECC.PrivateToPublic(MifareDuoXEccCurve.NistP256, PcdEPriKeyNXP, out byte[] PcdTempPubKey);

            rc = card.IsoGeneralAuthenticatePart1(0x00, PcdOptions, PcdTempPubKey, out byte[] PiccTempPubKey);
            Check(rc);

            rc = card.IsoGeneralAuthenticateInitSession(MifareDuoXEccCurve.NistP256, PcdOptions, PcdEPriKeyNXP, PiccTempPubKey, PcdLTPriKeyNXP, PcdCertificateNXP, out byte[] PcdMessage);
            Check(rc);

            rc = card.IsoGeneralAuthenticatePart2(PcdMessage, out byte[] PiccMessage);
            Check(rc);

            rc = card.IsoGeneralAuthenticateConfirmSession(MifareDuoXEccCurve.NistP256, PcdTempPubKey, PiccTempPubKey, null, PiccMessage, out byte[] PiccOptions, out byte[] PiccCertificate);
            Check(rc);

            rc = card.SelectApplication(0);
            Check(rc);
            rc = card.SelectApplication(0x332211);
            Check(rc);

            /* Testing IsoGeneralAuthenticateReader, with PcdCertificate, and fixed test keys */
            /* ------------------------------------------------------------------------------ */

            bench = Stopwatch.StartNew();
            rc = card.IsoGeneralAuthenticateReader(MifareDuoXEccCurve.NistP256, 0, PcdLTPriKeyNXP, PcdCertificateNXP, out PiccOptions);
            bench.Stop();
            Check(rc);
            Console.WriteLine($"\nIsoGeneralAuthenticateReader: {bench.ElapsedMilliseconds}ms");

            rc = card.SelectApplication(0x332211);
            Check(rc);

            /* Testing IsoGeneralAuthenticateMutual, with PcdCertificate, and fixed test keys */
            /* ------------------------------------------------------------------------------ */

            bench = Stopwatch.StartNew();
            rc = card.IsoGeneralAuthenticateMutual(MifareDuoXEccCurve.NistP256, 0, PcdLTPriKeyNXP, PcdCertificateNXP, 0, 0, out PiccOptions, out byte[] PiccCertificateRead);
            bench.Stop();
            Check(rc);
            Console.WriteLine($"\nIsoGeneralAuthenticateMutual: {bench.ElapsedMilliseconds}ms");

            rc = card.SelectApplication(0x332211);
            Check(rc);

            /* Testing IsoGeneralAuthenticateReader, without PcdCertificate, and fixed test keys */
            /* --------------------------------------------------------------------------------- */

            rc = card.IsoGeneralAuthenticateReader(MifareDuoXEccCurve.NistP256, 0, CARootPriKeyNXP, out PiccOptions);
            Check(rc);

            rc = card.SelectApplication(0x332211);
            Check(rc);

            /* Testing IsoGeneralAuthenticateMutual, without PcdCertificate, and fixed test keys */
            /* --------------------------------------------------------------------------------- */

            rc = card.IsoGeneralAuthenticateMutual(MifareDuoXEccCurve.NistP256, 0, CARootPriKeyNXP, 0, 0, out PiccOptions, out PiccCertificateRead);
            Check(rc);

            rc = card.SelectApplication(0x332211);
            Check(rc);

            rc = card.GetCardUID(out CardUid);
            Check(rc);
            rc = card.GetCardUID(out CardUid);
            Check(rc);
            rc = card.GetVersion(out VersionInfo);
            Check(rc);

            rc = card.SelectApplication(0x332211);
            Check(rc);

            /* Testing IsoInternalAuthenticate with fixed test keys */
            /* ---------------------------------------------------- */

            rc = card.IsoInternalAuthenticate(MifareDuoXEccCurve.NistP256, 0, null, PiccLTPubKeyNXP);
            Check(rc);
            rc = card.IsoInternalAuthenticate(MifareDuoXEccCurve.NistP256, 0, new byte[] { 0x16, 0x05, 0x19, 0x74, 0xAB, 0xCD }, PiccLTPubKeyNXP);
            Check(rc);

            rc = card.SelectApplication(0x332211);
            Check(rc);

            for (int i = 0; i < 4; i++)
            {

                /* Testing IsoGeneralAuthenticate again with fixed test keys, but at index 1 instead of 0 */
                /* -------------------------------------------------------------------------------------- */

                rc = card.IsoGeneralAuthenticateReader(MifareDuoXEccCurve.NistP256, 1, PcdLTPriKeyNXP, PcdCertificateNXP, out PiccOptions);
                Check(rc);

                rc = card.SelectApplication(0x332211);
                Check(rc);

                rc = card.IsoGeneralAuthenticateMutual(MifareDuoXEccCurve.NistP256, 1, PcdLTPriKeyNXP, PcdCertificateNXP, 1, 1, out PiccOptions, out PiccCertificateRead);
                Check(rc);

                rc = card.SelectApplication(0x332211);
                Check(rc);

                rc = card.IsoGeneralAuthenticateReader(MifareDuoXEccCurve.NistP256, 1, CARootPriKeyNXP, out PiccOptions);
                Check(rc);

                rc = card.SelectApplication(0x332211);
                Check(rc);

                rc = card.IsoGeneralAuthenticateMutual(MifareDuoXEccCurve.NistP256, 1, CARootPriKeyNXP, 1, 1, out PiccOptions, out PiccCertificateRead);
                Check(rc);

                rc = card.SelectApplication(0x332211);
                Check(rc);

                /* Testing IsoGeneralAuthenticate again with fixed test keys, but at index 1 instead of 0 */
                /* -------------------------------------------------------------------------------------- */

                rc = card.IsoInternalAuthenticate(MifareDuoXEccCurve.NistP256, 1, null, PiccLTPubKeyNXP);
                Check(rc);
                rc = card.IsoInternalAuthenticate(MifareDuoXEccCurve.NistP256, 1, new byte[] { 0x16, 0x05, 0x19, 0x74, 0xAB, 0xCD }, PiccLTPubKeyNXP);
                Check(rc);

                rc = card.SelectApplication(0x332211);
                Check(rc);
            }

            /* Rewrite the private key at index 1 and the certificate */
            /* ------------------------------------------------------ */

            rc = card.IsoGeneralAuthenticateMutual(MifareDuoXEccCurve.NistP256, 1, PcdLTPriKeyNXP, PcdCertificateNXP, 1, 1, out PiccOptions, out PiccCertificateRead);
            Check(rc);

            rc = card.ImportPrivateKey(0x01,
                MifareDuoXEccCurve.NistP256,
                MifareDuoXKeyPairPolicy.PiccAuth | MifareDuoXKeyPairPolicy.MutualAuth | MifareDuoXKeyPairPolicy.Sign,
                MifareDuoXAccessRights.Create(0, DesfireCommMode.Full),
                100000,
                PiccLTPriKeyNXP);
            Check(rc);

            rc = card.WriteData(0x01, (byte)DesfireCommMode.Plain, PiccCertificateNXPWithPrefix);
            Check(rc);

            rc = card.SelectApplication(0x332211);
            Check(rc);

            /* Testing IsoGeneralAuthenticate again with fixed test keys at index 1 */
            /* -------------------------------------------------------------------- */

            rc = card.IsoGeneralAuthenticateReader(MifareDuoXEccCurve.NistP256, 1, PcdLTPriKeyNXP, PcdCertificateNXP, out PiccOptions);
            Check(rc);

            rc = card.SelectApplication(0x332211);
            Check(rc);

            rc = card.IsoGeneralAuthenticateMutual(MifareDuoXEccCurve.NistP256, 1, PcdLTPriKeyNXP, PcdCertificateNXP, 1, 1, out PiccOptions, out PiccCertificateRead);
            Check(rc);

            rc = card.SelectApplication(0x332211);
            Check(rc);

            rc = card.IsoGeneralAuthenticateReader(MifareDuoXEccCurve.NistP256, 1, CARootPriKeyNXP, out PiccOptions);
            Check(rc);

            rc = card.SelectApplication(0x332211);
            Check(rc);

            rc = card.IsoGeneralAuthenticateMutual(MifareDuoXEccCurve.NistP256, 1, CARootPriKeyNXP, 1, 1, out PiccOptions, out PiccCertificateRead);
            Check(rc);

            rc = card.SelectApplication(0x332211);
            Check(rc);

            /* Testing IsoGeneralAuthenticate again with fixed test keys, at index 1 */
            /* --------------------------------------------------------------------- */

            rc = card.IsoInternalAuthenticate(MifareDuoXEccCurve.NistP256, 1, null, PiccLTPubKeyNXP);
            Check(rc);
            rc = card.IsoInternalAuthenticate(MifareDuoXEccCurve.NistP256, 1, new byte[] { 0x16, 0x05, 0x19, 0x74, 0xAB, 0xCD }, PiccLTPubKeyNXP);
            Check(rc);

            rc = card.SelectApplication(0x332211);
            Check(rc);

            /* Testing IsoGeneralAuthenticate again with PICC fixed test keys at index 1, but this time using a Test key for the PCD */
            /* --------------------------------------------------------------------------------------------------------------------- */

            for (int i = 0; i < 4; i++)
            {
                ECC.GenerateKeyPair(MifareDuoXEccCurve.NistP256, out byte[] PcdLTPriKeyTest, out byte[] PcdLTPubKeyTest);
                byte[] PcdCertificateTest = X509CERT.Create(MifareDuoXEccCurve.NistP256, "TEST PCD", PcdLTPubKeyTest, "NXP", CARootPriKeyNXP);

                if (!X509CERT.Verify(PcdCertificateTest, MifareDuoXEccCurve.NistP256, CARootPubKeyNXP))
                    throw new Exception("Certificate generation failed");

                rc = card.IsoGeneralAuthenticateReader(MifareDuoXEccCurve.NistP256, 1, PcdLTPriKeyTest, PcdCertificateTest, out PiccOptions);
                if (rc != 0)
                {
                    logger.info("Retry");
                    rc = card.IsoGeneralAuthenticateReader(MifareDuoXEccCurve.NistP256, 1, PcdLTPriKeyTest, PcdCertificateTest, out PiccOptions);
                }
                Check(rc);

                rc = card.SelectApplication(0x332211);
                Check(rc);

                rc = card.IsoGeneralAuthenticateMutual(MifareDuoXEccCurve.NistP256, 1, PcdLTPriKeyTest, PcdCertificateTest, 1, 1, out PiccOptions, out PiccCertificateRead);
                Check(rc);

                rc = card.SelectApplication(0x332211);
                Check(rc);

                rc = card.IsoGeneralAuthenticateReader(MifareDuoXEccCurve.NistP256, 1, CARootPriKeyNXP, out PiccOptions);
                Check(rc);

                rc = card.SelectApplication(0x332211);
                Check(rc);

                rc = card.IsoGeneralAuthenticateMutual(MifareDuoXEccCurve.NistP256, 1, CARootPriKeyNXP, 1, 1, out PiccOptions, out PiccCertificateRead);
                Check(rc);

                rc = card.SelectApplication(0x332211);
                Check(rc);
            }

            /* Testing IsoGeneralAuthenticate again with PICC fixed test keys at index 1, but this time using a Test key for the PCD and a chained certificate */
            /* ----------------------------------------------------------------------------------------------------------------------------------------------- */

            for (int i = 0; i < 4; i++)
            {
                ECC.GenerateKeyPair(MifareDuoXEccCurve.NistP256, out byte[] CAPriKeyTest1, out byte[] CAPubKeyTest1);
                byte[] CACertificateTest1 = X509CERT.Create(MifareDuoXEccCurve.NistP256, "TEST CA", CAPubKeyTest1, "NXP", CARootPriKeyNXP);

                if (!X509CERT.Verify(CACertificateTest1, MifareDuoXEccCurve.NistP256, CARootPubKeyNXP))
                    throw new Exception("Certificate generation failed");

                ECC.GenerateKeyPair(MifareDuoXEccCurve.NistP256, out byte[] PcdLTPriKeyTest1, out byte[] PcdLTPubKeyTest1);
                byte[] PcdCertificateTest1 = X509CERT.Create(MifareDuoXEccCurve.NistP256, "TEST PCD", PcdLTPubKeyTest1, "TEST CA", CAPriKeyTest1);

                if (!X509CERT.Verify(PcdCertificateTest1, MifareDuoXEccCurve.NistP256, CAPubKeyTest1))
                    throw new Exception("Certificate generation failed");

                /* For MifareDuoX, the certificate chain is in reverse order!!! CertA = CertA.Parent (CA) || CertA.Leaf (Reader) */
                byte[] ChainedCertificates1 = X509CERT.Chain(CACertificateTest1, PcdCertificateTest1);

                rc = card.IsoGeneralAuthenticateReader(MifareDuoXEccCurve.NistP256, 1, PcdLTPriKeyTest1, ChainedCertificates1, out PiccOptions);
                Check(rc);

                rc = card.SelectApplication(0x332211);
                Check(rc);

                rc = card.IsoGeneralAuthenticateMutual(MifareDuoXEccCurve.NistP256, 1, PcdLTPriKeyTest1, ChainedCertificates1, 1, 1, out PiccOptions, out PiccCertificateRead);
                Check(rc);

                rc = card.SelectApplication(0x332211);
                Check(rc);

                rc = card.IsoGeneralAuthenticateReader(MifareDuoXEccCurve.NistP256, 1, CARootPriKeyNXP, out PiccOptions);
                Check(rc);

                rc = card.SelectApplication(0x332211);
                Check(rc);

                rc = card.IsoGeneralAuthenticateMutual(MifareDuoXEccCurve.NistP256, 1, CARootPriKeyNXP, 1, 1, out PiccOptions, out PiccCertificateRead);
                Check(rc);

                rc = card.SelectApplication(0x332211);
                Check(rc);
            }

            /* Generate a new private key at index 1 and a new PICC certificate with NXP CA */
            /* ---------------------------------------------------------------------------- */

            rc = card.IsoGeneralAuthenticateMutual(MifareDuoXEccCurve.NistP256, 1, PcdLTPriKeyNXP, PcdCertificateNXP, 1, 1, out PiccOptions, out PiccCertificateRead);
            Check(rc);

            rc = card.GenerateKeyPair(0x01,
                MifareDuoXEccCurve.NistP256,
                MifareDuoXKeyPairPolicy.PiccAuth | MifareDuoXKeyPairPolicy.MutualAuth | MifareDuoXKeyPairPolicy.Sign,
                MifareDuoXAccessRights.Create(1, DesfireCommMode.Full),
                100,
                out byte[] PiccLTPubKeyTest1);
            Check(rc);

            byte[] PiccCertificateNXPNew = X509CERT.Create(MifareDuoXEccCurve.NistP256, "TEST PICC", PiccLTPubKeyTest1, "NXP", CARootPriKeyNXP);
            rc = card.WriteData(0x01, (byte)DesfireCommMode.Plain, X509CERT.AddDataFilePrefix(PiccCertificateNXPNew));
            Check(rc);

            rc = card.SelectApplication(0x332211);
            Check(rc);

            /* Generate a new private key at index 2 and a new PICC certificate with a test CA */
            /* ------------------------------------------------------------------------------- */

            ECC.GenerateKeyPair(MifareDuoXEccCurve.NistP256, out byte[] CARootPriKeyTest2, out byte[] CARootPubKeyTest2);
            ECC.GenerateKeyPair(MifareDuoXEccCurve.NistP256, out byte[] CAPriKeyTest2, out byte[] CAPubKeyTest2);
            byte[] CACertificateTest2 = X509CERT.Create(MifareDuoXEccCurve.NistP256, "TEST CA", CAPubKeyTest2, "ROOT CA", CARootPriKeyTest2);

            rc = card.AuthenticateEV2First(0, NullKey_16);
            Check(rc);

            rc = card.CreateStdDataFile(0x02, (byte)DesfireCommMode.Plain, 0xEEEE, 0x00300);
            Check(rc);

            rc = card.GenerateKeyPair(0x02,
                MifareDuoXEccCurve.NistP256,
                MifareDuoXKeyPairPolicy.PiccAuth | MifareDuoXKeyPairPolicy.MutualAuth,
                MifareDuoXAccessRights.Create(2, DesfireCommMode.Full),
                1000,
                out byte[] PiccLTPubKeyTest2);
            Check(rc);

            rc = card.ManageCARootKey(0x02,
                MifareDuoXEccCurve.NistP256,
                MifareDuoXCARootKeyAccessRights.Create(0x0003),
                MifareDuoXAccessRights.Create(0, DesfireCommMode.Maced),
                MifareDuoXAccessRights.Create(0, DesfireCommMode.Maced),
                CARootPubKeyTest2,
                DesfireCommMode.Full);
            Check(rc);

            rc = card.SelectApplication(0x332211);
            Check(rc);

            /* Generate a new private key at index 3 and a new PICC certificate with a test CA */
            /* ------------------------------------------------------------------------------- */

            ECC.GenerateKeyPair(MifareDuoXEccCurve.NistP256, out byte[] CARootPriKeyTest3, out byte[] CARootPubKeyTest3);
            ECC.GenerateKeyPair(MifareDuoXEccCurve.NistP256, out byte[] CAPriKeyTest3, out byte[] CAPubKeyTest3);
            byte[] CACertificateTest3 = X509CERT.Create(MifareDuoXEccCurve.NistP256, "TEST CA", CAPubKeyTest3, "ROOT CA", CARootPriKeyTest3);

            rc = card.AuthenticateEV2First(0, NullKey_16);
            Check(rc);

            rc = card.CreateStdDataFile(0x03, (byte)DesfireCommMode.Plain, 0xEEEE, 0x00300);
            Check(rc);

            rc = card.GenerateKeyPair(0x03,
                MifareDuoXEccCurve.NistP256,
                MifareDuoXKeyPairPolicy.PiccAuth | MifareDuoXKeyPairPolicy.MutualAuth,
                MifareDuoXAccessRights.Create(3, DesfireCommMode.Full),
                100000,
                out byte[] PiccLTPubKeyTest3);
            Check(rc);

            rc = card.ManageCARootKey(0x03,
                MifareDuoXEccCurve.NistP256,
                MifareDuoXCARootKeyAccessRights.Create(0x0003),
                MifareDuoXAccessRights.Create(0, DesfireCommMode.Full),
                MifareDuoXAccessRights.Create(0, DesfireCommMode.Full),
                CARootPubKeyTest3,
                DesfireCommMode.Full);
            Check(rc);

            rc = card.SelectApplication(0x332211);
            Check(rc);

            /* List CA keys */
            /* ------------ */
            rc = card.GetCARootKeyList(out DesfireCARootKeyInfo[] CARootKeyList);
            Check(rc);

            Console.WriteLine();
            foreach (DesfireCARootKeyInfo CARootKeyInfo in CARootKeyList)
                Console.WriteLine(CARootKeyInfo.ToString());

            foreach (DesfireCARootKeyInfo CARootKeyInfo in CARootKeyList)
            {
                if (CARootKeyInfo.ReadKeyNo != 0x0E)
                    break;

                rc = card.ReadCARootPublicKey(CARootKeyInfo.KeyNumber, DesfireCommMode.Plain, out byte[] PublicKey);
                if (rc != 0)
                    Check(rc);
            }

            rc = card.AuthenticateEV2First(0, NullKey_16);
            Check(rc);

            foreach (DesfireCARootKeyInfo CARootKeyInfo in CARootKeyList)
            {
                rc = card.ReadCARootPublicKey(CARootKeyInfo.KeyNumber, CARootKeyInfo.ReadCommMode, out byte[] PublicKey);
                if (rc != 0)
                    Check(rc);

                rc = card.ReadCARootPublicKey(CARootKeyInfo.KeyNumber, CARootKeyInfo.ReadCommMode, out PublicKey);
                if (rc != 0)
                    Check(rc);
            }

            foreach (DesfireCARootKeyInfo CARootKeyInfo in CARootKeyList)
            {
                rc = card.ReadCARootPublicKey(CARootKeyInfo.KeyNumber, CARootKeyInfo.ReadCommMode, out byte[] PublicKey);
                if (rc != 0)
                    Check(rc);

                rc = card.ReadCARootPublicKey(CARootKeyInfo.KeyNumber, CARootKeyInfo.ReadCommMode, out PublicKey);
                if (rc != 0)
                    Check(rc);

                Console.WriteLine(string.Format("{0:X02} {1}", CARootKeyInfo.KeyNumber, BinConvert.ToHex(PublicKey)));
            }

            /* List private keys */
            /* ----------------- */
            rc = card.GetPrivateKeyList(out DesfirePrivateKeyInfo[] PrivateKeyList);
            Check(rc);

            Console.WriteLine();
            foreach (DesfirePrivateKeyInfo PrivateKeyInfo in PrivateKeyList)
                Console.WriteLine(PrivateKeyInfo.ToString());

            /* Change key settings */
            /* ------------------- */

            rc = card.UpdateKeyPairMetaData(0x00, (byte)MifareDuoXEccCurve.NistP256, 0x0180, 0x00, 0);
            rc = card.UpdateKeyPairMetaData(0x01, (byte)MifareDuoXEccCurve.NistP256, 0x0180, 0x00, 0);
            rc = card.UpdateKeyPairMetaData(0x02, (byte)MifareDuoXEccCurve.NistP256, 0x0180, 0x00, 0);
            rc = card.UpdateKeyPairMetaData(0x03, (byte)MifareDuoXEccCurve.NistP256, 0x0180, 0x00, 0);

            /* Testing IsoGeneralAuthenticate again with fixed test keys at index 1 */
            /* -------------------------------------------------------------------- */

            rc = card.IsoGeneralAuthenticateReader(MifareDuoXEccCurve.NistP256, 1, PcdLTPriKeyNXP, PcdCertificateNXP, out PiccOptions);
            Check(rc);

            rc = card.SelectApplication(0x332211);
            Check(rc);

            rc = card.IsoGeneralAuthenticateMutual(MifareDuoXEccCurve.NistP256, 1, PcdLTPriKeyNXP, PcdCertificateNXP, 1, 1, out PiccOptions, out PiccCertificateRead);
            Check(rc);

            rc = card.SelectApplication(0x332211);
            Check(rc);

            rc = card.IsoGeneralAuthenticateReader(MifareDuoXEccCurve.NistP256, 1, CARootPriKeyNXP, out PiccOptions);
            Check(rc);

            rc = card.SelectApplication(0x332211);
            Check(rc);

            rc = card.IsoGeneralAuthenticateMutual(MifareDuoXEccCurve.NistP256, 1, CARootPriKeyNXP, 1, 1, out PiccOptions, out PiccCertificateRead);
            Check(rc);

            rc = card.SelectApplication(0x332211);
            Check(rc);

            /* Testing IsoGeneralAuthenticate again with fixed test keys, at index 1 */
            /* --------------------------------------------------------------------- */

            rc = card.IsoInternalAuthenticate(MifareDuoXEccCurve.NistP256, 1, null, PiccLTPubKeyTest1);
            Check(rc);
            rc = card.IsoInternalAuthenticate(MifareDuoXEccCurve.NistP256, 1, new byte[] { 0x16, 0x05, 0x19, 0x74, 0xAB, 0xCD }, PiccLTPubKeyTest1);
            Check(rc);

            rc = card.SelectApplication(0x332211);
            Check(rc);


            rc = card.SelectApplication(0);
            Check(rc);

            //rc = card.IsoInternalAuthenticate(MifareDuoXEccCurve.NistP256, 0, null, out byte[] Challenge, out byte[] PiccSignature);
            //Check(rc);

            rc = card.IsoInternalAuthenticate(MifareDuoXEccCurve.NistP256, 1, null, out byte[] Challenge, out byte[] PiccSignature);
            Check(rc);

            if (doChangeMasterKey)
            {
                rc = card.AuthenticateEV2First(0, RootKey2K);
                Check(rc);

                rc = card.ChangeKeySettings(0x8);
                Check(rc);

                rc = card.SelectApplication(0);
                Check(rc);

            }
            else
            {
                rc = card.AuthenticateEV2First(0, NullKey_16);
                Check(rc);
            }

            if (doChangeMasterKey)
            {
                //  Change the master key settings back to the default which is least restrictive.
                rc = card.ChangeKeySettings(0xF);
                Check(rc);

                //  Change the Card master key back to the 0 key.
                rc = card.AuthenticateEV2First(0, RootKey2K);
                Check(rc);

                rc = card.ChangeKey(0, 0, NullKey_16, null);
                Check(rc);

                rc = card.AuthenticateEV2First(0, NullKey_16);
                Check(rc);
            }
            else
            {
                rc = card.AuthenticateEV2First(0, NullKey_16);
                Check(rc);
            }

            rc = card.GetFreeMemory(out FreeBytes);
            Check(rc);

            //  Delete all demonstration data from the card.
            rc = card.FormatPICC();
            Check(rc);

            rc = card.GetFreeMemory(out FreeBytes);
            Check(rc);
        }

        #endregion

        public void TestMifareDuoXAes(MifareDuoX card, bool aes256)
        {
            byte[] CardUid;
            DesfireVersionInfo VersionInfo;
            uint FreeBytes;
            byte KeyVersion;
            byte KeySettings;
            byte KeyCount;

            uint[] ApplicationList;
            byte[] FileList;

            byte[] DataBuffer;
            int NRecordsRead;
            byte FileType;
            byte CommMode;
            int Transaction;
            ushort AccessRights;
            DesfireFileSettings FileSettings;

            byte KeyType;

            byte[] NullKey = null;
            byte[] AppBKeyMaster0 = null;
            byte[] TestKeyDes1K = null;
            byte[] AppBChangeKey = null;
            byte[] AppBKey1 = null;
            byte[] AppBKey2 = null;
            byte[] AppBKey3 = null;
            byte[] AppBKey4 = null;
            byte[] AppCKey1 = null;
            byte[] AppCKey2 = null;

            Stopwatch bench;

            long rc;

            if (aes256)
            {
                KeyType = 0xC0;
                NullKey = NullKey_32;
                AppBKeyMaster0 = AppBKeyMaster0_32;
                TestKeyDes1K = TestKeyDes1K_32;
                AppBChangeKey = AppBChangeKey_32;
                AppBKey1 = AppBKey1_32;
                AppBKey2 = AppBKey2_32;
                AppBKey3 = AppBKey3_32;
                AppBKey4 = AppBKey4_32;
                AppCKey1 = AppCKey1_32;
                AppCKey2 = AppCKey2_32;
            }
            else
            {
                KeyType = 0x80;
                NullKey = NullKey_16;
                AppBKeyMaster0 = AppBKeyMaster0_16;
                TestKeyDes1K = TestKeyDes1K_16;
                AppBChangeKey = AppBChangeKey_16;
                AppBKey1 = AppBKey1_16;
                AppBKey2 = AppBKey2_16;
                AppBKey3 = AppBKey3_16;
                AppBKey4 = AppBKey4_16;
                AppCKey1 = AppCKey1_16;
                AppCKey2 = AppCKey2_16;
            }

            logger.debug("TestMifareDuoXAes({0:X02}) {1}", KeyType, BinConvert.ToHex(NullKey));

            //  After activating a DesFire card the currently selected 'application' is the card
            //  iTestMode (AID = 0). Therefore the next command is redundant.
            //  We use the command to check that the card is responding correctly.
            rc = card.SelectApplication(0);
            Check(rc);

            rc = card.GetFreeMemory(out FreeBytes);
            Check(rc);

            //  Which Card Master Key is currently in use ?
            //  Beginning with DesFire version 0.1 the GetKeyVersion command can help determining
            //  which key is currently effective.
            rc = card.GetKeyVersion(0, out KeyVersion);
            Check(rc);
            logger.trace("Master Key Version is {0:X02}", KeyVersion);

            //  Authenticate with the key which corresponds to the retieved key version.
            if (KeyVersion == 0)
            {
                rc = card.AuthenticateEV2First(0, NullKey_16);
                Check(rc);
            }
            else if (KeyVersion == 0xAE)
            {
                rc = card.AuthenticateEV2First(0, RootKey2K);
                Check(rc);
                rc = card.ChangeKey((byte)Desfire.DesfireKeyType.AES128, 0x00, NullKey_16, RootKey2K);
                Check(rc);
            }
            else
            {
                //  Who knows the key ?
                Console.WriteLine("Sorry, the master key is unknown (version = {0:X02})", KeyVersion);
                return;
            }

            if (doChangeMasterKey)
            {
                if (KeyVersion != 0)
                {
                    //  Back to default (null) key
                    rc = card.ChangeKey(0, 0, NullKey_16, null);
                    Check(rc);
                }

                //  Authenticate again
                rc = card.AuthenticateEV2First(0, NullKey_16);
                Check(rc);

                //  Try to allow to change the key
                rc = card.ChangeKeySettings(0xF);
                Check(rc);
            }

            //  List the existing applications
            rc = card.GetApplicationIDs(out ApplicationList);
            Check(rc);

            if (ApplicationList.Length > 0)
            {
                //  Startup with a blank card !!!
                rc = card.FormatPICC();
                Check(rc);
            }

            //  Authenticate again
            rc = card.AuthenticateEV2First(0, NullKey_16);
            Check(rc);

            // Get the UID of the card
            rc = card.GetCardUID(out CardUid);
            Check(rc);
            Console.WriteLine();
            Console.WriteLine("UID: {0}", BinConvert.ToHex(CardUid));

            // Get the UID of the card again (to verify the IV) */
            rc = card.GetCardUID(out CardUid);
            Check(rc);

            if (doChangeMasterKey)
            {
                rc = card.GetKeyVersion(0, out KeyVersion);
                Check(rc);

                rc = card.ChangeKey((byte)Desfire.DesfireKeyType.AES128, 0xAE, RootKey2K, null);
                Check(rc);
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

            rc = card.GetFreeMemory(out FreeBytes);
            Check(rc);

            rc = card.GetKeyVersion(0, out KeyVersion);
            Check(rc);
            rc = card.GetKeyVersion(0, out KeyVersion);
            Check(rc);

            if (doChangeMasterKey)
            {
                rc = card.AuthenticateEV2First(0, RootKey2K);
                Check(rc);
            }

            rc = card.GetKeySettings(out KeySettings, out KeyCount);
            Check(rc);

            rc = card.GetFreeMemory(out FreeBytes);
            Check(rc);

            //  At this point we would like to begin with a blank card.
            rc = card.FormatPICC();
            Check(rc);

            rc = card.GetFreeMemory(out FreeBytes);
            Check(rc);


            //  Create three applications:

            //  Application A is the most open one.
            //  It has no keys and its key settings are least restrictive.
            //  Note: since there are no keys, the Change Keys key settting must be assigned
            //        the value 0xE or 0xF.
            rc = card.CreateApplication(0xAAAAAA, 0xFF, (byte)(KeyType | 0));
            Check(rc);

            //  Application B's key settings can be changed at a later time.
            //  It has six keys.
            //  Authentication with a given key allows also to change that key.
            //  (the Change Keys key settting is 0xE)
            rc = card.CreateApplication(0xBBBBBB, 0xEF, (byte)(KeyType | 6));
            Check(rc);

            //  Application C keeps everything private.
            //  Even getting its file directory is not publicly allowed.
            //  The application has the maximum of 14 keys.
            //  We make key #0xC the Change Keys key.
            rc = card.CreateApplication(0xCCCCCC, 0xC0, (byte)(KeyType | 14));
            Check(rc);

            //  Verify that the applications have been created.
            rc = card.GetApplicationIDs(out ApplicationList);
            Check(rc);

            if (true)
            {
                // The ISO DF=2000 application will allow ISO EFs
                rc = card.CreateApplication(0xFF2000, 0xFF, (byte)(KeyType | (byte)Desfire.DesfireApplicationSettings.KeySetting2.IsoEFIds), 0x2000, StrUtils.ToBytes("1TIC.ICA"));
                Check(rc);
                rc = card.CreateApplication(0xFF3000, 0xFF, (byte)(KeyType | (byte)Desfire.DesfireApplicationSettings.KeySetting2.IsoEFIds), 0x3000, StrUtils.ToBytes("2MPP.EPP"));
                Check(rc);
                rc = card.CreateApplication(0xFF4000, 0xFF, (byte)(KeyType | (byte)Desfire.DesfireApplicationSettings.KeySetting2.IsoEFIds), 0x4000, StrUtils.ToBytes("3JDA.JDA"));
                Check(rc);
                rc = card.CreateApplication(0xFF1234, 0xFF, (byte)(KeyType | (byte)Desfire.DesfireApplicationSettings.KeySetting2.IsoEFIds), 0x1234, StrUtils.ToBytes("Test DF 1234"));
                Check(rc);

                // More applications
                if (FreeBytes > 4096)
                {
                    rc = card.CreateApplication(0xFFFF00, 0xFF, KeyType);
                    Check(rc);
                    rc = card.CreateApplication(0xFFFF01, 0xFF, KeyType);
                    Check(rc);
                    rc = card.CreateApplication(0xFFFF02, 0xFF, KeyType);
                    Check(rc);
                    rc = card.CreateApplication(0xFFFF03, 0xFF, KeyType);
                    Check(rc);
                    rc = card.CreateApplication(0xFFFF04, 0xFF, KeyType);
                    Check(rc);
                    rc = card.CreateApplication(0xFFFF05, 0xFF, KeyType);
                    Check(rc);
                    rc = card.CreateApplication(0xFFFF06, 0xFF, KeyType);
                    Check(rc);
                    rc = card.CreateApplication(0xFFFF07, 0xFF, KeyType);
                    Check(rc);
                    rc = card.CreateApplication(0xFFFF08, 0xFF, KeyType);
                    Check(rc);
                    rc = card.CreateApplication(0xFFFF0A, 0xFF, KeyType);
                    Check(rc);
                    rc = card.CreateApplication(0xFFFF0B, 0xFF, KeyType);
                    Check(rc);
                    rc = card.CreateApplication(0xFFFF0C, 0xFF, KeyType);
                    Check(rc);
                    rc = card.CreateApplication(0xFFFF0D, 0xFF, KeyType);
                    Check(rc);
                    rc = card.CreateApplication(0xFFFF0E, 0xFF, KeyType);
                    Check(rc);
                    rc = card.CreateApplication(0xFFFF0F, 0xFF, KeyType);
                    Check(rc);

                    rc = card.CreateApplication(0xFFFF10, 0xFF, KeyType);
                    Check(rc);
                    rc = card.CreateApplication(0xFFFF20, 0xFF, KeyType);
                    Check(rc);
                    rc = card.CreateApplication(0xFFFF30, 0xFF, KeyType);
                    Check(rc);
                    rc = card.CreateApplication(0xFFFF40, 0xFF, KeyType);
                    Check(rc);
                    rc = card.CreateApplication(0xFFFF50, 0xFF, KeyType);
                    Check(rc);
                    rc = card.CreateApplication(0xFFFF60, 0xFF, KeyType);
                    Check(rc);
                }

                //  Verify that the applications have been created.
                rc = card.GetApplicationIDs(out ApplicationList);
                Check(rc);

                // Cleanup authentication state
                rc = card.SelectApplication(0);
                Check(rc);

                // Retrieve the list of applications
                rc = card.GetApplicationIDs(out ApplicationList);
                Check(rc);

                if (!quiet)
                {
                    Console.WriteLine();
                    Console.WriteLine("{0} application(s) found:", ApplicationList.Length);
                    for (int i = 0; i < ApplicationList.Length; i++)
                        Console.WriteLine("\t- {0:X06}", ApplicationList[i]);
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
                                Console.Write("{0}", (char)astIsoApplications[i].IsoName[j]);
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
                rc = card.GetFileIDs(out FileList);
                Check(rc);

                if (!quiet)
                {
                    Console.WriteLine();
                    Console.WriteLine("{0} file(s) found:", FileList.Length);
                    for (int i = 0; i < FileList.Length; i++)
                        Console.WriteLine("\t- {0:X02}", FileList[i]);
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

                if (true)
                {
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
                    DataBuffer = new byte[8192];
                    for (int i = 0; i < DataBuffer.Length; i++)
                        DataBuffer[i] = 0xDA;

                    rc = card.WriteData(15, (byte)Desfire.DesfireCommMode.Plain, 0, 640, DataBuffer);
                    Check(rc);
                    rc = card.WriteData(15, (byte)Desfire.DesfireCommMode.Plain, 0, 30, StrUtils.ToBytes("This is the 1st block written."));
                    Check(rc);
                    rc = card.WriteData(15, (byte)Desfire.DesfireCommMode.Plain, 34, 22, StrUtils.ToBytes("This is the 2nd block."));
                    Check(rc);

                    //  Then make the file permanently read-only.
                    rc = card.ChangeFileSettings(15, (byte)Desfire.DesfireCommMode.Plain, 0xEFFF);
                    Check(rc);

                    //  Read part of the file's contents.
                    rc = card.ReadData(15, (byte)Desfire.DesfireCommMode.Plain, 10, 50, out DataBuffer);
                    Check(rc);

                    //  Get all data in one block. 
                    //  Note: Must make sure that buffer is large enough for all data!!
                    rc = card.ReadData(15, (byte)Desfire.DesfireCommMode.Plain, 0, 0, out DataBuffer);
                    Check(rc);

                    //  Test different lengths
                    for (int i = 45; i < 65; i++)
                    {
                        rc = card.ReadData(15, (byte)Desfire.DesfireCommMode.Plain, 0, i, out DataBuffer);
                        Check(rc);
                    }

                    //  Try to overwrite the file.
                    //  Since we have made the file read-only, this should fail.
                    rc = card.WriteData(15, (byte)Desfire.DesfireCommMode.Plain, 20, 5, StrUtils.ToBytes("Essai"));
                    Check(rc, Desfire.DesfireCardError.PermissionDenied);

                    //  Do 15 transactions.
                    for (Transaction = 0; Transaction < 15; Transaction++)
                    {
                        //  Write to the Backup Data file.
                        string strBuffer = string.Format("{0:D02},", Transaction);
                        rc = card.WriteData(5, (byte)Desfire.DesfireCommMode.Plain, 3 * Transaction, 3, StrUtils.ToBytes(strBuffer));
                        Check(rc);

                        //  Manipulate the Value file.
                        rc = card.Credit(4, (byte)Desfire.DesfireCommMode.Plain, 100);
                        Check(rc);
                        rc = card.Debit(4, (byte)Desfire.DesfireCommMode.Plain, 93);
                        Check(rc);

                        //  Write to the Cyclic Record file.
                        rc = card.WriteRecord(0, (byte)Desfire.DesfireCommMode.Plain, 2, 2, DataBuffer);
                        Check(rc);
                        //  The following Write Record will write to the same record as above
                        rc = card.WriteRecord(0, (byte)Desfire.DesfireCommMode.Plain, 0, 2, StrUtils.ToBytes("r."));
                        Check(rc);

                        //  Verify that the 'official' contents of the three files has not changed
                        //  before the CommitTransaction command.
                        //  Must make sure that buffer is large enough for all data!
                        rc = card.ReadData(5, (byte)Desfire.DesfireCommMode.Plain, 0, 0, out DataBuffer);
                        Check(rc);
                        rc = card.GetValue(4, (byte)Desfire.DesfireCommMode.Plain, out long Amount);
                        Check(rc);

                        //  Note: reading from an empty record file returns an error.
                        //        beginning with version 0.1 this aborts the transaction.
                        if (Transaction != 0)
                        {
                            rc = card.ReadRecords(0, (byte)Desfire.DesfireCommMode.Plain, 0, 0, 4, out DataBuffer, out NRecordsRead);
                            Check(rc);
                        }
                        //  Declare the transaction valid.
                        rc = card.CommitTransaction();
                        Check(rc);

                        //  Verify that the transaction has become effective.
                        //  Note: Must make sure that buffer is large enough for all data!
                        rc = card.ReadData(5, (byte)Desfire.DesfireCommMode.Plain, 0, 0, out DataBuffer);
                        Check(rc);
                        rc = card.GetValue(4, (byte)Desfire.DesfireCommMode.Plain, out Amount);
                        Check(rc);
                        rc = card.ReadRecords(0, (byte)Desfire.DesfireCommMode.Plain, 0, 0, 4, out DataBuffer, out NRecordsRead);
                        Check(rc);
                    }

                    //  Limited Credit has been disabled, so the following call should fail.
                    rc = card.LimitedCredit2(4, 20);
                    Check(rc, Desfire.DesfireCardError.PermissionDenied);

                    //  Get the file IDs of the current application.
                    rc = card.GetFileIDs(out FileList);
                    Check(rc);

                    if (!quiet)
                    {
                        Console.WriteLine();
                        Console.WriteLine("{0} file(s) found:", FileList.Length);
                        for (int i = 0; i < FileList.Length; i++)
                            Console.WriteLine("\t- {0:X02}", FileList[i]);
                    }

                    //  Get information about the application's files.
                    //  Delete each file after retrieving information about it.
                    for (int FileIndex = 0; FileIndex < FileList.Length; FileIndex++)
                    {
                        rc = card.GetFileSettings(FileList[FileIndex], out FileType, out CommMode, out AccessRights, out FileSettings);
                        Check(rc);
                        rc = card.DeleteFile(FileList[FileIndex]);
                        Check(rc);
                    }

                    //  Verify that there are no files in the application.
                    rc = card.GetFileIDs(out FileList);
                    Check(rc);

                    //  Delete application A.
                    //  Since this application doesn't have an Application Master Key,
                    //  this requires Card Master Key authentication.
                    rc = card.SelectApplication(0);
                    Check(rc);

                    if (doChangeMasterKey)
                    {
                        rc = card.AuthenticateEV2First(0, RootKey2K);
                        Check(rc);
                    }
                    else
                    {
                        rc = card.AuthenticateEV2First(0, NullKey_16);
                        Check(rc);
                    }

                    rc = card.DeleteApplication(0xAAAAAA);
                    Check(rc);
                }
                else
                {
                    rc = card.SelectApplication(0);
                    Check(rc);

                    if (doChangeMasterKey)
                    {
                        rc = card.AuthenticateEV2First(0, RootKey2K);
                        Check(rc);
                    }
                    else
                    {
                        rc = card.AuthenticateEV2First(0, NullKey_16);
                        Check(rc);
                    }
                }

                //  Verify that application A has been deleted.
                rc = card.GetApplicationIDs(out ApplicationList);
                Check(rc);
            }

            //  Changing application B's keys:
            rc = card.SelectApplication(0xBBBBBB);
            Check(rc);

            rc = card.AuthenticateEV2First(0, NullKey);
            Check(rc);

            rc = card.GetCardUID(out CardUid);
            Check(rc);
            rc = card.GetCardUID(out CardUid);
            Check(rc);

            rc = card.GetVersion(out VersionInfo);
            Check(rc);

            if (!quiet)
            {
                Console.WriteLine();
                Console.WriteLine("HwVendorID={0:X02}", VersionInfo.HwVendorID);
                Console.WriteLine("HwType={0:X02}", VersionInfo.HwType);
                Console.WriteLine("HwSubType={0:X02}", VersionInfo.HwSubType);
                Console.WriteLine("HwMajorVersion={0:X02}", VersionInfo.HwMajorVersion);
                Console.WriteLine("HwMinorVersion={0:X02}", VersionInfo.HwMinorVersion);
                Console.WriteLine("HwStorageSize={0:X02}", VersionInfo.HwStorageSize);
                Console.WriteLine("HwProtocol={0:X02}", VersionInfo.HwProtocol);
                Console.WriteLine("SwVendorID={0:X02}", VersionInfo.SwVendorID);
                Console.WriteLine("SwType={0:X02}", VersionInfo.SwType);
                Console.WriteLine("SwSubType={0:X02}", VersionInfo.SwSubType);
                Console.WriteLine("SwMajorVersion={0:X02}", VersionInfo.SwMajorVersion);
                Console.WriteLine("SwMinorVersion={0:X02}", VersionInfo.SwMinorVersion);
                Console.WriteLine("SwStorageSize={0:X02}", VersionInfo.SwStorageSize);
                Console.WriteLine("SwProtocol={0:X02}", VersionInfo.SwProtocol);
                Console.WriteLine("Uid={0:X02}:{1:X02}:{2:X02}:{3:X02}:{4:X02}:{5:X02}:{6:X02}", VersionInfo.Uid[0], VersionInfo.Uid[1], VersionInfo.Uid[2], VersionInfo.Uid[3], VersionInfo.Uid[4], VersionInfo.Uid[5], VersionInfo.Uid[6]);
                Console.WriteLine("BatchNo={0:X02}:{1:X02}:{2:X02}:{3:X02}:{4:X02}", VersionInfo.BatchNo[0], VersionInfo.BatchNo[1], VersionInfo.BatchNo[2], VersionInfo.BatchNo[3], VersionInfo.BatchNo[4]);
                Console.WriteLine("ProductionCW={0:X02}", VersionInfo.ProductionCW);
                Console.WriteLine("ProductionYear={0:X02}", VersionInfo.ProductionYear);
            }

            bench = Stopwatch.StartNew();

            //  Set the new application master key and get authenticated with it
            rc = card.ChangeKey(0, 0, AppBKeyMaster0, null); // JDA
            Check(rc);
            rc = card.AuthenticateEV2First(0, AppBKeyMaster0);
            Check(rc);

            rc = card.GetFreeMemory(out FreeBytes);
            Check(rc);
            rc = card.GetFreeMemory(out FreeBytes);
            Check(rc);

            //  Beginning with DesFire version 0.1 we can query the version number of a key.
            rc = card.GetKeyVersion(0, out KeyVersion);
            Check(rc);

            //  Change key #1 to a different SingleDES key (both key halves are the same).
            //  Authentication with that key is necessary for changing it.
            rc = card.AuthenticateEV2First(1, NullKey);
            Check(rc);
            rc = card.ChangeKey(1, 0x33, TestKeyDes1K, null);
            Check(rc);

            //  Change key #5 to a TripeDES key.
            //  Authentication with that key is necessary for changing it.
            rc = card.AuthenticateEV2First(5, NullKey);
            Check(rc);
            rc = card.ChangeKey(5, 0x77, AppBChangeKey, null);
            Check(rc);

            //  Get authenticated again with appl's Master key
            rc = card.AuthenticateEV2First(0, AppBKeyMaster0);
            Check(rc);

            rc = card.GetFreeMemory(out FreeBytes);
            Check(rc);
            rc = card.GetFreeMemory(out FreeBytes);
            Check(rc);

            //  Make key #5 the Change Keys Key.
            rc = card.ChangeKeySettings(0x5F);
            Check(rc);

            //  Verify the new key settings.
            rc = card.GetKeySettings(out KeySettings, out KeyCount);
            Check(rc);

            //  Change keys #1 through #4 using the three key procedure.
            //  Authentication with the Change Keys Key is now necessary for changing ordinary keys.
            rc = card.AuthenticateEV2First(5, AppBChangeKey);
            Check(rc);
            rc = card.ChangeKey(1, 0x33, AppBKey1, TestKeyDes1K);
            Check(rc);
            rc = card.ChangeKey(2, 0x55, AppBKey2, NullKey);
            Check(rc);
            rc = card.ChangeKey(3, 0x33, AppBKey3, NullKey);
            Check(rc);
            rc = card.ChangeKey(4, 0x55, AppBKey4, NullKey);
            Check(rc);

            rc = card.AuthenticateEV2First(5, AppBChangeKey);
            Check(rc);

            rc = card.GetFreeMemory(out FreeBytes);
            Check(rc);
            rc = card.GetFreeMemory(out FreeBytes);
            Check(rc);
            rc = card.GetKeySettings(out KeySettings, out KeyCount);
            Check(rc);
            rc = card.GetCardUID(out CardUid);
            Check(rc);
            rc = card.GetCardUID(out CardUid);
            Check(rc);

            rc = card.AuthenticateEV2NonFirst(1, AppBKey1);
            Check(rc);
            rc = card.AuthenticateEV2NonFirst(2, AppBKey2);
            Check(rc);
            rc = card.AuthenticateEV2NonFirst(3, AppBKey3);
            Check(rc);
            rc = card.AuthenticateEV2NonFirst(4, AppBKey4);
            Check(rc);
            rc = card.AuthenticateEV2NonFirst(5, AppBChangeKey);
            Check(rc);

            bench.Stop();
            Console.WriteLine($"\nBench AES{NullKey.Length * 8}: {bench.ElapsedMilliseconds}ms");

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

            rc = card.GetFreeMemory(out FreeBytes);
            Check(rc);

            //  Do 7 transactions.
            for (Transaction = 0; Transaction < 7; Transaction++)
            {
                //  Change the communication mode for all files.
                CommMode = (byte)(Transaction % 3);
                if (CommMode == 2) CommMode = 3;

                //  This requires authentication with the key defined for changing the configuration.
                rc = card.AuthenticateEV2First(4, AppBKey4);
                Check(rc);

                rc = card.ChangeFileSettings(14, CommMode, 0x1234);
                Check(rc);
                rc = card.ChangeFileSettings(4, CommMode, 0x1324);
                Check(rc);
                rc = card.ChangeFileSettings(1, CommMode, 0x1324);
                Check(rc);

                //  Authenticate with the key which allows reading the files
                rc = card.AuthenticateEV2First(1, AppBKey1);
                Check(rc);

                //  Get the Value file's current balance.
                rc = card.GetValue(4, CommMode, out long Amount);
                Check(rc);

                if (Transaction < 3)
                {
                    //  Test different lengths
                    for (int i = 45; i < 65; i++)
                    {
                        rc = card.ReadData(14, CommMode, 100 - i, i, out DataBuffer);
                        Check(rc);
                    }
                    for (int i = 10; i <= 100; i += 10)
                    {
                        rc = card.ReadData(14, CommMode, 100 - i, i, out DataBuffer);
                        Check(rc);
                    }
                }

                rc = card.ReadData(14, CommMode, 0, 0, out DataBuffer);
                Check(rc);

                //  Authenticate with the key which allows writing to files and increasing the Value
                //  file's value.
                rc = card.AuthenticateEV2First(2, AppBKey2);
                Check(rc);

                //  Write to the Standard Data file.
                DataBuffer = new byte[100];
                for (int i = 0; i < 100; i++)
                    DataBuffer[i] = (byte)((Transaction << 6) + i + 0);

                if (Transaction < 3)
                {
                    rc = card.WriteData(14, CommMode, 0, 7, DataBuffer);
                    Check(rc);
                    rc = card.WriteData(14, CommMode, 0, 8, DataBuffer);
                    Check(rc);
                    rc = card.WriteData(14, CommMode, 0, 9, DataBuffer);
                    Check(rc);
                    rc = card.WriteData(14, CommMode, 0, 14, DataBuffer);
                    Check(rc);
                    rc = card.WriteData(14, CommMode, 0, 15, DataBuffer);
                    Check(rc);
                    rc = card.WriteData(14, CommMode, 0, 16, DataBuffer);
                    Check(rc);

                    rc = card.WriteData(14, CommMode, 0, 1, DataBuffer);
                    Check(rc);
                    rc = card.WriteData(14, CommMode, 0, 2, DataBuffer);
                    Check(rc);

                    for (int i = 1; i <= 100; i++)
                    {
                        rc = card.WriteData(14, CommMode, 0, i, DataBuffer);
                        Check(rc);
                    }

                    for (int i = 0; i < 100; i++)
                    {
                        rc = card.WriteData(14, CommMode, i, 100 - i, DataBuffer);
                        Check(rc);
                    }

                    rc = card.WriteData(14, CommMode, 0, 10, DataBuffer);
                    Check(rc);
                    rc = card.WriteData(14, CommMode, 10, 10, DataBuffer);
                    Check(rc);
                    rc = card.WriteData(14, CommMode, 20, 20, DataBuffer);
                    Check(rc);
                    rc = card.WriteData(14, CommMode, 30, 30, DataBuffer);
                    Check(rc);
                    rc = card.WriteData(14, CommMode, 40, 40, DataBuffer);
                    Check(rc);
                    rc = card.WriteData(14, CommMode, 50, 50, DataBuffer);
                    Check(rc);
                    rc = card.WriteData(14, CommMode, 30, 70, DataBuffer);
                    Check(rc);
                    rc = card.WriteData(14, CommMode, 10, 90, DataBuffer);
                    Check(rc);
                }

                rc = card.WriteData(14, CommMode, 0, 100, DataBuffer);
                Check(rc);

                string strBuffer = string.Format(" Transaction #{0} ", Transaction);
                rc = card.WriteData(14, CommMode, 5, StrUtils.ToBytes(strBuffer));
                Check(rc);

                //  Write to the Linear Record file.
                //  If it turns out, that the file is full, clear its contents and repeat writing.
                for (int i = 0; i < 2; i++)
                {
                    rc = card.WriteRecord(1, CommMode, 0, StrUtils.ToBytes("0123456789012345678901234"));
                    if (rc == 0)
                        rc = card.WriteRecord(1, CommMode, 5, StrUtils.ToBytes(strBuffer));
                    //  Was the WriteRecord successful ?
                    if (rc == 0)
                        break;              // yes

                    // The current authentication status has been lost. We must get authenticated again
                    rc = card.AuthenticateEV2First(2, AppBKey2);
                    Check(rc);

                    //  Clear the record file.
                    rc = card.ClearRecordFile(1);
                    Check(rc);

                    //  It is not allowed to write to the file before a CommitTransaction.
                    //  So the following call will fail !
                    rc = card.WriteRecord(1, CommMode, 5, 25, DataBuffer);
                    Check(rc, Desfire.DesfireCardError.PermissionDenied);

                    // The current authentication status has been lost. We must get authenticated again
                    rc = card.AuthenticateEV2First(2, AppBKey2);
                    Check(rc);

                    //  Version 0.1 and above execute an implicit AbortTransaction after any
                    //  error. Therefore the ClearRecordFile has been cancelled. We have to repeat it.
                    rc = card.ClearRecordFile(1);
                    Check(rc);

                    //  After the following the Record file is again ready for data.
                    rc = card.CommitTransaction();
                    Check(rc);
                }

                //  Modify the Value file.
                rc = card.Debit(4, CommMode, 1300);
                Check(rc);
                rc = card.Credit(4, CommMode, 20);
                Check(rc);
                rc = card.Debit(4, CommMode, 1700);
                Check(rc);

                //  Make all changes current.
                rc = card.CommitTransaction();
                Check(rc);

                //  Return the whole debited amount to the Value File.
                rc = card.LimitedCredit(4, CommMode, 3000);
                Check(rc);

                //  Make the change current.
                rc = card.CommitTransaction();
                Check(rc);


                //  Authenticate with the key which allows reading files and retrieving the Value
                //  file's value.
                rc = card.AuthenticateEV2First(1, AppBKey1);
                Check(rc);

                //  Read the first half of the Standard Data file's data specifying the exact
                //  number of bytes to read.
                rc = card.ReadData(14, CommMode, 0, 50, out DataBuffer);
                Check(rc);
                //  Read the second half of the data with an open read (give me all data available).
                rc = card.ReadData(14, CommMode, 50, 0, out DataBuffer);
                Check(rc);

                //  Get the Value file's current balance.
                rc = card.GetValue(4, CommMode, out Amount);
                Check(rc);

                //  Get the number of records in the Linear Record file.
                rc = card.GetFileSettings(1, out FileType, out CommMode, out AccessRights, out FileSettings);
                Check(rc);

                if (FileSettings.RecordFile.CurrentRecordCount > 0)
                {
                    //  Read the oldest record from the file.
                    rc = card.ReadRecords(1, CommMode, FileSettings.RecordFile.CurrentRecordCount - 1, 1, FileSettings.RecordFile.RecordSize, out DataBuffer, out NRecordsRead);
                    Check(rc);

                    //  Read all records from the file.
                    rc = card.ReadRecords(1, CommMode, 0, 0, FileSettings.RecordFile.RecordSize, out DataBuffer, out NRecordsRead);
                    Check(rc);
                }
            }

            //  Get the file IDs of the current application.
            rc = card.GetFileIDs(out FileList);
            Check(rc);

            //  Get information about the application's files.
            //  Delete each file after retrieving information about it.
            for (int FileIndex = 0; FileIndex < FileList.Length; FileIndex++)
            {
                rc = card.GetFileSettings(FileList[FileIndex], out FileType, out CommMode, out AccessRights, out FileSettings);
                Check(rc);
                rc = card.DeleteFile(FileList[FileIndex]);
                Check(rc);
            }

            //  Verify that there are no files in the application.
            rc = card.GetFileIDs(out FileList);
            Check(rc);

            //  Delete application B.
            //  This time we can (and do) use the Application Master Key.
            rc = card.AuthenticateEV2First(0, AppBKeyMaster0);
            Check(rc);

            rc = card.DeleteApplication(0xBBBBBB);
            Check(rc);

            rc = card.SelectApplication(0);
            Check(rc);

            //  Verify that application B has been deleted.
            rc = card.GetApplicationIDs(out ApplicationList);
            Check(rc);

            if (FreeBytes < 2000)
            {
                rc = card.SelectApplication(0);
                Check(rc);

                if (doChangeMasterKey)
                {
                    rc = card.AuthenticateEV2First(0, RootKey2K);
                    Check(rc);
                }
                else
                {
                    rc = card.AuthenticateEV2First(0, NullKey_16);
                    Check(rc);
                }

                rc = card.FormatPICC();
                Check(rc);

                rc = card.CreateApplication(0xCCCCCC, 0xC0, 14);
                Check(rc);
            }

            //  Working with a larger file (a Cyclic Record File) using application C:
            rc = card.SelectApplication(0xCCCCCC);
            Check(rc);

            //  Define keys #1 and #2 using the Change Keys key (#12).
            rc = card.AuthenticateEV2First(12, NullKey);
            Check(rc);
            rc = card.ChangeKey(1, 0, AppCKey1, NullKey);
            Check(rc);
            rc = card.ChangeKey(2, 0, AppCKey2, NullKey);
            Check(rc);
            // Back to master key
            rc = card.AuthenticateEV2First(0, NullKey);
            Check(rc);

            //  Create the file - it has 16 records of 100 bytes
            rc = card.CreateCyclicRecordFile(6, 0, 0x12E0, 100, 16);
            Check(rc);

            //  Do 50 transactions.
            for (Transaction = 0; Transaction < 50; Transaction++)
            {
                //  Change the file's communication mode.
                CommMode = (byte)(Transaction % 3);
                if (CommMode == 2)
                    CommMode++;

                //  This requires authentication with the key defined for changing the configuration.
                //  For this file it is the Application Master Key.
                rc = card.AuthenticateEV2First(0, NullKey);
                Check(rc);

                rc = card.ChangeFileSettings(6, CommMode, 0x12E0);
                Check(rc);

                //  The file can be written using either the Write access key (0x.2..) or the
                //  Read/Write key (0x..E.).
                //  A valid authentication with key #2 causes the communication to take place in
                //  the mode defined with ChangeFileSettings above.
                //  Not being authenticated with key #2 causes the Read/Write access right to be used
                //  forcing the communication to plain mode.
                if ((Transaction & 0x04) != 0)
                {
                    rc = card.AuthenticateEV2First(2, AppCKey2);
                    Check(rc);
                }
                else
                    CommMode = 0;

                //  Write a new record.
                DataBuffer = new byte[100];
                string strBuffer = string.Format(" Transaction #{0} !TEST!?!TEST! ", Transaction);
                BinUtils.CopyTo(DataBuffer, StrUtils.ToBytes(strBuffer));
                rc = card.WriteRecord(6, CommMode, 0, 100, DataBuffer);

                //  Cancel every 7th WriteRecord operation.
                if (Transaction % 7 == 0)
                    rc = card.AbortTransaction();
                else
                    rc = card.CommitTransaction();

                Check(rc, new Desfire.DesfireCardError[] { Desfire.Success, Desfire.DesfireCardError.NoChange, Desfire.DesfireCardError.CommandAborted });
            }

            //  Read each individual record using the designated read key.
            //  Note that increasing the offset lets us go back in the record history.
            //  Note also that only 16-1 records (one less than specified in CreateCyclicRecordFile)
            //  can be accessed.
            CommMode = 1;

            rc = card.AuthenticateEV2First(1, AppCKey1);
            Check(rc);

            for (int i = 0; i < 16; i++)
            {
                rc = card.ReadRecords(6, CommMode, i, 1, 100, out DataBuffer, out NRecordsRead);
                Check(rc, new Desfire.DesfireCardError[] { Desfire.Success, Desfire.DesfireCardError.BoundaryError });
            }

            //  Following the Boundary Error we lose the authentication - so we must get authenticated again
            rc = card.AuthenticateEV2First(1, AppCKey1);
            Check(rc);

            rc = card.ReadRecords(6, CommMode, 0, 1, 100, out DataBuffer, out NRecordsRead);
            Check(rc);

            //  Read the whole record file with a single ReadRecords call.
            rc = card.ReadRecords(6, CommMode, 0, 15, 100, out DataBuffer, out NRecordsRead);
            Check(rc);

            rc = card.ReadRecords(6, CommMode, 0, 0, 100, out DataBuffer, out NRecordsRead);
            Check(rc);

            //  Change the master key settings such that master key authentication will be required
            //  for all card operations.
            //  Leave the ChangeConfiguration bit (bit 3) set to allow undoing the change.
            rc = card.SelectApplication(0);
            Check(rc);

            if (doChangeMasterKey)
            {
                rc = card.AuthenticateEV2First(0, RootKey2K);
                Check(rc);

                rc = card.ChangeKeySettings(0x8);
                Check(rc);

                //  Clear the authentication state and try to get application IDs.
                //  Also try to delete application C or to create a new application.
                rc = card.SelectApplication(0);
                Check(rc);

                //  The following three calls will report an Authentication Error (0xAE).
                rc = card.GetApplicationIDs(out ApplicationList);
                Check(rc, Desfire.DesfireCardError.AuthenticationError);
                rc = card.DeleteApplication(0xCCCCCC);
                Check(rc, Desfire.DesfireCardError.AuthenticationError);

                // This one must fail
                rc = card.CreateApplication(0xDDDDDD, 0xEF, KeyType);
                Check(rc, Desfire.DesfireCardError.AuthenticationError);

                //  With authentication all three should work.
                rc = card.AuthenticateEV2First(0, RootKey2K);
                Check(rc);
            }
            else
            {
                rc = card.AuthenticateEV2First(0, NullKey_16);
                Check(rc);
            }

            rc = card.GetApplicationIDs(out ApplicationList);
            Check(rc);
            rc = card.DeleteApplication(0xCCCCCC);
            Check(rc);
            rc = card.CreateApplication(0xDDDDDD, 0xEF, KeyType);
            Check(rc);

            if (doChangeMasterKey)
            {
                //  Change the master key settings back to the default which is least restrictive.
                rc = card.ChangeKeySettings(0xF);
                Check(rc);

                //  Change the Card master key back to the 0 key.
                rc = card.AuthenticateEV2First(0, RootKey2K);
                Check(rc);

                rc = card.ChangeKey(0, 0, NullKey_16, null);
                Check(rc);

                rc = card.AuthenticateEV2First(0, NullKey_16);
                Check(rc);
            }
            else
            {
                rc = card.AuthenticateEV2First(0, NullKey_16);
                Check(rc);
            }

            rc = card.GetFreeMemory(out FreeBytes);
            Check(rc);

            //  Delete all demonstration data from the card.
            rc = card.FormatPICC();
            Check(rc);

            rc = card.GetFreeMemory(out FreeBytes);
            Check(rc);


            Console.WriteLine();
        }
    }
}
