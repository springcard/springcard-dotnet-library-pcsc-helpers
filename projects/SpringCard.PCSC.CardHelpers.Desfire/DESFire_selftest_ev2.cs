/*
 * SpringCard DESFire Library (C#)
 * Copyright (c) SpringCard SAS, 2008-2025
 *
 * This file is part of the SpringCard DESFire library.
 * See LICENSE.txt for license details and restrictions.
 *
 */
using SpringCard.LibCs;
using System;


namespace SpringCard.PCSC.CardHelpers
{
    public partial class Desfire
    {
        /**
         * @brief Self-test for DESFire EV2
         */
        public static void DesfireEV2SelfTest()
        {
            DesfireEV2SelfTest_SAL();

            DesfireEV2SelfTest_PC1();
            DesfireEV2SelfTest_PC2();
            DesfireEV2SelfTest_PC3();

            DesfireEV2SelfTest_Auth();

            DesfireEV2SelfTest_CreateApplication();

            DesfireEV2SelfTest_ChangeKey_1();
            DesfireEV2SelfTest_ChangeKey_2();
            DesfireEV2SelfTest_ChangeKey_3();

            DesfireEV2SelfTest_InitializeKeySet();
            DesfireEV2SelfTest_FinalizeKeySet();
            DesfireEV2SelfTest_RollKeySet();

            DesfireEV2SelfTest_WriteData_Mac();
            DesfireEV2SelfTest_ReadData_Mac();
            DesfireEV2SelfTest_WriteData_Full();
            DesfireEV2SelfTest_ReadData_Full();


            DesfireEV2SelfTest_DAM();
            DesfireEV2SelfTest_CreateDelegatedApplication();
        }

        public static void DesfireEV2SelfTest_SAL()
        {
            Logger.Info("SYLVAIN");

            FakeCardTransmitter transmitter = new FakeCardTransmitter();

            transmitter.AddApduPair("710300", "AF8666A0E23125EE986CE988B569034B6E");
            transmitter.AddApduPair("AF0F2BFDA5275930C9ACAE3C9DDAF6D448D7AE7906E58179DE9863688765151679", "000944F894D43C2EFFF6F064546C5A445F99658330F578033B0CA8C79F96E16260");
            transmitter.AddApduPair("3D05000000100000A565CAB35197A8800220B6A75CB7150AD91ECED7739D064C2C9A8D7C358AB250694E5BDDD1780747", "00A5ED0A889CFD8EF5");
            transmitter.AddApduPair("3D0500000003000083D21EAE924BBA41592595F40BBEF0B93270F7087FD121BE", "000A619F3EB163CD23");

            FakeRandomGenerator fakeRandomGenerator = new FakeRandomGenerator(BinConvert.HexToBytes("17109E18D1A6F9E6634BD4AD5C856AC6"));

            Desfire desfire = new Desfire(transmitter, DesfireIsoWrapping.None);
            desfire.SetLogger(new Logger(), true, true);
            desfire.SetRandomGenerator(fakeRandomGenerator);

            Logger.Info("AuthenticateEV2First");

            if (desfire.AuthenticateEV2First(0x03, new byte[16], null, out byte[] PcdCaps2_echo, out byte[] PiccCaps2, out byte[] TransactionIdentifier) != Success)
                goto failed;

            Logger.Info("AuthenticateEV2First OK");

            (desfire.SessionCryptoContext as DesfireCryptoContextEV2).ExportSessionKeys(out byte[] encKey, out byte[] cmacKey);

            Logger.Info("EncKey=" + BinConvert.ToHex(encKey));
            Logger.Info("CmacKey=" + BinConvert.ToHex(cmacKey));

            if (!BinUtils.Equals(encKey, BinConvert.HexToBytes("59B70B6C3E8B97E5453357FDA867F846")))
                goto failed;

            Logger.Info("Encryption Key OK");

            if (!BinUtils.Equals(cmacKey, BinConvert.HexToBytes("D1148CD6B56819FA7CE905D33FF3078D")))
                goto failed;

            Logger.Info("Cmac Key OK");

            if (desfire.WriteData(0x05, 0x03, 0, BinConvert.HexToBytes("DADADADADADADADADADADADADADADADA")) != Success)
                goto failed;

            Logger.Info("WriteData(16) OK");

            if (desfire.WriteData(0x05, 0x03, 0, BinConvert.HexToBytes("DADADA")) != Success)
                goto failed;

            Logger.Info("WriteData(3) OK");

            throw new Exception("ARRET BRUTAL");

            return;

        failed:
            throw new Exception("DesfireEV2 self-test [Auth] failed");
        }



        /*
         * Reference: AN14212 - Table 9. Example showing Cmd.AuthenticateEV2First authentication
         */
        public static void DesfireEV2SelfTest_Auth()
        {
            FakeCardTransmitter transmitter = new FakeCardTransmitter();

            transmitter.AddApduPair("710000", "AF8CE7D9A83FA3B66AE59E51D2DAECCD5D");
            transmitter.AddApduPair("AF60DCFF9A0BBE8DE18B7D79BB590CD4B42D531C24906D1B0D11BEB17E8850D298", "00EE93375DE2190A24F97D4AE363CAEC8DE2ED76DF4C3EE23C9D3499E3EC8D2259");

            FakeRandomGenerator fakeRandomGenerator = new FakeRandomGenerator(BinConvert.HexToBytes("876D85B7FC717073AFBF564834F98F1E"));

            Desfire desfire = new Desfire(transmitter, DesfireIsoWrapping.None);
            desfire.SetLogger(new Logger(), true, true);
            desfire.SetRandomGenerator(fakeRandomGenerator);

            Logger.Info("AuthenticateEV2First");

            if (desfire.AuthenticateEV2First(0x00, new byte[16], null, out byte[] PcdCaps2_echo, out byte[] PiccCaps2, out byte[] TransactionIdentifier) != Success)
                goto failed;

            Logger.Info("AuthenticateEV2First OK");

            if (!BinUtils.Equals(TransactionIdentifier, BinConvert.HexToBytes("B04D6C11")))
                goto failed;

            Logger.Info("TI OK");

            if (!BinUtils.Equals(PiccCaps2, BinConvert.HexToBytes("000000000000")))
                goto failed;

            Logger.Info("PiccCaps2 OK");

            if (!BinUtils.Equals(PcdCaps2_echo, BinConvert.HexToBytes("000000000000")))
                goto failed;

            Logger.Info("PcdCaps2 OK");

            (desfire.SessionCryptoContext as DesfireCryptoContextEV2).ExportSessionKeys(out byte[] encKey, out byte[] cmacKey);

            if (!BinUtils.Equals(encKey, BinConvert.HexToBytes("030A8C76BBC954513A52B2AAD161D15B")))
                goto failed;

            Logger.Info("Encryption Key OK");

            if (!BinUtils.Equals(cmacKey, BinConvert.HexToBytes("185D0E3CEA4C0C32DFAD84B3414A5054")))
                goto failed;

            Logger.Info("Cmac Key OK");
            return;

        failed:
            throw new Exception("DesfireEV2 self-test [Auth] failed");
        }

        public static void DesfireEV2SelfTest_ChangeKey_1()
        {
            FakeCardTransmitter transmitter = new FakeCardTransmitter();

            transmitter.AddApduPair("C60001FBCAB0195724263777DDEE9C05BF2E14D839BC33F5D9803F3C74E32F818CF5F9767AC3F2F917EB95", "00BC209BFE2F4BD9D7");

            Desfire desfire = new Desfire(transmitter, DesfireIsoWrapping.None);
            desfire.SetLogger(new Logger(), true, true);

            desfire.SessionCryptoContext = new DesfireCryptoContextEV2(desfire, new byte[16]);

            (desfire.SessionCryptoContext as DesfireCryptoContextEV2).ImportSessionKeys(BinConvert.HexToBytes("DCD2286FF009ED5A2DBCC178D6CB78E4"), BinConvert.HexToBytes("D98FE5A95B62E602633983C486143179"));
            (desfire.SessionCryptoContext as DesfireCryptoContextEV2).ImportTransaction(BinConvert.HexToBytes("1EE22355"), 2);

            if (desfire.ChangeKeyEV2(0x00, 0x01, 0x00, BinConvert.HexToBytes("A0A1A2A3A4A5A6A7A8A9AAABACADAEAF"), BinConvert.HexToBytes("00112233445566778899AABBCCDDEEFF")) != Success)
                goto failed;

            Logger.Info("ChangeKeyEV2 OK");
            return;

        failed:
            throw new Exception("DesfireEV2 self-test [ChangeKey 1] failed");
        }

        public static void DesfireEV2SelfTest_ChangeKey_2()
        {
            FakeCardTransmitter transmitter = new FakeCardTransmitter();

            transmitter.AddApduPair("C60000E1B62916EDE2BD9E76615DE26733B843B554D0594A52ABAE7ACD218F4CBA64903747461D39B3B530", "00");

            Desfire desfire = new Desfire(transmitter, DesfireIsoWrapping.None);
            desfire.SetLogger(new Logger(), true, true);

            desfire.SessionCryptoContext = new DesfireCryptoContextEV2(desfire, new byte[16]);

            (desfire.SessionCryptoContext as DesfireCryptoContextEV2).ImportSessionKeys(BinConvert.HexToBytes("AFBD57BE96219810D10DC5F40236A8D6"), BinConvert.HexToBytes("E1F374D1F5DD913F0D3ACA52B149A4EA"));
            (desfire.SessionCryptoContext as DesfireCryptoContextEV2).ImportTransaction(BinConvert.HexToBytes("96780CB0"), 0);
            (desfire.SessionCryptoContext as DesfireCryptoContextEV2).ImportInitVector(BinConvert.HexToBytes("93C4B2353DE7A27D18A92D27E1E368B5"));

            if (desfire.ChangeKeyEV2(0x00, 0x00, 0x00, BinConvert.HexToBytes("AABBCCDDEEFFAABBCCDDEEFFAABBCCDD"), null) != Success)
                goto failed;

            Logger.Info("ChangeKeyEV2 OK");
            return;

        failed:
            throw new Exception("DesfireEV2 self-test [ChangeKey 2] failed");
        }

        /*
         * Reference: AN14212 - Table 12. Cmd.WriteData in EV2 Secure Messaging using CommMode.MAC
         */
        public static void DesfireEV2SelfTest_WriteData_Mac()
        {
            FakeCardTransmitter transmitter = new FakeCardTransmitter();

            transmitter.AddApduPair("3D020000001500000102030405060708090A0B0C0D0E0F10111213141516C090A3EB0889AA", "00377D8A81AF663484");

            Desfire desfire = new Desfire(transmitter, DesfireIsoWrapping.None);
            desfire.SetLogger(new Logger(), true, true);

            desfire.SessionCryptoContext = new DesfireCryptoContextEV2(desfire, new byte[16]);

            (desfire.SessionCryptoContext as DesfireCryptoContextEV2).ImportSessionKeys(null, BinConvert.HexToBytes("185D0E3CEA4C0C32DFAD84B3414A5054"));
            (desfire.SessionCryptoContext as DesfireCryptoContextEV2).ImportTransaction(BinConvert.HexToBytes("B04D6C11"), 1);

            if (desfire.WriteData(0x02, DesfireCommMode.Maced, BinConvert.HexToBytes("0102030405060708090A0B0C0D0E0F101112131415")) != Success)
                goto failed;

            Logger.Info("WriteData MAC OK");
            return;

        failed:
            throw new Exception("DesfireEV2 self-test [WriteData MAC] failed");
        }

        /*
         * Reference: AN14212 - Table 13. Cmd.ReadData in EV2 Secure Messaging using CommMode.MAC
         */
        public static void DesfireEV2SelfTest_ReadData_Mac()
        {
            FakeCardTransmitter transmitter = new FakeCardTransmitter();

            transmitter.AddApduPair("BD0200000015000098871842F01DAB5F", "000102030405060708090A0B0C0D0E0F1011121314153B14CBFD05A8E327");

            Desfire desfire = new Desfire(transmitter, DesfireIsoWrapping.None);
            desfire.SetLogger(new Logger(), true, true);

            desfire.SessionCryptoContext = new DesfireCryptoContextEV2(desfire, new byte[16]);

            (desfire.SessionCryptoContext as DesfireCryptoContextEV2).ImportSessionKeys(null, BinConvert.HexToBytes("185D0E3CEA4C0C32DFAD84B3414A5054"));
            (desfire.SessionCryptoContext as DesfireCryptoContextEV2).ImportTransaction(BinConvert.HexToBytes("B04D6C11"), 2);

            if (desfire.ReadData(0x02, DesfireCommMode.Maced, 0, 0x15, out byte[] buffer) != Success)
                goto failed;

            if (!BinUtils.Equals(buffer, BinConvert.HexToBytes("0102030405060708090A0B0C0D0E0F101112131415")))
                goto failed;

            Logger.Info("ReadData MAC OK");
            return;

        failed:
            throw new Exception("DesfireEV2 self-test [ReadData MAC] failed");
        }

        /*
         * Reference: AN14212 - Table 14. Cmd.WriteData in EV2 Secure Messaging using CommMode.Full
         */
        public static void DesfireEV2SelfTest_WriteData_Full()
        {
            FakeCardTransmitter transmitter = new FakeCardTransmitter();

            transmitter.AddApduPair("3D03000000150000F7BB09DF5CF7C3BFF99F86FAE35E71EAA4FA4CC7D806DEBC4C49D42EAABC3A6F34D21EC9D99A0B17", "00A9E45BF1857AF67B");

            Desfire desfire = new Desfire(transmitter, DesfireIsoWrapping.None);
            desfire.SetLogger(new Logger(), true, true);

            desfire.SessionCryptoContext = new DesfireCryptoContextEV2(desfire, new byte[16]);

            (desfire.SessionCryptoContext as DesfireCryptoContextEV2).ImportSessionKeys(BinConvert.HexToBytes("030A8C76BBC954513A52B2AAD161D15B"), BinConvert.HexToBytes("185D0E3CEA4C0C32DFAD84B3414A5054"));
            (desfire.SessionCryptoContext as DesfireCryptoContextEV2).ImportTransaction(BinConvert.HexToBytes("B04D6C11"), 5);

            if (desfire.WriteData(0x03, DesfireCommMode.Full, BinConvert.HexToBytes("0102030405060708090A0B0C0D0E0F101112131415")) != Success)
                goto failed;

            Logger.Info("WriteData Full OK");
            return;

        failed:
            throw new Exception("DesfireEV2 self-test [WriteData Full] failed");
        }

        /*
         * Reference: AN14212 - Table 15. Cmd.ReadData in EV2 Secure Messaging using CommMode.Full
         */
        public static void DesfireEV2SelfTest_ReadData_Full()
        {
            FakeCardTransmitter transmitter = new FakeCardTransmitter();

            transmitter.AddApduPair("BD03000000150000BC9F9E75E6EB4014", "00F4A604CD65F97290767B78B02A55A84648A13A2D5BC7E14C795B1F0AE4154711E359DA5BBEB0FE30");

            Desfire desfire = new Desfire(transmitter, DesfireIsoWrapping.None);
            desfire.SetLogger(new Logger(), true, true);

            desfire.SessionCryptoContext = new DesfireCryptoContextEV2(desfire, new byte[16]);

            (desfire.SessionCryptoContext as DesfireCryptoContextEV2).ImportSessionKeys(BinConvert.HexToBytes("030A8C76BBC954513A52B2AAD161D15B"), BinConvert.HexToBytes("185D0E3CEA4C0C32DFAD84B3414A5054"));
            (desfire.SessionCryptoContext as DesfireCryptoContextEV2).ImportTransaction(BinConvert.HexToBytes("B04D6C11"), 7);

            if (desfire.ReadData(0x03, DesfireCommMode.Full, 0, 0x15, out byte[] buffer) != Success)
                goto failed;

            if (!BinUtils.Equals(buffer, BinConvert.HexToBytes("0102030405060708090A0B0C0D0E0F101112131415")))
                goto failed;

            Logger.Info("ReadData Full OK");
            return;

        failed:
            throw new Exception("DesfireEV2 self-test [ReadData Full] failed");
        }

        /*
         * Reference: AN14212 - Table 45. Example for Cmd.InitializeKeySet in EV2 Secure Messaging [WITH AN ERROR IN THE AN!!!]
         */
        public static void DesfireEV2SelfTest_InitializeKeySet()
        {
            FakeCardTransmitter transmitter = new FakeCardTransmitter();

            transmitter.AddApduPair("560102CF78815F7A22066C", "006CAA7E76675DD87C");

            Desfire desfire = new Desfire(transmitter, DesfireIsoWrapping.None);
            desfire.SetLogger(new Logger(), true, true);

            desfire.SessionCryptoContext = new DesfireCryptoContextEV2(desfire, new byte[16]);

            (desfire.SessionCryptoContext as DesfireCryptoContextEV2).ImportSessionKeys(BinConvert.HexToBytes("6A52C626425C39504E371607E7545D6C"), BinConvert.HexToBytes("1F28BEAD76521D73FFF6E693B521E239"));
            (desfire.SessionCryptoContext as DesfireCryptoContextEV2).ImportTransaction(BinConvert.HexToBytes("2BF0463E"), 0);

            if (desfire.InitializeKeySet(0x01, 0x02) != Success)
                goto failed;

            Logger.Info("InitializeKeySet OK");
            return;

        failed:
            throw new Exception("DesfireEV2 self-test [InitializeKeySet] failed");
        }

        /*
         * Reference: AN14212 - Table 46. Example for Cmd.ChangeKey in EV2 Secure Messaging
         */
        public static void DesfireEV2SelfTest_ChangeKey_3()
        {
            FakeCardTransmitter transmitter = new FakeCardTransmitter();

            transmitter.AddApduPair("C401218A2D144D64CE918A41C4712A2C9EF1E2F868AA83E8DE76D4665E3DC4690177B0F10C0EEB0AD115", "00856F88AC2224C4CF");

            Desfire desfire = new Desfire(transmitter, DesfireIsoWrapping.None);
            desfire.SetLogger(new Logger(), true, true);

            desfire.SessionCryptoContext = new DesfireCryptoContextEV2(desfire, new byte[16]);

            (desfire.SessionCryptoContext as DesfireCryptoContextEV2).ImportSessionKeys(BinConvert.HexToBytes("3D14286D998BF62B6B82C8A42DC33E3F"), BinConvert.HexToBytes("6C1CF8AAEBB0CDCDF79E1A1B8BEA15BD"));
            (desfire.SessionCryptoContext as DesfireCryptoContextEV2).ImportTransaction(BinConvert.HexToBytes("6F9E6308"), 1);
            (desfire.SessionCryptoContext as DesfireCryptoContextEV2).ImportInitVector(BinConvert.HexToBytes("331655A5FE10ADF02CAB1A31E6BC1CAA"));

            if (desfire.ChangeKey(0x01, 0x03, BinConvert.HexToBytes("A0A1A2A3A4A5A6A7A8A9AAABACADAEAF"), BinConvert.HexToBytes("00112233445566778899AABBCCDDEEFF")) != Success)
                goto failed;

            Logger.Info("ChangeKeyEV2 OK");
            return;

        failed:
            throw new Exception("DesfireEV2 self-test [ChangeKey 3] failed");
        }

        /*
         * Reference: AN14212 - Table 47. Example for Cmd.FinalizeKeySet in EV2 Secure Messaging [WITH AN ERROR IN THE AN!!!]
         */
        public static void DesfireEV2SelfTest_FinalizeKeySet()
        {
            FakeCardTransmitter transmitter = new FakeCardTransmitter();

            transmitter.AddApduPair("5701128D3E5C733C0181A7", "00465D6D4737EBE157");

            Desfire desfire = new Desfire(transmitter, DesfireIsoWrapping.None);
            desfire.SetLogger(new Logger(), true, true);

            desfire.SessionCryptoContext = new DesfireCryptoContextEV2(desfire, new byte[16]);

            (desfire.SessionCryptoContext as DesfireCryptoContextEV2).ImportSessionKeys(BinConvert.HexToBytes("88C1FE0773508C090422BB1F29AC09D6"), BinConvert.HexToBytes("E5860EA27916203FFCE2B6ABCBDE435D"));
            (desfire.SessionCryptoContext as DesfireCryptoContextEV2).ImportTransaction(BinConvert.HexToBytes("BC8DE63D"), 0);

            if (desfire.FinalizeKeySet(0x01, 0x12) != Success)
                goto failed;

            Logger.Info("FinalizeKeySet OK");
            return;

        failed:
            throw new Exception("DesfireEV2 self-test [FinalizeKeySet] failed");
        }

        /*
         * Reference: AN14212 - Table 48. Example for Cmd.RollKeyset in EV2 Secure Messaging
         */
        public static void DesfireEV2SelfTest_RollKeySet()
        {
            FakeCardTransmitter transmitter = new FakeCardTransmitter();

            transmitter.AddApduPair("55019881C8165A8A0B0F", "006CAA7E76675DD87C");

            Desfire desfire = new Desfire(transmitter, DesfireIsoWrapping.None);
            desfire.SetLogger(new Logger(), true, true);

            desfire.SessionCryptoContext = new DesfireCryptoContextEV2(desfire, new byte[16]);

            (desfire.SessionCryptoContext as DesfireCryptoContextEV2).ImportSessionKeys(BinConvert.HexToBytes("88C1FE0773508C090422BB1F29AC09D6"), BinConvert.HexToBytes("E5860EA27916203FFCE2B6ABCBDE435D"));
            (desfire.SessionCryptoContext as DesfireCryptoContextEV2).ImportTransaction(BinConvert.HexToBytes("BC8DE63D"), 0);

            if (desfire.RollKeySet(0x01) != Success)
                goto failed;

            Logger.Info("RollKeySet OK");
            return;

        failed:
            throw new Exception("DesfireEV2 self-test [RollKeySet] failed");
        }

        /*
         * Reference: AN14212 - Table 51. Create Conventional Application in EV2 Securing Messaging
         */
        public static void DesfireEV2SelfTest_CreateApplication()
        {
            FakeCardTransmitter transmitter = new FakeCardTransmitter();

            transmitter.AddApduPair("CA1FC1C21FB50100041002112201020304050668CB54266E0ED482", "00787B2EFA996DCA91");

            Desfire desfire = new Desfire(transmitter, DesfireIsoWrapping.None);
            desfire.SetLogger(new Logger(), true, true);

            desfire.SessionCryptoContext = new DesfireCryptoContextEV2(desfire, new byte[16]);

            (desfire.SessionCryptoContext as DesfireCryptoContextEV2).ImportSessionKeys(null, BinConvert.HexToBytes("936F81529886567E164402DD6531F5E8"));
            (desfire.SessionCryptoContext as DesfireCryptoContextEV2).ImportTransaction(BinConvert.HexToBytes("0EF80413"), 2);

            if (desfire.CreateApplication(
                Aid: 0xC2C11F,
                KeySetting1: 0x1F,
                KeySetting2: 0xB5,
                KeySetting3: 0x01,
                AksVersion: 0x00,
                NoKeySets: 0x04,
                MaxKeySize: 0x10,
                AppKeySetSetting: 0x02,
                IsoDfId: 0x2211,
                IsoDfName: BinConvert.HexToBytes("010203040506")) != Success)
                goto failed;

            Logger.Info("CreateApplication OK");
            return;

        failed:
            throw new Exception("DesfireEV2 self-test [CreateApplication] failed");
        }

        /*
         * Reference: AN14212 - Table 52. Encryption of AppDAMDefaultKey and Table 53. DAMMAC Generation
         */
        public static void DesfireEV2SelfTest_DAM()
        {
            Desfire desfire = new Desfire(null, DesfireIsoWrapping.None);
            desfire.SetLogger(new Logger(), true, true);
            desfire.SetRandomGenerator(new FakeRandomGenerator(BinConvert.HexToBytes("FF710170C69EF0")));

            if (desfire.PrepareCreateDelegatedApplication(
                PiccDamEncKey: BinConvert.HexToBytes("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
                PiccDamMacKey: BinConvert.HexToBytes("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
                Aid: 0xD2D11F,
                DAMSlotNumber: 0x0002,
                DAMSlotVersion: 0x01,
                QuotaLimit: 0x0020,
                KeySetting1: 0x1F,
                KeySetting2: 0xB5,
                KeySetting3: 0x01,
                AksVersion: 0x00,
                NoKeySets: 0x04,
                MaxKeySize: 0x10,
                AppKeySetSetting: 0x02,
                IsoDfId: 0x2211,
                IsoDfName: BinConvert.HexToBytes("010203040506"),
                DefaultKeyValue: BinConvert.HexToBytes("00112233445566778899AABBCCDDEEFF0011223344556677"),
                DefaultKeyVersion: 0x00,
                out byte[] DefaultKeyEnc,
                out byte[] DamMac) != Success)
                goto failed;

            Logger.Info("PrepareCreateDelegatedApplication OK");

            if (!BinUtils.Equals(DefaultKeyEnc, BinConvert.HexToBytes("FFDAB2B5080B7239DFA6D782607E7B0458297C8EDEC21509D8B3D31240664E8D")))
                goto failed;

            Logger.Info("EncK OK");

            if (!BinUtils.Equals(DamMac, BinConvert.HexToBytes("0D62E6F221C981C7")))
                goto failed;

            Logger.Info("DAMMAC OK");

            return;

        failed:
            throw new Exception("DesfireEV2 self-test [DAM] failed");
        }


        /*
         * Reference: AN14212 - Table 51. Create Conventional Application in EV2 Securing Messaging
         */
        public static void DesfireEV2SelfTest_CreateDelegatedApplication()
        {
            FakeCardTransmitter transmitter = new FakeCardTransmitter();

            transmitter.AddApduPair("C91FD1D202000120001FB501000410021122010203040506", "AF");
            transmitter.AddApduPair("AFFFDAB2B5080B7239DFA6D782607E7B0458297C8EDEC21509D8B3D31240664E8D0D62E6F221C981C78AE8B0874A42EC6D", "0019802F4A92D58F81");

            Desfire desfire = new Desfire(transmitter, DesfireIsoWrapping.None);
            desfire.SetLogger(new Logger(), true, true);

            desfire.SessionCryptoContext = new DesfireCryptoContextEV2(desfire, new byte[16]);

            (desfire.SessionCryptoContext as DesfireCryptoContextEV2).ImportSessionKeys(new byte[16], BinConvert.HexToBytes("446B1DC31F8C136605BB9A527F4B23B9"));
            (desfire.SessionCryptoContext as DesfireCryptoContextEV2).ImportTransaction(BinConvert.HexToBytes("26973400"), 0);

            if (desfire.CreateDelegatedApplication(
                Aid: 0xD2D11F,
                DAMSlotNumber: 0x0002,
                DAMSlotVersion: 0x01,
                QuotaLimit: 0x0020,
                KeySetting1: 0x1F,
                KeySetting2: 0xB5,
                KeySetting3: 0x01,
                AksVersion: 0x00,
                NoKeySets: 0x04,
                MaxKeySize: 0x10,
                AppKeySetSetting: 0x02,
                IsoDfId: 0x2211,
                IsoDfName: BinConvert.HexToBytes("010203040506"),
                DefaultAppKeyEnc: BinConvert.HexToBytes("FFDAB2B5080B7239DFA6D782607E7B0458297C8EDEC21509D8B3D31240664E8D"),
                DamMac: BinConvert.HexToBytes("0D62E6F221C981C7")) != Success)
                goto failed;

            Logger.Info("CreateDelegatedApplication OK");

            return;

        failed:
            throw new Exception("DesfireEV2 self-test [CreateDelegatedApplication] failed");
        }
    }
}
