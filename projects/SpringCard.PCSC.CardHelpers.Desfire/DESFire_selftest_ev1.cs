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
using System.Security.Cryptography;


namespace SpringCard.PCSC.CardHelpers
{
    public partial class Desfire
    {
        /**
         * @brief Self-test for DESFire EV1
         */
        public static void DesfireEV1SelfTest()
        {
            DesfireEV1SelfTest_Tdes2kAuth();
            DesfireEV1SelfTest_Tdes3kAuth();
            DesfireEV1SelfTest_AesAuth();
            DesfireEV1SelfTest_ChangeKey_1();
            DesfireEV1SelfTest_ChangeKey_2();
            DesfireEV1SelfTest_ChangeKey_3();
            DesfireEV1SelfTest_WriteData_Mac();
            //DesfireEV1SelfTest_ReadData_Mac();
            //            DesfireEV1SelfTest_WriteData_Full();
            //DesfireEV2SelfTest_ReadData_Full();
        }

        public static void DesfireEV1SelfTest_Tdes2kAuth()
        {
            FakeCardTransmitter transmitter = new FakeCardTransmitter();

            transmitter.AddApduPair("1A00", "AFD3C84E1AAB3AA692");
            transmitter.AddApduPair("AF58B8AE456571C577CD21D082B693EA3D", "00DC9A5F5B3F8DE04E");

            FakeRandomGenerator fakeRandomGenerator = new FakeRandomGenerator(BinConvert.HexToBytes("FE07A026547F0BAE"));

            Desfire desfire = new Desfire(transmitter, DesfireIsoWrapping.None);
            desfire.SetLogger(new Logger(), true, true);
            desfire.SetRandomGenerator(fakeRandomGenerator);

            Logger.Info("AuthenticateISO");

            if (desfire.AuthenticateEV1TDes(0x00, new byte[16]) != Success)
                goto failed;

            Logger.Info("AuthenticateISO OK");

            (desfire.SessionCryptoContext as DesfireCryptoContextEV1).ExportSessionKey(out byte[] sessionKey);

            if (!BinUtils.Equals(sessionKey, BinConvert.HexToBytes("FE07A026682EB9D7FE07A026682EB9D7")))
                goto failed;

            Logger.Info("Session Key OK");

            Logger.Info("Cmac Key OK");
            return;

        failed:
            throw new Exception("DesfireEV1 self-test [3DES-2K Auth] failed");
        }

        public static void DesfireEV1SelfTest_Tdes3kAuth()
        {
            FakeCardTransmitter transmitter = new FakeCardTransmitter();

            transmitter.AddApduPair("1A00", "AF256C4ED82E8045AD40BE7954F041363E");
            transmitter.AddApduPair("AF25971BEB5B983750659F95ADE9F13B7CB1D42FB5F5EB814776E95FF3C5EE7988", "00E5D994F7A8F7C8FA8FE8FB40C00A5945");

            FakeRandomGenerator fakeRandomGenerator = new FakeRandomGenerator(BinConvert.HexToBytes("D23F9B11C35CB2C10DB15D01CB38BE37"));

            Desfire desfire = new Desfire(transmitter, DesfireIsoWrapping.None);
            desfire.SetLogger(new Logger(), true, true);
            desfire.SetRandomGenerator(fakeRandomGenerator);

            Logger.Info("AuthenticateISO");

            if (desfire.AuthenticateEV1TDes(0x00, new byte[24]) != Success)
                goto failed;

            Logger.Info("AuthenticateISO OK");

            (desfire.SessionCryptoContext as DesfireCryptoContextEV1).ExportSessionKey(out byte[] sessionKey);

            if (!BinUtils.Equals(sessionKey, BinConvert.HexToBytes("D23F9B11AC940BC1B2C10DB16D74A9BACB38BE37ED3DFC92")))
                goto failed;

            Logger.Info("Session Key OK");

            Logger.Info("Cmac Key OK");
            return;

        failed:
            throw new Exception("DesfireEV1 self-test [3DES-3K Auth] failed");
        }


        public static void DesfireEV1SelfTest_AesAuth()
        {
            FakeCardTransmitter transmitter = new FakeCardTransmitter();

            transmitter.AddApduPair("AA00", "AFC5537C8EFFFCC7E152C27831AFD383BA");
            transmitter.AddApduPair("AF1EF512D957973AED7E6E13991EB0FB431B373EA23400A3AC0B7749CD6FB1C328", "00FFC212245F03DB0EA0645A495190952A");

            FakeRandomGenerator fakeRandomGenerator = new FakeRandomGenerator(BinConvert.HexToBytes("2347C1557F80707ABDFF86BF9D965CA7"));

            Desfire desfire = new Desfire(transmitter, DesfireIsoWrapping.None);
            desfire.SetLogger(new Logger(), true, true);
            desfire.SetRandomGenerator(fakeRandomGenerator);

            Logger.Info("AuthenticateAes");

            if (desfire.AuthenticateEV1Aes(0x00, new byte[16]) != Success)
                goto failed;

            Logger.Info("AuthenticateAes OK");

            (desfire.SessionCryptoContext as DesfireCryptoContextEV1).ExportSessionKey(out byte[] sessionKey);

            if (!BinUtils.Equals(sessionKey, BinConvert.HexToBytes("2347C1551EA0353A9D965CA7B52FCA84")))
                goto failed;

            Logger.Info("Session Key OK");

            Logger.Info("Cmac Key OK");
            return;

        failed:
            throw new Exception("DesfireEV1 self-test [Aes Auth] failed");
        }

        public static void DesfireEV1SelfTest_ChangeKey_1()
        {
            FakeCardTransmitter transmitter = new FakeCardTransmitter();

            transmitter.AddApduPair("C480440FE29FF2E51AD18AA105C125CDC1F3B81590984219EAB1", "00");

            Desfire desfire = new Desfire(transmitter, DesfireIsoWrapping.None);
            desfire.SetLogger(new Logger(), true, true);

            desfire.SessionCryptoContext = new DesfireCryptoContextEV1TDes(desfire, new byte[16]);

            (desfire.SessionCryptoContext as DesfireCryptoContextEV1TDes).ImportSessionKey(BinConvert.HexToBytes("DAFF378C024610FBDAFF378C024610FB"));

            if (desfire.ChangeKey(0x80, 0x00, new byte[16], null) != Success)
                goto failed;

            Logger.Info("ChangeKey 1 OK");
            return;

        failed:
            throw new Exception("DesfireEV1 self-test [ChangeKey 1] failed");
        }

        public static void DesfireEV1SelfTest_ChangeKey_2()
        {
            FakeCardTransmitter transmitter = new FakeCardTransmitter();

            transmitter.AddApduPair("C401E4CDFCD2D335CCAAB4BB602805B9DAAFFB1B84FE4E4952DD0B9E2F20BB4C789C", "0002BC7F4ACA83DA63");

            Desfire desfire = new Desfire(transmitter, DesfireIsoWrapping.None);
            desfire.SetLogger(new Logger(), true, true);

            desfire.SessionCryptoContext = new DesfireCryptoContextEV1Aes(desfire, new byte[16]);

            (desfire.SessionCryptoContext as DesfireCryptoContextEV1Aes).ImportSessionKey(BinConvert.HexToBytes("5DD4CBFC20A1988E1CDBAE322B315D57"));
            (desfire.SessionCryptoContext as DesfireCryptoContextEV1Aes).ImportInitVector(BinConvert.HexToBytes("70873F2D468019A38E7184FE5208F607"));

            if (desfire.ChangeKey(0x01, 0x03, BinConvert.HexToBytes("A0A1A2A3A4A5A6A7A8A9AAABACADAEAF"), BinConvert.HexToBytes("00112233445566778899AABBCCDDEEFF")) != Success)
                goto failed;

            Logger.Info("ChangeKey 2 OK");
            return;

        failed:
            throw new Exception("DesfireEV1 self-test [ChangeKey 2] failed");
        }

        public static void DesfireEV1SelfTest_ChangeKey_3()
        {
            FakeCardTransmitter transmitter = new FakeCardTransmitter();

            transmitter.AddApduPair("C400B679B08051DA0A62D14C3544A968C943636A2815165E1FB7C1DCC839CFCD3D94", "00");

            Desfire desfire = new Desfire(transmitter, DesfireIsoWrapping.None);
            desfire.SetLogger(new Logger(), true, true);

            desfire.SessionCryptoContext = new DesfireCryptoContextEV1Aes(desfire, new byte[16]);

            (desfire.SessionCryptoContext as DesfireCryptoContextEV1Aes).ImportSessionKey(BinConvert.HexToBytes("04BC99A81DB7293FAA86CA225ECD7660"));

            if (desfire.ChangeKey(0x00, 0x01, BinConvert.HexToBytes("B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"), null) != Success)
                goto failed;

            Logger.Info("ChangeKey 3 OK");
            return;

        failed:
            throw new Exception("DesfireEV1 self-test [ChangeKey 3] failed");
        }

        public static void DesfireEV1SelfTest_WriteData_Mac()
        {
            FakeCardTransmitter transmitter = new FakeCardTransmitter();

            transmitter.AddApduPair("3D01000000120000010203040506070809101112131415161718C15BFD83F9021869", "00AD37516C1029640E");

            Desfire desfire = new Desfire(transmitter, DesfireIsoWrapping.None);
            desfire.SetLogger(new Logger(), true, true);

            desfire.SessionCryptoContext = new DesfireCryptoContextEV1TDes(desfire, new byte[16]);

            (desfire.SessionCryptoContext as DesfireCryptoContextEV1TDes).ImportSessionKey(BinConvert.HexToBytes("7EBBEA1BA4A399EF7EBBEA1BA4A399EF"));

            if (desfire.WriteData(0x01, DesfireCommMode.Maced, BinConvert.HexToBytes("010203040506070809101112131415161718")) != Success)
                goto failed;

            Logger.Info("WriteData MAC OK");
            return;

        failed:
            throw new Exception("DesfireEV1 self-test [WriteData MAC] failed");
        }

        public static void DesfireEV1SelfTest_ReadData_Mac()
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
            throw new Exception("DesfireEV1 self-test [ReadData MAC] failed");
        }

        public static void DesfireEV1SelfTest_WriteData_Full()
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
            throw new Exception("DesfireEV1 self-test [WriteData Full] failed");
        }

        public static void DesfireEV1SelfTest_ReadData_Full()
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

            throw new Exception("DesfireEV1 self-test [ReadData Full] failed");
            return;

        failed:
            throw new Exception("DesfireEV2 self-test [ReadData Full] failed");
        }
    }
}
