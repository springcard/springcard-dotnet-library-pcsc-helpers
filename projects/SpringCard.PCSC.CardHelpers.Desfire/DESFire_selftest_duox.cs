/*
 * SpringCard DESFire Library (C#)
 * Copyright (c) SpringCard SAS, 2008-2025
 *
 * This file is part of the SpringCard DESFire library.
 * See LICENSE.txt for license details and restrictions.
 *
 */
using Org.BouncyCastle.Crypto.Parameters;
using SpringCard.LibCs;
using System;

namespace SpringCard.PCSC.CardHelpers
{
    public partial class Desfire
    {
        /**
         * @brief Self-test for Mifare DuoX
         */
        public static void MifareDuoXSelfTest()
        {
            MifareDuoX_SessionKeysSelfTest();
            MifareDuoX_AsymmetricAuthenticationSelfTest();
            MifareDuoX_Sylvain();
            throw new Exception("DuoX Self Test done");
        }

        public static void MifareDuoX_Sylvain()
        {
            //FakeCardTransmitter transmitter = new FakeCardTransmitter();

            //const string PriKey0 = "C28276FC8DB6CF1040B635E3E5BACCE0EFA32FAA03C812B340916BB306CC2972";
            //const string PubKey1 = "040C5E10F8F81588695F1B05707FB8F0BA69F70026D9159B04C69255EA486DEE331FFE6A17AE8DB65F4A13801CD744726255D1F0C2B20506DCEE1479E885C3C394";

            //Desfire instance = new Desfire(transmitter, DesfireIsoWrapping.Disabled);

            //instance.ISOGeneralAuthenticate(0x00, new byte[] { 0x80, 0x04, 0x80, 0x00, 0x01, 0x00 }, BinConvert.ToHex())
        }

        /*
         * Reference: AN14212 - Table 10. Asymmetric Authentication example
         */
        public static void MifareDuoX_AsymmetricAuthenticationSelfTest()
        {
            FakeCardTransmitter transmitter = new FakeCardTransmitter();
            transmitter.SetLogger(new Logger());

            transmitter.AddApduPair("CA112233EF82", "00");
            transmitter.AddApduPair("6A", "00112233");
            transmitter.AddApduPair("5A112233", "00");
            transmitter.AddApduPair("710000", "AFC2608B2435091745EAB945422EB55E8C");
            transmitter.AddApduPair("AFB2BC27411F637A20087F9C0ED302163B86E9AD39A17A59A4BCBDC2D90C788ED3", "00B47E279491117E9962749F7A67AC611323D3A57A4FC0E68828B1B3D516C820E3");
            transmitter.AddApduPair("4600010C80013000000000DB667013666476F61CD0659154EA2471EB586F0A5813387725B699D8AA073FC44C9F38F5402EB0056E96D7E6D76C7838621EA26DC0A26B36", "00DF624DF633FF561C");
            transmitter.AddApduPair("48000C03003030000000009004CDB544E1858E5CD7E41D7C56D3648FE12387FD31A1B44F623AC04A9FA8A424496E0D842B48E2517E86B9C9B5C9B4B673EA874E7694DF76307838EF502C7DA129E72269385712F25F741F91FADE57EE32ECA6E9BE75E3", "0099B34C563C1417CE");
            transmitter.AddApduPair("CD0000EEEE0003002F874DD912889D97", "00FFF513147D34AB12");
            transmitter.AddApduPair("3D000000004A0100470100308201433081EAA003020102020ACCCCCCCCCCCCCCCCCCCC300A06082A8648CE3D040302301B31193017060355040A0C10", "AF");
            transmitter.AddApduPair("AFCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC3022180F31393730303130313030303030305A180F39393939313233313233353935395A302F3114301206", "AF");
            transmitter.AddApduPair("AF0355042D030B00CCCCCCCCCCCCCCCCCCCC31173015060355040D0C0ECCCCCCCCCCCCCCCCCCCCCCCCCCCC3059301306072A8648CE3D020106082A86", "AF");
            transmitter.AddApduPair("AF48CE3D030107034200040889CA87F0E97C088C596F3F50EEC82D295549BB2B20956176F3B5B0B2EC5F8F559396958821F723A3C46684EC2B9BDB74", "AF");
            transmitter.AddApduPair("AFD4F3B69D3F8F195EB0E9C8CA911836300A06082A8648CE3D0403010348003045022037DCF93C46E012AC2D14738D04BB3D71BC7DDCE85DDA3A23AA", "AF");
            transmitter.AddApduPair("AF2F3F31C25340A402210082389BEC11BCB0EC560D6C8AB601183E5F800E7BD50E68185B3BE60665335EC3", "00");
            transmitter.AddApduPair("008700004B8004800000007C43854104CA7D8D8830F3EF470BD2EB62A1A1A9289527F425820D86A9B991E7206816C2E6B6F39D8824CFD56DD2EEC68EED4E7B09F70870F1B8AA8EA25F61125E9B25947B00", "7C438541040E4022C213C687114D74FBC0F20EC3850A356734A5E709A1F8F37F6614500BCC62D6841EF96B3178BB1193805F0DA1D674E11F3E8C6814AD457527DF2329CF2E9000");
            transmitter.AddApduPair("008700000001787C8201748682017013E1AC28897AA234A7D16390B351C670EEB1B4FAF914F0BC5BF146D89F41B316568E2FC3E86E1E8FD01D6D61B8F5DC88DE1FBACDB98BE697CC5E524C38C06A5E1836ED57AD25E4E3DDD0DB9FEB38C75A58FE1934A9DDCE6CCEACCE7F828CB33ABBBEA374C373A6EF2196F9F4A6CF7A5DA099FD213BC29D790339B0D93240E1FB16FD741E54257919E9FD1F741086A4A2C34D6001BB511DE7A4601D5B06E1FB8D3A889F7A4D150004F9D7C31A97C6F73E098493B6FCA4935818C5A763ADC5C3C9183EC4FDE84C8A352CA9AAF88B55C2C98877B16454B8133704A8F9657C69404FC106DB8FBAE50136634C5B6BD6D044CCBF7130598927DD67A550AA84692C4A9D037227CD081B3057B2756890B0B83C5ACFF5AE48078178AEFDE774E931510852086DF2E8D937DF69174C61D030C189BD7AEBEFDD6FCF54ED457ADA3C7A52A5E895E0612326D6197DDB977CE5FD2D2EBE33C3459B1F645846E39E424A15A05152FA3920401557378B243481F7FE502EC30000", "7C8201A4828201A05980ADC660208DB284ABB4C68E181C9FF9A75E846505B73C956848C356E8BA9AD5E882940E2B53F39302DF3980C83875AEF18DEACD42003F2756F757FDE44015856A91EAF41C6EC673946C72FF8E1F3E662FF562338B1E7B6D327BC55E0605E5DE2D43B7C1141F839C07720C15D84EF9DF90262C3B4C9F047A9E80F337D25AD0F925D11A17E7FD991BF8E872862F45F2E8A4BDF4A6401179B834B63DCFA023820E554EBC91ED9A0E6A2F7C1AE2EFAD4B0E640507B77CA436811B9D1FECE949CC6C867C4EACFBE26A67997465F70C27768DB0942B174760910F7E01265E061FA826DB7A9CCD4CA26406FF91825E325D7BA45A2557C5907BC9F2E8181E1C593A22F5A1B02C1E7003C09CDE1B10A9B7E2A07D8DF2D51E2B03EB5F3D8E026E5F11D12A19C97DD2DB8985830463B2F5EE26297733BC64FF747152383F550905D25B68045F055E851716FAB45A8D5004B3480621381B864224527C516B816A56117FB779E726AF225D9BD278EDEA7D769ED8A2A07C6E4F2C21AE279EC3A633429ABD942BCADD68985CA3C98ED281CAEC51DFCCF72049D7326C21789084FE9F042E78499000");

            // const string TestPriKey = "DB667013666476F61CD0659154EA2471EB586F0A5813387725B699D8AA073FC44C9F38F5402EB0056E96D7E6D76C7838621EA26DC0A26B36";

            const string PiccPriKey = "50FF451C5824781D57755C5B02CB563F150644FA693235806625123717F05D28";
            const string PiccPubKey = "040889CA87F0E97C088C596F3F50EEC82D295549BB2B20956176F3B5B0B2EC5F8F559396958821F723A3C46684EC2B9BDB74D4F3B69D3F8F195EB0E9C8CA911836";

            const string CARootPriKey = "51711459434A0C68386C42B54B8A01E8546B037E2C1953BD6FA63DDF1E074B06";
            const string CARootPubKey = "04D00D763909DE8017376DF143124AB251D926B040E1173D04C62FE8C1ADA0F2BC20865E605C6971F3293DEEBD93019712BDF1AD1EEC5C9C39E25C7D05005B49F5";

            const string PcdLTPriKey = "C28276FC8DB6CF1040B635E3E5BACCE0EFA32FAA03C812B340916BB306CC2972";
            // const string PcdPubKey = "040C5E10F8F81588695F1B05707FB8F0BA69F70026D9159B04C69255EA486DEE331FFE6A17AE8DB65F4A13801CD744726255D1F0C2B20506DCEE1479E885C3C39400";

            const string PcdCertA = "308201283081D0A00302010202040102BD16300A06082A8648CE3D0403023020311E301C060355042D0315003F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F301E170D3231303230333231313534305A170D3235313230383231313534305A301A31183016060355042D030F0072656164657220656E646C6561663059301306072A8648CE3D020106082A8648CE3D030107034200040C5E10F8F81588695F1B05707FB8F0BA69F70026D9159B04C69255EA486DEE331FFE6A17AE8DB65F4A13801CD744726255D1F0C2B20506DCEE1479E885C3C394300A06082A8648CE3D040302034700304402200873D566987981257752DA7930B68BEFD39BE17118ED3217AC421B1B06BF2D6602206E2A840D42D3F1A19453E5894B6A36DC56298BEE504416F72970A55CDEA28153";
            const string PiccCertA = "470100308201433081EAA003020102020ACCCCCCCCCCCCCCCCCCCC300A06082A8648CE3D040302301B31193017060355040A0C10CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC3022180F31393730303130313030303030305A180F39393939313233313233353935395A302F31143012060355042D030B00CCCCCCCCCCCCCCCCCCCC31173015060355040D0C0ECCCCCCCCCCCCCCCCCCCCCCCCCCCC3059301306072A8648CE3D020106082A8648CE3D030107034200040889CA87F0E97C088C596F3F50EEC82D295549BB2B20956176F3B5B0B2EC5F8F559396958821F723A3C46684EC2B9BDB74D4F3B69D3F8F195EB0E9C8CA911836300A06082A8648CE3D0403010348003045022037DCF93C46E012AC2D14738D04BB3D71BC7DDCE85DDA3A23AA2F3F31C25340A402210082389BEC11BCB0EC560D6C8AB601183E5F800E7BD50E68185B3BE60665335EC3";

            const string PcdTempPubKey = "04CA7D8D8830F3EF470BD2EB62A1A1A9289527F425820D86A9B991E7206816C2E6B6F39D8824CFD56DD2EEC68EED4E7B09F70870F1B8AA8EA25F61125E9B25947B";
            const string PcdEncMessage = "13E1AC28897AA234A7D16390B351C670EEB1B4FAF914F0BC5BF146D89F41B316568E2FC3E86E1E8FD01D6D61B8F5DC88DE1FBACDB98BE697CC5E524C38C06A5E1836ED57AD25E4E3DDD0DB9FEB38C75A58FE1934A9DDCE6CCEACCE7F828CB33ABBBEA374C373A6EF2196F9F4A6CF7A5DA099FD213BC29D790339B0D93240E1FB16FD741E54257919E9FD1F741086A4A2C34D6001BB511DE7A4601D5B06E1FB8D3A889F7A4D150004F9D7C31A97C6F73E098493B6FCA4935818C5A763ADC5C3C9183EC4FDE84C8A352CA9AAF88B55C2C98877B16454B8133704A8F9657C69404FC106DB8FBAE50136634C5B6BD6D044CCBF7130598927DD67A550AA84692C4A9D037227CD081B3057B2756890B0B83C5ACFF5AE48078178AEFDE774E931510852086DF2E8D937DF69174C61D030C189BD7AEBEFDD6FCF54ED457ADA3C7A52A5E895E0612326D6197DDB977CE5FD2D2EBE33C3459B1F645846E39E424A15A05152FA3920401557378B243481F7FE502EC3";

            const uint Aid = 0x332211;
            byte[] BlankKey = new byte[16];

            Desfire instance = new Desfire(transmitter, DesfireIsoWrapping.None);
            instance.SetLogger(new Logger());

            ECC.PrivateToPublic(MifareDuoXEccCurve.NistP256, BinConvert.HexToBytes(PiccPriKey), out byte[] _PiccPubKey);
            Logger.Trace("PiccPubKey: {0}", BinConvert.ToHex(_PiccPubKey));
            if (BinConvert.ToHex(_PiccPubKey) != PiccPubKey)
            {
                Logger.Error("Failed to retrieve the Pub Key of the Picc");
                goto failed;
            }

            ECC.PrivateToPublic(MifareDuoXEccCurve.NistP256, BinConvert.HexToBytes(CARootPriKey), out byte[] _CARootPubKey);
            Logger.Trace("CA PubKey:  {0}", BinConvert.ToHex(_CARootPubKey));
            if (BinConvert.ToHex(_CARootPubKey) != CARootPubKey)
            {
                Logger.Error("Failed to retrieve the Pub Key of the CA");
                goto failed;
            }

            DesfireCryptoContextEV2 crypto = new DesfireCryptoContextEV2(instance, BlankKey);

            crypto.ProcessAuth1(BinConvert.HexToBytes(/* AF */ "C2608B2435091745EAB945422EB55E8C"), out byte[] _dummy);
            Logger.Trace("RndPicc:    {0}", BinConvert.ToHex(crypto.AuthRndPicc));

            crypto.ProcessAuth2First(BinConvert.HexToBytes(/* 00 */ "B47E279491117E9962749F7A67AC611323D3A57A4FC0E68828B1B3D516C820E3"), out byte[] TransactionIdentifier, out byte[] PiccCaps2, out byte[] PcdCaps2);
            Logger.Trace("RndPcd:     {0}", BinConvert.ToHex(crypto.AuthRndPcd));

            Logger.Trace("TI:         {0}", BinConvert.ToHex(TransactionIdentifier));
            Logger.Trace("PiccCaps:   {0}", BinConvert.ToHex(PiccCaps2));
            Logger.Trace("PcdCaps:    {0}", BinConvert.ToHex(PcdCaps2));

            //instance.DecodeAuthenticateEV2First1(BinConvert.HexToBytes("AFC2608B2435091745EAB945422EB55E8C"), BlankKey, out byte[] RndPicc1);

            //instance.DecodeAuthenticateEV2First2(BinConvert.HexToBytes("AFB2BC27411F637A20087F9C0ED302163B86E9AD39A17A59A4BCBDC2D90C788ED3"), BlankKey, out byte[] RndPicc2, out byte[] RndPcd1);
            //Logger.Trace("RndPicc:    {0}", BinConvert.ToHex(RndPicc2));

            //instance.DecodeAuthenticateEV2First3(BinConvert.HexToBytes("00B47E279491117E9962749F7A67AC611323D3A57A4FC0E68828B1B3D516C820E3"), BlankKey, out byte[] RndPcd2, out byte[] TransactionIdentifier, out byte[] PiccCaps2, out byte[] PcdCaps2);
            //Logger.Trace("RndPcd:     {0}", BinConvert.ToHex(RndPcd2));

            instance.SetRandomGenerator(new FakeRandomGenerator(BinConvert.HexToBytes("549ECF061D6DBFE2CEB7F2B36C9405C3")));
            instance.SetLogger(new Logger());

            if (instance.CreateApplication(Aid, 0xEF, 0x82) != 0)
                goto failed;
            if (instance.GetApplicationIDs(out uint[] AidList) != 0)
                goto failed;
            if (instance.SelectApplication(Aid) != 0)
                goto failed;
            if (instance.AuthenticateEV2First(0x00, BlankKey) != 0)
                goto failed;
            if (instance.ImportPrivateKey(0x00, (byte)MifareDuoXEccCurve.NistP256, 0x0180, 0x30, 0, BinConvert.HexToBytes(PiccPriKey)) != 0)
                goto failed;
            if (instance.ManageCARootKey(0x00, (byte)MifareDuoXEccCurve.NistP256, 0x0080, 0x30, 0x30, BinConvert.HexToBytes(CARootPubKey), (byte)DesfireCommMode.Full) != 0)
                goto failed;
            if (instance.CreateStdDataFile(0x00, (byte)DesfireCommMode.Plain, 0xEEEE, 0x00300) != 0)
                goto failed;
            if (instance.WriteData(0x00, (byte)DesfireCommMode.Plain, BinConvert.HexToBytes(PiccCertA)) != 0)
                goto failed;
            if (instance.IsoGeneralAuthenticateMutual(
                MifareDuoXEccCurve.NistP256,
                0x00,
                0x00,
                BinConvert.HexToBytes(PcdLTPriKey),
                BinConvert.HexToBytes(PcdCertA),
                0,
                false,
                0,
                out byte[] PiccOptions,
                out byte[] PiccCertificate) != 0)
                goto failed;


            return;

            failed:
            throw new Exception("DuoXAsymmetricAuthenticationSelfTest failed");
        }

        /*
         * Reference: AN14212 - Table 11. Numerical example of session key generation during asymmetric authentication
         */
        public static void MifareDuoX_SessionKeysSelfTest()
        {
            const string EPubA = "04CA7D8D8830F3EF470BD2EB62A1A1A9289527F425820D86A9B991E7206816C2E6B6F39D8824CFD56DD2EEC68EED4E7B09F70870F1B8AA8EA25F61125E9B25947B";
            const string EPubB = "040E4022C213C687114D74FBC0F20EC3850A356734A5E709A1F8F37F6614500BCC62D6841EF96B3178BB1193805F0DA1D674E11F3E8C6814AD457527DF2329CF2E";
            const string SharedSecret = "DF7FD83547C1551B0A1E9A0421CFD6E1721D7FE4B51534652FEFA2222A775506";

            const string OptionsA = "80000000";

            const string LTPubA = "040C5E10F8F81588695F1B05707FB8F0BA69F70026D9159B04C69255EA486DEE331FFE6A17AE8DB65F4A13801CD744726255D1F0C2B20506DCEE1479E885C3C394";
            const string LTPubB = "040889CA87F0E97C088C596F3F50EEC82D295549BB2B20956176F3B5B0B2EC5F8F559396958821F723A3C46684EC2B9BDB74D4F3B69D3F8F195EB0E9C8CA911836";

            const string SesAuthEncKey = "062CCA3C1B1A889164A21873B13D2C26";
            const string SesAuthMacKey = "070FA8F70C57AF7DE92AA386F1B0F04E";

            Desfire instance = new Desfire(null, DesfireIsoWrapping.None);

            instance.SetLogger(new Logger());

            instance.SessionCryptoContext = new DesfireCryptoContextDuoX(instance);

            (instance.SessionCryptoContext as DesfireCryptoContextDuoX).GenerateSessionKeysDuoX(BinConvert.HexToBytes(EPubA), BinConvert.HexToBytes(EPubB), BinConvert.HexToBytes(SharedSecret));
            (instance.SessionCryptoContext as DesfireCryptoContextDuoX).ExportSessionKeys(out byte[] aSesAuthEncKey, out byte[] aSesAuthMacKey);

            Logger.Info("K SesAuthENC = {0} {1}", BinConvert.ToHex(aSesAuthEncKey), SesAuthEncKey);
            Logger.Info("K SesAuthENC = {0} {1}", BinConvert.ToHex(aSesAuthMacKey), SesAuthMacKey);

            if (BinConvert.ToHex(aSesAuthEncKey) != SesAuthEncKey)
            {
                Logger.Error("Failed to recover the Encryption key");
                goto failed;
            }

            if (BinConvert.ToHex(aSesAuthMacKey) != SesAuthMacKey)
            {
                Logger.Error("Failed to recover the CMAC key");
                goto failed;
            }

            /* From General Authenticate Part 2 Command */
            byte[] EncMsgA = BinConvert.HexToBytes("13E1AC28897AA234A7D16390B351C670EEB1B4FAF914F0BC5BF146D89F41B316568E2FC3E86E1E8FD01D6D61B8F5DC88DE1FBACDB98BE697CC5E524C38C06A5E1836ED57AD25E4E3DDD0DB9FEB38C75A58FE1934A9DDCE6CCEACCE7F828CB33ABBBEA374C373A6EF2196F9F4A6CF7A5DA099FD213BC29D790339B0D93240E1FB16FD741E54257919E9FD1F741086A4A2C34D6001BB511DE7A4601D5B06E1FB8D3A889F7A4D150004F9D7C31A97C6F73E098493B6FCA4935818C5A763ADC5C3C9183EC4FDE84C8A352CA9AAF88B55C2C98877B16454B8133704A8F9657C69404FC106DB8FBAE50136634C5B6BD6D044CCBF7130598927DD67A550AA84692C4A9D037227CD081B3057B2756890B0B83C5ACFF5AE48078178AEFDE774E931510852086DF2E8D937DF69174C61D030C189BD7AEBEFDD6FCF54ED457ADA3C7A52A5E895E0612326D6197DDB977CE5FD2D2EBE33C3459B1F645846E39E424A15A05152FA3920401557378B243481F7FE502EC3");

            /*
             * CLA INS  P1  P2     LC
             *  00  87  00  00 000178
             *  
             * DATA
             *  T  L      V
             *  7C 820174 
             *            T  L      V
             *            86 820170 13E1AC28897AA234A7D16390B351C670EEB1B4FAF914F0BC5BF146D89F41B316568E2FC3E86E1E8FD01D6D61B8F5DC88DE1FBACDB98BE697CC5E524C38C06A5E1836ED57AD25E4E3DDD0DB9FEB38C75A58FE1934A9DDCE6CCEACCE7F828CB33ABBBEA374C373A6EF2196F9F4A6CF7A5DA099FD213BC29D790339B0D93240E1FB16FD741E54257919E9FD1F741086A4A2C34D6001BB511DE7A4601D5B06E1FB8D3A889F7A4D150004F9D7C31A97C6F73E098493B6FCA4935818C5A763ADC5C3C9183EC4FDE84C8A352CA9AAF88B55C2C98877B16454B8133704A8F9657C69404FC106DB8FBAE50136634C5B6BD6D044CCBF7130598927DD67A550AA84692C4A9D037227CD081B3057B2756890B0B83C5ACFF5AE48078178AEFDE774E931510852086DF2E8D937DF69174C61D030C189BD7AEBEFDD6FCF54ED457ADA3C7A52A5E895E0612326D6197DDB977CE5FD2D2EBE33C3459B1F645846E39E424A15A05152FA3920401557378B243481F7FE502EC3
             *            
             *                         LE
             *                         0000
            */

            byte[] buffer = BinUtils.Copy(EncMsgA);
            Logger.Info("MsgA Ciphered: {0}", BinConvert.ToHex(buffer));
            (instance.SessionCryptoContext as DesfireCryptoContextDuoX).CipherRecvEx(ref buffer, true);
            if (!(instance.SessionCryptoContext as DesfireCryptoContextDuoX).Unpadd(ref buffer))
            {
                Logger.Error("Failed to unpadd Msg.A");
                goto failed;
            }
            Logger.Info("MsgA Plain: {0}", BinConvert.ToHex(buffer));

            byte[] MsgA = BinUtils.Copy(buffer);

            if ((MsgA[0] != 0xE0) || (MsgA[1] != 0xE0))
            {
                Logger.Error("Failed to decipher Msg.A.Enc");
                goto failed;
            }

            byte[] SigA = null;

            if (MsgA.Length > 2 + 64 + 2)
            {
                /* It seems that we have E0E0 || CertA || SigA */
                Asn1Tlv tlvCertificate = Asn1Tlv.Deserialize(BinUtils.Copy(MsgA, 2, MsgA.Length - 2), out buffer);
                Logger.Info(tlvCertificate.ToString());
                SigA = BinUtils.Copy(buffer);
            }
            else if (MsgA.Length == 2 + 64)
            {
                /* It seems that we have E0E0 || SigA */
                SigA = BinUtils.Copy(MsgA, 2, -2);
            }
            else
            {
                Logger.Error("Wrong length for Msg.A");
                goto failed;
            }

            Logger.Info("SigA: {0}", BinConvert.ToHex(SigA));

            /* Try to verify the signature */
            byte[] SigAExt = new byte[] { 0xE0, 0xE0 };
            SigAExt = BinUtils.Concat(SigAExt, MifareDuoXGeneralAuthenticatePcdOptions.Create(BinConvert.HexToBytes(OptionsA)).GetTLV());
            SigAExt = BinUtils.Concat(SigAExt, BinConvert.HexToBytes(EPubA));
            SigAExt = BinUtils.Concat(SigAExt, BinConvert.HexToBytes(EPubB));
            Logger.Info("SigA.ext: {0}", BinConvert.ToHex(SigAExt));

            if (!ECC.Verify(MifareDuoXEccCurve.NistP256, BinConvert.HexToBytes(LTPubA), SigAExt, SigA))
            {
                Logger.Error("Signature A verification failed");
                goto failed;
            }
            else
            {
                Logger.Info("Signature A is OK");
            }

            /* Verify we can compute the signature */
            ECC.ImportPrivate(MifareDuoXEccCurve.NistP256, BinConvert.HexToBytes("C28276FC8DB6CF1040B635E3E5BACCE0EFA32FAA03C812B340916BB306CC2972"), out ECPrivateKeyParameters ecPrivateKeyA);
            if (!ECC.Sign(MifareDuoXEccCurve.NistP256, ecPrivateKeyA, SigAExt, out byte[] SigAcalc))
            {
                Logger.Error("Signature A re-creation failed");
                goto failed;
            }
            Logger.Info("SigA.ext: {0} (calc)", BinConvert.ToHex(SigAcalc));

            if (!ECC.Verify(MifareDuoXEccCurve.NistP256, BinConvert.HexToBytes(LTPubA), SigAExt, SigAcalc))
            {
                Logger.Error("Signature A 2nd verification failed");
                goto failed;
            }

            /* From General Authenticate Part 2 Response */
            byte[] EncMsgB = BinConvert.HexToBytes("5980ADC660208DB284ABB4C68E181C9FF9A75E846505B73C956848C356E8BA9AD5E882940E2B53F39302DF3980C83875AEF18DEACD42003F2756F757FDE44015856A91EAF41C6EC673946C72FF8E1F3E662FF562338B1E7B6D327BC55E0605E5DE2D43B7C1141F839C07720C15D84EF9DF90262C3B4C9F047A9E80F337D25AD0F925D11A17E7FD991BF8E872862F45F2E8A4BDF4A6401179B834B63DCFA023820E554EBC91ED9A0E6A2F7C1AE2EFAD4B0E640507B77CA436811B9D1FECE949CC6C867C4EACFBE26A67997465F70C27768DB0942B174760910F7E01265E061FA826DB7A9CCD4CA26406FF91825E325D7BA45A2557C5907BC9F2E8181E1C593A22F5A1B02C1E7003C09CDE1B10A9B7E2A07D8DF2D51E2B03EB5F3D8E026E5F11D12A19C97DD2DB8985830463B2F5EE26297733BC64FF747152383F550905D25B68045F055E851716FAB45A8D5004B3480621381B864224527C516B816A56117FB779E726AF225D9BD278EDEA7D769ED8A2A07C6E4F2C21AE279EC3A633429ABD942BCADD68985CA3C98ED281CAEC51DFCCF72049D7326C21789084FE9F042E7849");

            /*
             * DATA
             *  T  L      V
             *  7C 8201A4
             *            T  L      V
             *            82 8201A0 5980ADC660208DB284ABB4C68E181C9FF9A75E846505B73C956848C356E8BA9AD5E882940E2B53F39302DF3980C83875AEF18DEACD42003F2756F757FDE44015856A91EAF41C6EC673946C72FF8E1F3E662FF562338B1E7B6D327BC55E0605E5DE2D43B7C1141F839C07720C15D84EF9DF90262C3B4C9F047A9E80F337D25AD0F925D11A17E7FD991BF8E872862F45F2E8A4BDF4A6401179B834B63DCFA023820E554EBC91ED9A0E6A2F7C1AE2EFAD4B0E640507B77CA436811B9D1FECE949CC6C867C4EACFBE26A67997465F70C27768DB0942B174760910F7E01265E061FA826DB7A9CCD4CA26406FF91825E325D7BA45A2557C5907BC9F2E8181E1C593A22F5A1B02C1E7003C09CDE1B10A9B7E2A07D8DF2D51E2B03EB5F3D8E026E5F11D12A19C97DD2DB8985830463B2F5EE26297733BC64FF747152383F550905D25B68045F055E851716FAB45A8D5004B3480621381B864224527C516B816A56117FB779E726AF225D9BD278EDEA7D769ED8A2A07C6E4F2C21AE279EC3A633429ABD942BCADD68985CA3C98ED281CAEC51DFCCF72049D7326C21789084FE9F042E7849
             * SW1 SW2
             *  90  00
            */

            buffer = BinUtils.Copy(EncMsgB);
            Logger.Info("MsgB Ciphered: {0}", BinConvert.ToHex(buffer));
            (instance.SessionCryptoContext as DesfireCryptoContextDuoX).CipherRecvEx(ref buffer, true);
            if (!(instance.SessionCryptoContext as DesfireCryptoContextDuoX).Unpadd(ref buffer))
            {
                Logger.Error("Failed to unpadd Msg.B");
                goto failed;
            }
            Logger.Info("MsgB Plain: {0}", BinConvert.ToHex(buffer));
            byte[] MsgB = BinUtils.Copy(buffer);

            if ((MsgB[0] != 0xE1) || (MsgB[1] != 0xE1))
            {
                Logger.Error("Failed to decipher Msg.B.Enc");
                goto failed;
            }

            byte lenOptionsB = MsgB[2];
            byte[] OptionsB = BinUtils.Copy(MsgB, 2, 1 + lenOptionsB);
            Logger.Info("OptionsB: {0}", BinConvert.ToHex(OptionsB));

            byte[] SigB = null;

            if (MsgB.Length > 2 + 1 + lenOptionsB + 64 + 2)
            {
                /* It seems that we have E1E1 || OptionsB || CertB || SigB */
                Asn1Tlv tlvCertificate = Asn1Tlv.Deserialize(BinUtils.Copy(MsgB, 2 + 1 + lenOptionsB, MsgB.Length - 2 - 1 - lenOptionsB), out buffer);
                Logger.Info(tlvCertificate.ToString());
                SigB = BinUtils.Copy(buffer);
            }
            else if (MsgB.Length == 2 + 1 + lenOptionsB + 64)
            {
                /* It seems that we have E1E1 || OptionsB || SigB */
                SigB = BinUtils.Copy(MsgB, 2 + 1 + lenOptionsB, MsgB.Length - 2 - 1 - lenOptionsB);
            }
            else if (MsgB.Length == 2 + 1 + lenOptionsB)
            {
                /* It seems that we have E1E1 || OptionsB only */
            }
            else
            {
                Logger.Error("Wrong length for Msg.B");
                goto failed;
            }

            Logger.Info("SigB: {0}", BinConvert.ToHex(SigB));

            /* Try to verify the signature */
            byte[] SigBExt = new byte[] { 0xE1, 0xE1 };
            SigBExt = BinUtils.Concat(SigBExt, OptionsB);
            SigBExt = BinUtils.Concat(SigBExt, BinConvert.HexToBytes(EPubB));
            SigBExt = BinUtils.Concat(SigBExt, BinConvert.HexToBytes(EPubA));
            Logger.Info("SigB.ext: {0}", BinConvert.ToHex(SigBExt));

            if (!ECC.Verify(MifareDuoXEccCurve.NistP256, BinConvert.HexToBytes(LTPubB), SigBExt, SigB))
            {
                Logger.Error("Signature B verification failed");
                goto failed;
            }
            else
            {
                Logger.Info("Signature B is OK");
            }

            /* Verify we can compute the signature */
            ECC.ImportPrivate(MifareDuoXEccCurve.NistP256, BinConvert.HexToBytes("50FF451C5824781D57755C5B02CB563F150644FA693235806625123717F05D28"), out ECPrivateKeyParameters ecPrivateKeyB);
            if (!ECC.Sign(MifareDuoXEccCurve.NistP256, ecPrivateKeyB, SigBExt, out byte[] SigBcalc))
            {
                Logger.Error("Signature B re-creation failed");
                goto failed;
            }
            Logger.Info("SigB.ext: {0} (calc)", BinConvert.ToHex(SigBcalc));

            if (!ECC.Verify(MifareDuoXEccCurve.NistP256, BinConvert.HexToBytes(LTPubB), SigBExt, SigBcalc))
            {
                Logger.Error("Signature B 2nd verification failed");
                goto failed;
            }

            return;

        failed:
            throw new Exception("DuoX Session Keys Self Test failed");
        }
    }
}



