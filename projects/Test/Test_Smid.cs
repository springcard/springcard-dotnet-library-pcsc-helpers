/*
 * Created by SharpDevelop.
 * User: Jerome Izaac
 * Date: 07/09/2017
 * Time: 16:45
 * 
 * To change this template use Tools | Options | Coding | Edit Standard Headers.
 */
using SpringCard.LibCs;
using SpringCard.PCSC.CardHelpers;

namespace SpringCard.PCSC.SelfTest
{
    partial class Program
    {
        readonly byte[] testKey = new byte[] {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
        readonly byte[] salt = new byte[] { 0x1E, 0x49, 0x7E, 0x61, 0x3A, 0x99, 0xBE, 0x4f, 0x91, 0x87, 0x9f, 0xE3, 0x85, 0x65, 0x81, 0x97 };
        // for test
        // readonly byte[] salt = new byte[] { 0xAD, 0xCD, 0x5B, 0x60, 0x20, 0xCE, 0xE0, 0x86, 0xEB, 0xDC, 0x43, 0xEE, 0x65, 0x08, 0x43, 0xF3 };
        readonly byte[] smidReader = new byte[] { 0x41, 0x52, 0x53, 0x43, 0x53 };
        readonly byte[] abNullKey_16 = new byte[16];

        readonly byte[] SMID_READER = new byte[] { 0x41, 0x52, 0x43, 0x53, 0x2D, 0x52, 0x33, 0x31, 0x2D, 0x41, 0x2F, 0x42, 0x54, 0x31, 0x2D, 0x33, 0x49 };

        public void TestSmid(Smid card, bool bSimulate)
        {
            long rc = 0;
            byte[] usi = new byte[Smid.HCE_USI_LENGTH];
            /* for test */
            //ushort site_code = 0x1234;
            
            ushort site_code = 0x12AB;
            byte settings_unlock = 0x00;
            byte[] card_number = new byte[1];

            if (bSimulate)
            {
                Logger.Info("Self-test Stid Mobile ID ON");
                card.SelfTestOnOff();
            }
            
            /* SELECT APPLICATION */
            rc = card.SelectApplication(usi);
            if (rc != Smid.Success)
            {
                Logger.Fatal("Smid SelectApplication failed: {0}", Smid.GetErrorMessage(rc));
                throw new Exception("Test failed");
            }

            /* GETNBCARD */
            rc = card.HceGetNbCard(site_code, settings_unlock, card_number);
            if (rc != Smid.Success)
            {
                Logger.Fatal("Smid GetNbCard failed: {0}", Smid.GetErrorMessage(rc));
                throw new Exception("Test failed");
            }
            Logger.Info("Smid GetNbCard {0} card(s) available(s)\n", card_number[0]);
            

            /* AUTHENTICATE */
            rc = card.HceAuthenticateNfcV2(
                testKey,  // secretKey
                usi,
                site_code,
                salt
                );
            if (rc != Smid.Success)
            {
                Logger.Fatal("Smid Authenticate failed: {0}", Smid.GetErrorMessage(rc));
                throw new Exception("Test failed");
            }

            byte[] data = new byte[256];
            uint data_length = 0;

            rc = card.HceGetData(
                0x0000,                          // offset
                0x0004,                          // length
                data,
                ref data_length );
            if (rc != Smid.Success)
            {
                Logger.Fatal("Smid GetData failed: {0}", Smid.GetErrorMessage(rc));
                throw new Exception("Test failed");
            }

            logger.trace("GetData result  {0:X02}", BinConvert.ToHex(data, data_length));

            if (card._SmidProtocolVersion >= Smid.SmidProtocolVersion.Smid_v212)
            {
                rc = card.HceTransactionCommit(SMID_READER, 0x00);
                if (rc != Smid.Success)
                {
                    Logger.Fatal("Smid TransactionCommit failed: {0}", Smid.GetErrorMessage(rc));
                    throw new Exception("Test failed");
                }
            }

            /* all good, store the result */

            logger.trace("SUCCESS!\n");

            if (bSimulate)
            {
                Logger.Info("Self-test Stid Mobile ID OFF");
                card.SelfTestOnOff();
            }
            Console.WriteLine();
        }
    }
}

