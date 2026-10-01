using SpringCard.LibCs;
using SpringCard.PCSC;
using SpringCard.PCSC.CardHelpers;

namespace Test
{
    public class Program
    {
        bool ShowMifareDuoXPrivateKeyList(Desfire mifareDuoX)
        {
            if (mifareDuoX.GetPrivateKeyList(out Desfire.DesfirePrivateKeyInfo[] PrivateKeyList) != 0)
                return false;

            Logger.Info("{0} private key(s)", PrivateKeyList.Length);
            for (int i = 0; i<PrivateKeyList.Length; i++)
            {
                Logger.Info("\t{0:X02} Curve {1:X02} Policy {2:X04} Write {3:X02} KUC {4}/{5}", PrivateKeyList[i].KeyNumber, PrivateKeyList[i].CurveId, PrivateKeyList[i].KeyPolicy, PrivateKeyList[i].WriteAccess, PrivateKeyList[i].KeyUsageCtrlValue, PrivateKeyList[i].KeyUsageCtrlLimit);
            }

            return true;
        }

        bool SelfTestDesfireProximityCheck(SCardChannel card)
        {
            Desfire desfire = new Desfire(card, Desfire.DesfireIsoWrapping.Card);
            desfire.SetLogger(new Logger());

            if (desfire.AuthenticateEV2First(0, Desfire.SampleMasterKeyAES, null) != 0)
            {
                Logger.Error("Desfire AuthenticateEV2First failed");
                return false;
            }
            desfire.SelectApplication(0x160574);
            desfire.SelectApplication(0x000000);

            /* Do the proximity check */
            if (desfire.PreparePC(out byte option, out ushort pubRespTime, out byte PPS1) != 0)
            {
                Logger.Error("PreparePC failed");
                return false;
            }

            Logger.Trace("Doing ProximityCheck (8 steps), option={0:X02}, pubRespTime={1}, PPS1={2:X02}", option, pubRespTime, PPS1);

            if (desfire.ProximityCheck(8, (80 * pubRespTime) / 100, (110 * pubRespTime) / 100) != 0)
            {
                Logger.Error("ProximityCheck failed");
                return false;
            }

            Logger.Trace("Verifying the PC");

            if (desfire.VerifyPC(Desfire.SampleProximityKeyAES) != 0)
            {
                Logger.Error("Desfire VerifyPC failed");
                return false;
            }

            Logger.Info("Desfire VerifyPC OK");
            Logger.Info("Desfire VerifyPC 1/3 OK!");

            /* Authenticate EV1 */
            if (desfire.AuthenticateEV1Aes(0, Desfire.SampleMasterKeyAES) != 0)
            {
                Logger.Error("Desfire AuthenticateAes failed");
                return false;
            }

            /* Do the proximity check */
            if (desfire.PreparePC(out option, out pubRespTime, out PPS1) != 0)
            {
                Logger.Error("PreparePC failed");
                return false;
            }

            Logger.Trace("Doing ProximityCheck (8 steps), option={0:X02}, pubRespTime={1}, PPS1={2:X02}", option, pubRespTime, PPS1);

            if (desfire.ProximityCheck(8, (80 * pubRespTime) / 100, (110 * pubRespTime) / 100) != 0)
            {
                Logger.Error("ProximityCheck failed");
                return false;
            }

            Logger.Trace("Verifying the PC");

            if (desfire.VerifyPC() != 0)
            {
                Logger.Error("Desfire VerifyPC failed");
                return false;
            }

            Logger.Info("Desfire VerifyPC OK");
            Logger.Info("Desfire VerifyPC 2/3 OK!");

            /* Authenticate EV2 */
            if (desfire.AuthenticateEV2First(0, Desfire.SampleMasterKeyAES, null) != 0)
            {
                Logger.Error("Desfire AuthenticateEV2First failed");
                return false;
            }

            /* Do the proximity check */
            if (desfire.PreparePC(out option, out pubRespTime, out PPS1) != 0)
            {
                Logger.Error("PreparePC failed");
                return false;
            }

            Logger.Trace("Doing ProximityCheck (8 steps), option={0:X02}, pubRespTime={1}, PPS1={2:X02}", option, pubRespTime, PPS1);

            if (desfire.ProximityCheck(8, (80 * pubRespTime) / 100, (110 * pubRespTime) / 100) != 0)
            {
                Logger.Error("ProximityCheck failed");
                return false;
            }

            Logger.Trace("Verifying the PC");

            if (desfire.VerifyPC() != 0)
            {
                Logger.Error("Desfire VerifyPC failed");
                return false;
            }

            Logger.Info("Desfire VerifyPC OK");

            Logger.Info("Desfire VerifyPC 3/3 OK!");
            Logger.Info("TESTS OK");

            return true;
        }
    }
}