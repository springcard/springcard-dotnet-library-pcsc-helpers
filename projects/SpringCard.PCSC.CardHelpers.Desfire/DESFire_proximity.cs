using System;
using SpringCard.LibCs;

namespace SpringCard.PCSC.CardHelpers
{
    public partial class Desfire
    {
        public int ProximityCheckLowThreshold { get; private set; } = 75;
        public int ProximityCheckHighThreshold { get; private set; } = 110;

        /*
        ushort PCPubRespTime;
        byte PCOption = 0x00;
        byte PCPPS1;
        byte[] PCRndStream = new byte[16];
        byte[] pRndR = new byte[8];
        byte[] pRndC = new byte[8];
        */

        private class DesfireProximityCheckData
        {
            public byte Option;
            public ushort PubRespTime;
            public byte PPS1;
            public byte[] RndStream = new byte[16];
            public byte[] pRndR = new byte[8];
            public byte[] pRndC = new byte[8];
        }

        DesfireProximityCheckData ProximityCheckData = null;

        public long PreparePC()
        {
            return PreparePC(out byte dummy0, out ushort dummy1, out byte dummy2);
        }

        public long PreparePC(out ushort PubRespTime)
        {
            return PreparePC(out byte dummy0, out PubRespTime, out byte dummy1);
        }

        public long PreparePC(out byte Option, out ushort PubRespTime, out byte PPS1)
        {
            logger.trace("PreparePC");

            Option = 0; PubRespTime = 0; PPS1 = 0;

            if (IsoWrapping == DesfireIsoWrapping.Card)
            {
                long rc = IsoApdu(0x90, (byte)DesfireCommand.CMD_PPC, 0x00, 0x00, 0x00, out byte[] buffer, out ushort SW);

                if (rc != Success)
                    return rc;

                rc = TranslateSW(SW, 0x00);
                if (rc != Success)
                    return rc;

                if (SW == 0x9190)
                {
                    Option = buffer[0];
                    PubRespTime = (ushort)(buffer[1] << 8);
                    PubRespTime |= (ushort)(buffer[2] & 0x00FF);
                    if ((Option & 0x01) != 0)
                        PPS1 = buffer[3];
                }
            }
            else if (IsoWrapping == DesfireIsoWrapping.Reader)
            {
                xfer_length = 0;
                xfer_buffer[xfer_length++] = (byte)DesfireCommand.CMD_PPC;

                /* Send the command string to the PICC and get its response (1st frame exchange).
                 * The PICC has to respond with an (byte) ECardError.AdditionalFrame status byte. */
                long rc = Command(0, DesfireCommandFlag.WANTS_OPERATION_OK);
                if (rc != Success)
                    return rc;

                if (xfer_length > 3)
                {
                    Option = xfer_buffer[0];
                    PubRespTime = (ushort)(xfer_buffer[1] << 8);
                    PubRespTime |= (ushort)(xfer_buffer[2] & 0x00FF);
                    if ((Option & 0x01) != 0)
                        PPS1 = xfer_buffer[3];
                }
            }
            else
            {
                xfer_length = 0;
                xfer_buffer[xfer_length++] = (byte)DesfireCommand.CMD_PPC;

                long rc = Command(0, DesfireCommandFlag.WANTS_OPERATION_OK);
                if (rc != Success)
                    return rc;

                if (xfer_length > 3)
                {
                    Option = xfer_buffer[1];
                    PubRespTime = (ushort)(xfer_buffer[2] << 8);
                    PubRespTime |= (ushort)(xfer_buffer[3] & 0x00FF);
                    if ((Option & 0x01) != 0)
                        PPS1 = xfer_buffer[4];
                }
            }

            /* Remember the values, we'll need them in VerifyPC */
            ProximityCheckData = new DesfireProximityCheckData();
            ProximityCheckData.Option = Option;
            ProximityCheckData.PubRespTime = PubRespTime;
            ProximityCheckData.PPS1 = PPS1;

            logger.debug("PubRespTime={0} ({0:X04})", PubRespTime);
            if ((Option & 0x01) != 0)
                logger.debug("PPS1={0:X02}", PPS1);

            return Success;
        }

        /// <summary>
        /// ProximityCheck : The PICC answers with a prepared random number at the published response time in PreparePC. This command may be
        /// repeated up to 8 times splitting the random number for different time measurements
        /// </summary>
        /// <param name="SW">[out] ISO status code</param>
        /// <returns></returns>
        public long ProximityCheck()
        {
            return ProximityCheck(8);
        }

        public long ProximityCheck(int splitCount)
        {
            return ProximityCheck(splitCount, out int dummy);
        }

        public long ProximityCheck(out int averageRespTime)
        {
            return ProximityCheck(8, (ProximityCheckData.PubRespTime * ProximityCheckLowThreshold) / 100, (ProximityCheckData.PubRespTime * ProximityCheckHighThreshold) / 100, out int dummyMin, out int dummyMax, out averageRespTime);
        }

        public long ProximityCheck(int splitCount, out int averageRespTime)
        {
            return ProximityCheck(splitCount, (ProximityCheckData.PubRespTime * ProximityCheckLowThreshold) / 100, (ProximityCheckData.PubRespTime * ProximityCheckHighThreshold) / 100, out int dummyMin, out int dummyMax, out averageRespTime);
        }

        public long ProximityCheck(int splitCount, int minRespTime, int maxRespTime)
        {
            return ProximityCheck(splitCount, minRespTime, maxRespTime, out int dummyMin, out int dummyMax, out int dummyAverage);
        }

        public long ProximityCheck(int splitCount, int minRespTime, int maxRespTime, out int gotMinRespTime, out int gotMaxRespTime, out int gotAverageRespTime)
        {
            long rc = ProximityCheck(splitCount, minRespTime, maxRespTime, out int[] respTimes);

            gotMinRespTime = -1;
            gotMaxRespTime = -1;
            gotAverageRespTime = 0;
            for (int i=0; i<respTimes.Length; i++)
            {
                if ((gotMinRespTime == -1) || (respTimes[i] < gotMinRespTime))
                    gotMinRespTime = respTimes[i];
                if ((gotMaxRespTime == -1) || (respTimes[i] > gotMaxRespTime))
                    gotMaxRespTime = respTimes[i];
                gotAverageRespTime += respTimes[i];
            }
            if (splitCount != 0)
                gotAverageRespTime /= splitCount;

            return rc;
        }

        public long ProximityCheck(int splitCount, int minRespTime, int maxRespTime, out int[] respTimes)
        {
            respTimes = new int[splitCount];

            switch (splitCount)
            {
                case 1:
                case 2:
                case 4:
                case 8:
                    break;

                default:
                    logger.trace("Only splitCount=1, 2, 4 or 8 is supported");
                    return LibraryError(DesfireLibraryError.InvalidParameter);
            }

            byte[] rndR = new byte[8];
            byte[] rndC = randomGenerator.Get(8);
            logger.debug("RndC: {0}", BinConvert.ToHex(rndC));

            int offsetC = 0;
            int offsetR = 0;
            int offsetS = 0;

            bool isValid = true;

            for (int run = 0; run < splitCount; run++)
            {
                byte length = (byte)(8 / splitCount);
                byte[] c_part = new byte[length];
                byte[] r_part = new byte[length];

                for (int i = 0; i < length; i++)
                    c_part[i] = rndC[offsetC++];

                if ((IsoWrapping & DesfireIsoWrapping.Card) != 0)
                {
                    byte[] buffer = new byte[1 + length];
                    buffer[0] = length;
                    for (int i = 0; i < length; i++)
                        buffer[1 + i] = c_part[i];

                    long rc = IsoApdu(0x90, (byte)DesfireCommand.CMD_PC, 0x00, 0x00, buffer, length, out buffer, out ushort SW);
                    if (rc != Success)
                        return rc;

                    rc = TranslateSW(SW, 0x00);
                    if (rc != Success)
                        return rc;

                    if (buffer.Length != length)
                    {
                        logger.debug("Length is invalid");
                        return LibraryError(DesfireLibraryError.WrongLength);
                    }

                    for (int i = 0; i < buffer.Length; i++)
                        r_part[i] = buffer[i];
                }
                else
                {
                    xfer_length = 0;
                    xfer_buffer[xfer_length++] = (byte)DesfireCommand.CMD_PC;
                    xfer_buffer[xfer_length++] = length;
                    for (int i = 0; i < length; i++)
                        xfer_buffer[xfer_length++] = c_part[i];

                    /* Send the command string to the PICC and get its response (1st frame exchange).
                        The PICC has to respond with an (byte) ECardError.AdditionalFrame status byte. */
                    long rc = Command(0, DesfireCommandFlag.WANTS_OPERATION_OK);
                    if (rc != Success)
                    {
                        logger.debug("ProximityCheck err. {0} in exchange", rc);
                        return rc;
                    }

                    if (xfer_length != length + 1)
                    {
                        logger.debug("ProximityCheck expected {0}B, got {1}B", length, xfer_length);
                        return LibraryError(DesfireLibraryError.WrongLength);
                    }

                    for (int i = 0; i < length; i++)
                        r_part[i] = xfer_buffer[i + 1];
                }

                uint actualRespTime = GetCardFdt();
                respTimes[run] = (int) actualRespTime;

                for (int i = 0; i < length; i++)
                {
                    rndR[offsetR++] = r_part[i];
                    ProximityCheckData.RndStream[offsetS++] = r_part[i];
                }

                for (int i = 0; i < length; i++)
                {
                    ProximityCheckData.RndStream[offsetS++] = c_part[i];
                }

                logger.debug("PC {0}/{1} ? {2} < {3} < {4}", run, splitCount, minRespTime, actualRespTime, maxRespTime);

                if (minRespTime > 0)
                {
                    if (actualRespTime < minRespTime)
                    {
                        logger.trace("Response time is too short (expected: > {0}, measured: {1})\n", minRespTime, actualRespTime);
                        isValid = false;
                    }
                }

                if (maxRespTime > 0)
                {
                    if (actualRespTime > maxRespTime)
                    {
                        logger.trace("Response time is too long (expected: < {0}, measured: {1})\n", maxRespTime, actualRespTime);
                        isValid = false;
                    }
                }
            }

            logger.debug("RndR: {0}", BinConvert.ToHex(rndR));
            logger.debug("RndS: {0}", BinConvert.ToHex(ProximityCheckData.RndStream));

            if (!isValid)
                return LibraryError(DesfireLibraryError.ProximityCheckFailed);

            return Success;
        }

        private uint GetCardFdt()
        {
            long rc = IsoApdu(0xFF, 0xCA, 0xFE, 0x00, 0x00, out byte[] resp, out ushort SW);

            if (rc != Success)
                return 0;

            if (SW != 0x9000)
                return 0;

            if ((resp == null) || (resp.Length != 4))
                return 0;

            uint result = BinUtils.ToDword(resp);

            logger.debug("FDT={0}", result);

            return result;
        }

        /// <summary>
        /// The ISOSelect command presents an IID to the PD as defined in compliance with ISO/IEC 7816-4.
        /// The IID is supported by the infrastructure containing the PCD.
        /// </summary>
        /// <param name="KeyValue"> [in] mac proximity key</param>
        /// <param name="SW">[out] ISO status code</param>
        /// <returns></returns>
        public long VerifyPC(byte[] KeyValue)
        {
            DesfireCryptoContextEV2 cryptoContext = new DesfireCryptoContextEV2(this, KeyValue);
            return VerifyPC(cryptoContext);
        }

        public long VerifyPC()
        {
            if (!InSecureSession())
                return LibraryError(DesfireLibraryError.InvalidParameter);
            return VerifyPC(SessionCryptoContext as DesfireCryptoContext);
        }

        public long VerifyPC(DesfireCryptoContext cryptoContext)
        {
            long status;
            byte[] resp;

            byte[] cmac_c = ComputeVerifyPCCmacC(cryptoContext);
            if (cmac_c == null)
            {
                logger.trace("VerifyPC: ComputeVerifyPCCmacC failed");
                status = LibraryError(DesfireLibraryError.WrongCMAC);
                goto done;
            }

            byte[] cmac_r = ComputeVerifyPCCmacR(cryptoContext);
            if (cmac_r == null)
            {
                logger.trace("VerifyPC: ComputeVerifyPCCmacR failed");
                status = LibraryError(DesfireLibraryError.WrongCMAC);
                goto done;
            }

            if ((IsoWrapping & DesfireIsoWrapping.Card) != 0)
            {
                status = IsoApdu(0x90, (byte)DesfireCommand.CMD_VPC, 0x00, 0x00, cmac_c, 0, out resp, out ushort SW);
                if (status != Success)
                    goto done;

                status = TranslateSW(SW, 0x00);
                if (status != Success)
                    goto done;

                if ((resp == null) || (resp.Length != 8))
                {
                    logger.trace("VerifyPC: Wrong length");
                    status = LibraryError(DesfireLibraryError.WrongLength);
                    goto done;
                }
            }
            else
            {
                xfer_length = 0;
                xfer_buffer[xfer_length++] = (byte)DesfireCommand.CMD_VPC;
                for (int i = 0; i < 8; i++)
                    xfer_buffer[xfer_length++] = cmac_c[i];

                /* Send the command string to the PICC and get its response (1st frame exchange).
				    The PICC has to respond with an (byte) ECardError.AdditionalFrame status byte. */
                status = Command(0, DesfireCommandFlag.WANTS_OPERATION_OK);
                if (status != Success)
                    goto done;

                if (xfer_length != 1 + 8)
                {
                    logger.trace("VerifyPC: Wrong length");
                    status = LibraryError(DesfireLibraryError.WrongLength);
                    goto done;
                }

                resp = BinUtils.Copy(xfer_buffer, 1, 8);
            }

            if (!BinUtils.Equals(resp, cmac_r))
            {
                logger.trace("Returned CMAC-R is invalid");
                logger.trace("CMAC-R received: {0}", BinConvert.ToHex(resp));
                logger.trace("CMAC-R expected: {0}", BinConvert.ToHex(cmac_r));
                status = LibraryError(DesfireLibraryError.WrongCMAC);
                goto done;
            }

            logger.trace("VerifyPC: OK");
            return Success;

        done:
            logger.trace("VerifyPC: KO");
            EndSecureSession();
            return status;
        }

#if _RIEN
        /// <summary>
        /// The ISOSelect command presents an IID to the PD as defined in compliance with ISO/IEC 7816-4.
        /// The IID is supported by the infrastructure containing the PCD.
        /// </summary>
        /// <param name="VCEncKey"></param>
        /// <param name="VCMacKey"></param>
        /// <param name="VCProximityKey"></param>
        /// <param name="VCIid"></param>
        /// <param name="size_iid"></param>
        /// <param name="bProxCheck"></param>
        /// <param name="SW"></param>
        /// <returns></returns>
        public long VCSelect(
          byte[] VCIid,
          byte[] VCEncKey,
          byte[] VCMacKey,
          byte[] VCProximityKey = null)
        {
            EndSecureSession();

            long rc = ISOSelect(VCEncKey, VCIid, out byte[] RndChal, out byte[] vcdata);

            if (rc == DesfireCommand.OPERATION_OK)
            {
                rc = IsoExternalAuthenticate(VCMacKey, abRndChal, vcdata);
                if (rc != DesfireCommand.OPERATION_OK)
                    return rc;
            }

            if (VCProximityKey != null)
            {
                rc = PreparePC(out PCOption, out PCPubRespTime, out PCPPS1);
                if (rc == DesfireCommand.OPERATION_OK)
                {
                    rc = ProximityCheck();
                    if (rc == DesfireCommand.OPERATION_OK)
                        rc = VerifyPC(VCProximityKey);
                }
            }

            return rc;
        }
#endif

        private byte[] ComputeVerifyPCCmacC(DesfireCryptoContext cryptoContext)
        {
            int offset = 0;
            byte[] input;
            if ((ProximityCheckData.Option & 0x01) != 0)
                input = new byte[21];
            else
                input = new byte[20];

            /* MACt(KVCProximityKey , VPC || Option || pubRespTime || PPS1 || (pRndR1 || pRndC1) || .. || (pRndRn || pRndCn)) */
            input[offset++] = (byte)DesfireCommand.CMD_VPC;
            input[offset++] = ProximityCheckData.Option;
            input[offset++] = (byte)((ProximityCheckData.PubRespTime & 0xFF00) >> 8);
            input[offset++] = (byte)((ProximityCheckData.PubRespTime & 0x00FF));
            if ((ProximityCheckData.Option & 0x01) != 0)
                input[offset++] = ProximityCheckData.PPS1; // PPS1 is only present if the option is set
            for (int i = 0; i < 16; i++)
                input[offset++] = ProximityCheckData.RndStream[i];

            Logger.Trace("CMAC-C input: {0}", BinConvert.ToHex(input));

            byte[] result = cryptoContext.ComputeCmac(input);

            Logger.Trace("CMAC-C is: {0}", BinConvert.ToHex(result));

            return result;
        }

        private byte[] ComputeVerifyPCCmacR(DesfireCryptoContext cryptoContext)
        {
            int offset = 0;
            byte[] input;
            if ((ProximityCheckData.Option & 0x01) != 0)
                input = new byte[21];
            else
                input = new byte[20];

            /* MACt(KVCProximityKey , VPC || Option || pubRespTime || PPS1 || (pRndR1 || pRndC1) || .. || (pRndRn || pRndCn)) */
            input[offset++] = (byte)DesfireCardError.MoreOperationOK;
            input[offset++] = ProximityCheckData.Option;
            input[offset++] = (byte)((ProximityCheckData.PubRespTime & 0xFF00) >> 8);
            input[offset++] = (byte)((ProximityCheckData.PubRespTime & 0x00FF));
            if ((ProximityCheckData.Option & 0x01) != 0)
                input[offset++] = ProximityCheckData.PPS1; // PPS1 is only present if the option is set
            for (int i = 0; i < 16; i++)
                input[offset++] = ProximityCheckData.RndStream[i];

            Logger.Trace("CMAC-R input: {0}", BinConvert.ToHex(input));

            byte[] result = cryptoContext.ComputeCmac(input);

            Logger.Trace("CMAC-R is: {0}", BinConvert.ToHex(result));

            return result;
        }

        public static void DesfireEV2SelfTest_PC1()
        {
            byte[] RndC = { 0xD1, 0x53, 0x64, 0xEB, 0xAA, 0x5E, 0x34, 0x9B };
            byte[] RndR = { 0x30, 0x32, 0x57, 0xE3, 0xA5, 0x0A, 0xA8, 0x80 };
            byte[] Key = { 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22 };
            byte[] CmacC = { 0x7F, 0x18, 0x81, 0x00, 0xA4, 0xB5, 0xB8, 0x18 };
            byte[] CmacR = { 0xB8, 0xEA, 0xA1, 0xA1, 0x5D, 0x1D, 0x8E, 0xF2 };

            Desfire instance = new Desfire(null);

            instance.ProximityCheckData = new DesfireProximityCheckData();

            instance.ProximityCheckData.Option = 1;
            instance.ProximityCheckData.PubRespTime = 0x06A0;
            instance.ProximityCheckData.PPS1 = 0x07;

            Logger.Trace("RndC: {0}", BinConvert.ToHex(RndC));
            Logger.Trace("RndR: {0}", BinConvert.ToHex(RndR));

            instance.ProximityCheckData.RndStream = BinUtils.Concat(RndR, RndC);

            Logger.Trace("RndStream: {0}", BinConvert.ToHex(instance.ProximityCheckData.RndStream));

            instance.SessionCryptoContext = new DesfireCryptoContextEV2(instance, Key);

            byte[] cmac_c = instance.ComputeVerifyPCCmacC(instance.SessionCryptoContext as DesfireCryptoContextEV2);
            if (cmac_c == null)
            {
                Logger.Error("ComputeVerifyPCCmacC failed");
                goto failed;
            }

            byte[] cmac_r = instance.ComputeVerifyPCCmacR(instance.SessionCryptoContext as DesfireCryptoContextEV2);
            if (cmac_r == null)
            {
                Logger.Error("ComputeVerifyPCCmacR failed");
                goto failed;
            }

            if (!BinUtils.Equals(CmacC, cmac_c))
            {
                Logger.Error("Computed CMAC-C is invalid");
                goto failed;
            }

            if (!BinUtils.Equals(CmacR, cmac_r))
            {
                Logger.Error("Computed CMAC-R is invalid");
                goto failed;
            }

            Logger.Trace("VerifyPC self-test 1 is OK");
            return;

        failed:
            throw new Exception("VerifyPC self-test 1 failed");
        }

        public static void DesfireEV2SelfTest_PC2()
        {
            Logger.Trace("Prepare");

            FakeCardTransmitter transmitter = new FakeCardTransmitter();

            transmitter.AddApduPair("FFCAFE0000", "000002BE9000");

            transmitter.AddApduPair("90F0000000", "01034C0F9190");
            transmitter.AddApduPair("90F2000002013501", "2E9190");
            transmitter.AddApduPair("90F2000002010901", "B89190");
            transmitter.AddApduPair("90F200000201CA01", "8A9190");
            transmitter.AddApduPair("90F2000002010401", "9A9190");
            transmitter.AddApduPair("90F2000002018901", "889190");
            transmitter.AddApduPair("90F2000002017001", "7C9190");
            transmitter.AddApduPair("90F200000201F701", "CB9190");
            transmitter.AddApduPair("90F200000201DC01", "6B9190");
            transmitter.AddApduPair("90FD000008B1E2BA7BFEDC771500", "1BBADAD27C3E09BF9190");
//            transmitter.AddApduPair("90FD000008B1E2BA7BFEDC771508", "1BBADAD27C3E09BF9190");

            Logger.Trace("Ready");

            Desfire instance = new Desfire(transmitter, DesfireIsoWrapping.Card);
            instance.SetRandomGenerator(new FakeRandomGenerator(BinConvert.HexToBytes("3509CA048970F7DC")));
            instance.SetLogger(new Logger());

            long rc = instance.PreparePC(out byte option, out ushort pubRespTime, out byte pps1);
            if (rc != 0)
            {
                Logger.Trace("VerifyPC self-test 2 error {0} in PreparePC", rc);
                goto failed;
            }

            rc = instance.ProximityCheck(8);
            if (rc != 0)
            {
                Logger.Trace("VerifyPC self-test 2 error {0} in ProximityCheck", rc);
                goto failed;
            }

            rc = instance.VerifyPC(BinConvert.HexToBytes("00000000000000000000000000000002"));
            if (rc != 0)
            {
                Logger.Trace("VerifyPC self-test 2 error {0} in VerifyPC", rc);
                goto failed;
            }

            Logger.Trace("VerifyPC self-test 2 is OK");
            return;

        failed:
            throw new Exception("VerifyPC self-test 2 failed");
        }

        public static void DesfireEV2SelfTest_PC3()
        {
            Logger.Trace("Prepare");

            FakeCardTransmitter transmitter = new FakeCardTransmitter();

            transmitter.AddApduPair("FFCAFE0000", "000002BE9000");

            transmitter.AddApduPair("AA00", "AF21DC10D4C4E62CC758AA5D8CD3FA7714");
            transmitter.AddApduPair("AF7F6741579F2BFD61095DA5D008060121F6F688AD2063AC19044ABFE7BF009B49", "009099A3F414FE6A90184C1A7C871D7070");
            transmitter.AddApduPair("F0", "9001034C00");
            transmitter.AddApduPair("F208D4D5B42C087C0400", "9044EEF3824D734613");
            transmitter.AddApduPair("FDEF72ABB1787D5D85", "90CCE60D301F4E0192");

            Logger.Trace("Ready");

            Desfire instance = new Desfire(transmitter, DesfireIsoWrapping.None);
            instance.SetRandomGenerator(new FakeRandomGenerator(BinConvert.HexToBytes("6DCCE12B19B2C583136102A203CD4AB1D4D5B42C087C0400")));
            instance.SetLogger(new Logger());

            long rc = instance.AuthenticateEV1Aes(0x00, BinConvert.HexToBytes("55555555555555555555555555555555"));
            if (rc != 0)
            {
                Logger.Trace("VerifyPC self-test 3 error {0} in AuthenticateAes", rc);
                goto failed;
            }

            rc = instance.PreparePC(out byte option, out ushort pubRespTime, out byte pps1);
            if (rc != 0)
            {
                Logger.Trace("VerifyPC self-test 3 error {0} in PreparePC", rc);
                goto failed;
            }

            rc = instance.ProximityCheck(1);
            if (rc != 0)
            {
                Logger.Trace("VerifyPC self-test 3 error {0} in ProximityCheck", rc);
                goto failed;
            }

            /* Verify with the current key */
            rc = instance.VerifyPC();
            if (rc != 0)
            {
                Logger.Trace("VerifyPC self-test 3 error {0} in VerifyPC", rc);
                goto failed;
            }

            Logger.Trace("VerifyPC self-test 3 is OK");
            return;

        failed:
            throw new Exception("VerifyPC self-test 3 failed");
        }
    }
}
