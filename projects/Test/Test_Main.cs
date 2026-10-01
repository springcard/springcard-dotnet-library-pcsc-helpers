
using SpringCard.LibCs;
using SpringCard.PCSC.CardEmulation;
using SpringCard.PCSC.CardHelpers;

namespace SpringCard.PCSC.SelfTest
{
    partial class Program
    {
        Logger? logger;
        string? readerName = null;

        bool quiet = false;

        bool doEmulation = false;
        bool doSelfTest = false;

        bool doLogCrypto = false;
        bool doLogSecrets = false;
        bool doDeterministic = false;
        bool doChangeMasterKey = false;

        string emulInputFile = null;
        string emulOutputFile = null;

        [Flags]
        enum EActions
        {
            DesfireEV0 = 0x00000001,
            DesfireEV1 = 0x000000F0,
            DesfireEV1Legacy = 0x00000010,
            DesfireEV1TDes2k = 0x00000020,
            DesfireEV1TDes3k = 0x00000040,
            DesfireEV1Aes = 0x00000080,
            DesfireEV2 = 0x00000100,
            DesfireEV3 = 0x00000200,
            MifareDuoX = 0x0000F000,
            MifareDuoXAes128 = 0x00001000,
            MifareDuoXAes256 = 0x00002000,
            MifareDuoXAesEcc = 0x00004000,
        }

        EActions actions;

        IRandomGenerator fakeRandomGenerator = new FakeRandomGenerator();

        public Program()
        {

        }

        bool BeginEmulator(ICardTransmitter cardTransmitter)
        {
            if (cardTransmitter is CardEmulDesfire)
            {
                (cardTransmitter as CardEmulDesfire).SetLogger(new Logger(logger, cardTransmitter.GetType().Name), doLogCrypto, doLogSecrets);

                if (doDeterministic)
                    (cardTransmitter as CardEmulDesfire).SetRandomGenerator(fakeRandomGenerator);


                if (emulInputFile != null)
                {
                    if (!(cardTransmitter as CardEmulDesfire).LoadFromFile(emulInputFile))
                    {
                        Logger.Error("Failed to load card data from {0}", emulInputFile);
                        return false;
                    }
                }
            }

            return true;
        }

        bool EndEmulator(ICardTransmitter cardTransmitter)
        {
            if (emulOutputFile != null)
            {
                if (cardTransmitter is CardEmulDesfire)
                {
                    if (!(cardTransmitter as CardEmulDesfire).SaveToFile(emulOutputFile))
                    {
                        Logger.Error("Failed to save card data to {0}", emulOutputFile);
                        return false;
                    }
                }
            }

            return true;
        }

        bool RunTestDesfireEV0(ICardTransmitter cardTransmitter)
        {
            if (cardTransmitter == null)
            {
                Logger.Info("Emulating the Desfire EV0");
                cardTransmitter = new CardEmulDesfireEV0();
                if (!BeginEmulator(cardTransmitter))
                    return false;
            }

            Desfire desfire = new Desfire(cardTransmitter);
            desfire.SetLogger(logger, doLogCrypto, doLogSecrets);
            if (doDeterministic)
                desfire.SetRandomGenerator(fakeRandomGenerator);

            try
            {
                TestDesfireEV0(desfire);
            }
            catch (Exception ex)
            {
                Logger.Error(ex.GetType().FullName);
                Logger.Error(ex.Message);
                Logger.Error(ex.StackTrace);
                return false;
            }

            EndEmulator(cardTransmitter);
            return true;
        }

        bool RunTestDesfireEV1(ICardTransmitter cardTransmitter, DesfireEV1TestMode mode)
        {
            if (cardTransmitter == null)
            {
                Logger.Info("Emulating the Desfire EV1");
                cardTransmitter = new CardEmulDesfireEV1();
                if (!BeginEmulator(cardTransmitter))
                    return false;
            }

            Desfire desfire = new Desfire(cardTransmitter);
            desfire.SetLogger(logger, doLogCrypto, doLogSecrets);
            if (doDeterministic)
                desfire.SetRandomGenerator(fakeRandomGenerator);

            try
            {
                TestDesfireEV1(desfire, mode);
            }
            catch (Exception ex)
            {
                Logger.Error(ex.GetType().FullName);
                Logger.Error(ex.Message);
                Logger.Error(ex.StackTrace);
                return false;
            }

            EndEmulator(cardTransmitter);
            return true;
        }

        bool RunTestDesfireEV2(ICardTransmitter cardTransmitter)
        {
            if (cardTransmitter == null)
            {
                Logger.Info("Emulating the Desfire EV2");
                cardTransmitter = new CardEmulDesfireEV2();
                if (!BeginEmulator(cardTransmitter))
                    return false;
            }

            Desfire desfire = new Desfire(cardTransmitter);
            desfire.SetLogger(logger, doLogCrypto, doLogSecrets);
            if (doDeterministic)
                desfire.SetRandomGenerator(fakeRandomGenerator);

            try
            {
                TestDesfireEV2Base(desfire);
            }
            catch (Exception ex)
            {
                Logger.Error(ex.GetType().FullName);
                Logger.Error(ex.Message);
                Logger.Error(ex.StackTrace);
                return false;
            }

            EndEmulator(cardTransmitter);
            return true;
        }

        bool RunTestMifareDuoXEcc(ICardTransmitter cardTransmitter)
        {
            if (cardTransmitter == null)
            {
                Logger.Info("Emulating the Mifare DuoX");
                cardTransmitter = new CardEmulMifareDuoX();
                if (!BeginEmulator(cardTransmitter))
                    return false;
            }

            Desfire desfire = new Desfire(cardTransmitter);
            desfire.SetLogger(logger, doLogCrypto, doLogSecrets);
            if (doDeterministic)
                desfire.SetRandomGenerator(fakeRandomGenerator);

            try
            {
                TestMifareDuoXEcc(desfire);
            }
            catch (Exception ex)
            {
                Logger.Error(ex.GetType().FullName);
                Logger.Error(ex.Message);
                Logger.Error(ex.StackTrace);
                return false;
            }

            EndEmulator(cardTransmitter);
            return true;
        }

        bool RunTestMifareDuoXAes(ICardTransmitter cardTransmitter, bool aes256)
        {
            if (cardTransmitter == null)
            {
                Logger.Info("Emulating the Mifare DuoX");
                cardTransmitter = new CardEmulMifareDuoX();
                if (!BeginEmulator(cardTransmitter))
                    return false;
            }

            Desfire desfire = new Desfire(cardTransmitter);
            desfire.SetLogger(logger, doLogCrypto, doLogSecrets);
            if (doDeterministic)
                desfire.SetRandomGenerator(fakeRandomGenerator);

            try
            {
                TestMifareDuoXAes(desfire, aes256);
            }
            catch (Exception ex)
            {
                Logger.Error(ex.GetType().FullName);
                Logger.Error(ex.Message);
                Logger.Error(ex.StackTrace);
                return false;
            }

            EndEmulator(cardTransmitter);
            return true;
        }



        void selftest()
        {
            Logger.Info("Self-test Mifare DuoX");
            Desfire.MifareDuoXSelfTest();
            Logger.Info("Self-test Desfire EV2");
            Desfire.DesfireEV2SelfTest();
            Logger.Info("Self-test Desfire EV1");
            Desfire.DesfireEV1SelfTest();
            Logger.Info("Self-test OK!");
        }

        bool RunTestSmid(ICardTransmitter? cardTransmitter, bool bSelfTest)
        {
            if (cardTransmitter == null)
            {
                Logger.Info("Smid card transmitter is null");
                return false;
            }
            Smid smid = new Smid(cardTransmitter);
            smid.SetLogger(logger, doLogCrypto, doLogSecrets);

            try
            {
                TestSmid(smid, bSelfTest);
            }
            catch (Exception ex)
            {
                Logger.Error(ex.GetType().FullName);
                Logger.Error(ex.Message);
                Logger.Error(ex.StackTrace);
                return false;
            }
            return true;
        }

        bool parseArgs(string[] args)
        {
            Logger.ReadArgs(args);
            logger = new Logger(this);

            List<LongOpt> options = new List<LongOpt>();
            options.Add(new LongOpt("reader", Argument.Required, null, 'R'));
            options.Add(new LongOpt("test", Argument.No, null, 'T'));
            options.Add(new LongOpt("selftest", Argument.No, null, 'T'));
            options.Add(new LongOpt("self-test", Argument.No, null, 'T'));
            options.Add(new LongOpt("quiet", Argument.No, null, 'q'));
            options.Add(new LongOpt("crypto", Argument.No, null, 0x900));
            options.Add(new LongOpt("log-crypto", Argument.No, null, 0x900));
            options.Add(new LongOpt("secrets", Argument.No, null, 0x901));
            options.Add(new LongOpt("log-secrets", Argument.No, null, 0x901));
            options.Add(new LongOpt("emul", Argument.No, null, 'E'));
            options.Add(new LongOpt("emulation", Argument.No, null, 'E'));
            options.Add(new LongOpt("deter", Argument.No, null, 'D'));
            options.Add(new LongOpt("determinist", Argument.No, null, 'D'));
            options.Add(new LongOpt("deterministic", Argument.No, null, 'D'));
            options.Add(new LongOpt("test", Argument.No, null, 'T'));
            options.Add(new LongOpt("selftest", Argument.No, null, 'T'));
            options.Add(new LongOpt("self-test", Argument.No, null, 'T'));
            options.Add(new LongOpt("changemasterkey", Argument.No, null, 'K'));
            options.Add(new LongOpt("change-master-key", Argument.No, null, 'K'));
            options.Add(new LongOpt("file", Argument.Required, null, 'f'));
            options.Add(new LongOpt("emulfile", Argument.Required, null, 'f'));
            options.Add(new LongOpt("emul-file", Argument.Required, null, 'f'));
            options.Add(new LongOpt("emulinfile", Argument.Required, null, 'i'));
            options.Add(new LongOpt("in", Argument.Required, null, 'i'));
            options.Add(new LongOpt("input", Argument.Required, null, 'i'));
            options.Add(new LongOpt("emulinputfile", Argument.Required, null, 'i'));
            options.Add(new LongOpt("emul-in-file", Argument.Required, null, 'i'));
            options.Add(new LongOpt("emul-input-file", Argument.Required, null, 'i'));
            options.Add(new LongOpt("out", Argument.Required, null, 'o'));
            options.Add(new LongOpt("output", Argument.Required, null, 'o'));
            options.Add(new LongOpt("emuloutfile", Argument.Required, null, 'o'));
            options.Add(new LongOpt("emuloutputfile", Argument.Required, null, 'o'));
            options.Add(new LongOpt("emul-out-file", Argument.Required, null, 'o'));
            options.Add(new LongOpt("emul-output-file", Argument.Required, null, 'o'));
            options.Add(new LongOpt("quiet", Argument.No, null, 'q'));
            options.Add(new LongOpt("desfire-ev0", Argument.No, null, 0x800));
            options.Add(new LongOpt("desfire-ev1", Argument.No, null, 0x810));
            options.Add(new LongOpt("desfire-ev1-legacy", Argument.No, null, 0x811));
            options.Add(new LongOpt("desfire-ev1-ev0", Argument.No, null, 0x811));
            options.Add(new LongOpt("desfire-ev1-3des2k", Argument.No, null, 0x812));
            options.Add(new LongOpt("desfire-ev1-tdes2k", Argument.No, null, 0x812));
            options.Add(new LongOpt("desfire-ev1-3des3k", Argument.No, null, 0x813));
            options.Add(new LongOpt("desfire-ev1-tdes3k", Argument.No, null, 0x813));
            options.Add(new LongOpt("desfire-ev1-aes", Argument.No, null, 0x814));
            options.Add(new LongOpt("desfire-ev2", Argument.No, null, 0x820));
            options.Add(new LongOpt("desfire-ev3", Argument.No, null, 0x830));
            options.Add(new LongOpt("desfire-ev4", Argument.No, null, 0x840));
            options.Add(new LongOpt("mifare-duox", Argument.No, null, 0x840));
            options.Add(new LongOpt("duox", Argument.No, null, 0x840));
            options.Add(new LongOpt("mifare-duox-128", Argument.No, null, 0x841));
            options.Add(new LongOpt("duox-128", Argument.No, null, 0x841));
            options.Add(new LongOpt("mifare-duox-256", Argument.No, null, 0x842));
            options.Add(new LongOpt("duox-256", Argument.No, null, 0x842));
            options.Add(new LongOpt("mifare-duox-ecc", Argument.No, null, 0x843));
            options.Add(new LongOpt("duox-ecc", Argument.No, null, 0x843));
            options.Add(new LongOpt("crypto", Argument.No, null, 0x900));
            options.Add(new LongOpt("log-crypto", Argument.No, null, 0x900));
            options.Add(new LongOpt("secrets", Argument.No, null, 0x901));
            options.Add(new LongOpt("log-secrets", Argument.No, null, 0x901));

            Getopt g = new Getopt("Test", args, "R:EDTKf:i:o:qv::h", options.ToArray());
            g.Opterr = true;
            int c;

            /* Parse arguments */
            /* --------------- */

            while ((c = g.getopt()) != -1)
            {
                string arg = g.Optarg;

                switch (c)
                {
                    case 'R':
                        readerName = arg;
                        break;
                    case 'q':
                        quiet = true;
                        break;
                    case 'T':
                        Console.WriteLine("Self-test mode enabled");
                        doSelfTest = true;
                        break;
                    case 'E':
                        doEmulation = true;
                        break;
                    case 'D':
                        doDeterministic = true;
                        break;

                    case 'K':
                        doChangeMasterKey = true;
                        break;

                    case 'f':
                        emulInputFile = arg;
                        emulOutputFile = arg;
                        break;
                    case 'i':
                        emulInputFile = arg;
                        break;
                    case 'o':
                        emulOutputFile = arg;
                        break;

                    case 0x800:
                        actions |= EActions.DesfireEV0;
                        break;
                    case 0x810:
                        actions |= EActions.DesfireEV1;
                        break;
                    case 0x811:
                        actions |= EActions.DesfireEV1Legacy;
                        break;
                    case 0x812:
                        actions |= EActions.DesfireEV1TDes2k;
                        break;
                    case 0x813:
                        actions |= EActions.DesfireEV1TDes3k;
                        break;
                    case 0x814:
                        actions |= EActions.DesfireEV1Aes;
                        break;
                    case 0x820:
                        actions |= EActions.DesfireEV2;
                        break;
                    case 0x830:
                        actions |= EActions.DesfireEV3;
                        break;
                    case 0x840:
                        actions |= EActions.MifareDuoX;
                        break;
                    case 0x841:
                        actions |= EActions.MifareDuoXAes128;
                        break;
                    case 0x842:
                        actions |= EActions.MifareDuoXAes256;
                        break;
                    case 0x843:
                        actions |= EActions.MifareDuoXAesEcc;
                        break;
                    case 0x900:
                        doLogCrypto = true;
                        break;
                    case 0x901:
                        doLogSecrets = true;
                        break;
                }
            }

            return true;
        }

        bool main(string[] args)
        {
            if (!parseArgs(args))
                return false;

            //Desfire.DuoXSessionKeysSelfTest();
            //Desfire.DuoXAsymmetricAuthenticationSelfTest();
            //Desfire.VerifyPCSelfTest();

            ICardTransmitter? cardTransmitter = null;
            string[] readerNames = SCARD.ListReaders();
            if (readerNames != null)
            {
                foreach (string _readerName in readerNames)
                {
                    if (_readerName.ToLower().Contains("springcard") && _readerName.ToLower().Contains("contactless"))
                    {
                        readerName = _readerName;
                        break;
                    }
                }
            }

            if (doEmulation)
            {

            }
            else if (readerName != null)
            {
                Logger.Trace("Main reader found ({0})", readerName);
                SCardReader cardReader = new SCardReader(readerName);

                if (cardReader == null)
                {
                    Logger.Error("Main reader not found");
                    return false;
                }

                if (!cardReader.CardPresent)
                {
                    Logger.Error("No card in reader");
                    return false;
                }

                SCardChannel cardChannel = new SCardChannel(cardReader);

                if (!cardChannel.ConnectExclusive())
                {
                    Logger.Error("Failed to connect to the card");
                    return false;
                }

                cardTransmitter = cardChannel;
            }
            else
            {
                Logger.Error("No PC/SC reader");
                return false;
            }

            //if ((actions & EActions.Smid) != 0)
            //{
            //    Logger.Info("Test Smid ");
            //    if (!RunTestSmid(cardTransmitter, doSelfTest))
            //    {
            //        Logger.Error("Test Smid : failed");
            //        return false;
            //    }
            //}

            if ((actions & EActions.DesfireEV0) != 0)
            {
                Logger.Info("Test Desfire EV0");
                if (!RunTestDesfireEV0(cardTransmitter))
                {
                    Logger.Error("Test Desfire EV0 : failed");
                    return false;
                }
            }

            if ((actions & EActions.DesfireEV1Aes) != 0)
            {
                Logger.Info("Test DesfireEV1 AES");
                if (!RunTestDesfireEV1(cardTransmitter, DesfireEV1TestMode.Aes))
                {
                    Logger.Error("Test Desfire EV1 AES: failed");
                    return false;
                }
            }

            if ((actions & EActions.DesfireEV1TDes2k) != 0)
            {
                Logger.Info("Test Desfire EV1 TDES2K");
                if (!RunTestDesfireEV1(cardTransmitter, DesfireEV1TestMode.TDes2k))
                {
                    Logger.Error("Test Desfire EV1 TDES2K: failed");
                    return false;
                }
            }

            if ((actions & EActions.DesfireEV1TDes3k) != 0)
            {
                Logger.Info("Test Desfire EV1 TDES3K");
                if (!RunTestDesfireEV1(cardTransmitter, DesfireEV1TestMode.TDes3k))
                {
                    Logger.Error("Test Desfire EV1 TDES3K: failed");
                    return false;
                }
            }

            if ((actions & EActions.DesfireEV1Legacy) != 0)
            {
                Logger.Info("Test Desfire EV1 (legacy)");
                if (!RunTestDesfireEV1(cardTransmitter, DesfireEV1TestMode.Legacy))
                {
                    Logger.Error("Test Desfire EV1 (legacy): failed");
                    return false;
                }
            }

            if ((actions & EActions.DesfireEV2) != 0)
            {
                Logger.Info("Test Desfire EV2 AES");
                if (!RunTestDesfireEV2(cardTransmitter))
                {
                    Logger.Error("Test Desfire EV2 AES: failed");
                    return false;
                }
            }

            if ((actions & EActions.MifareDuoXAesEcc) != 0)
            {
                Logger.Info("Test Mifare DuoX ECC");
                if (!RunTestMifareDuoXEcc(cardTransmitter))
                {
                    Logger.Error("Test Mifare DuoX ECC: failed");
                    return false;
                }
            }

            if ((actions & EActions.MifareDuoXAes256) != 0)
            {
                Logger.Info("Test Mifare DuoX AES256");
                if (!RunTestMifareDuoXAes(cardTransmitter, true))
                {
                    Logger.Error("Test Mifare DuoX AES256: failed");
                    return false;
                }
            }

            if ((actions & EActions.MifareDuoXAes128) != 0)
            {
                Logger.Info("Test Mifare DuoX AES128");
                if (!RunTestMifareDuoXAes(cardTransmitter, false))
                {
                    Logger.Error("Test Mifare DuoX AES128: failed");
                    return false;
                }
            }

            Logger.Info("All tests passed");
            Console.WriteLine();
            Console.WriteLine("Success");
            return true;
        }

        static void Main(string[] args)
        {
            Program p = new Program();
            p.main(args);
        }
    }
}
