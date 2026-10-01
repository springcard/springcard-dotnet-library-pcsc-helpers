/**
 *
 * \author
 *   Johann.D et al. / SpringCard
 */
/*
 * Read LICENSE.txt for license details and restrictions.
 */
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using SpringCard.LibCs;
using SpringCard.PCSC;

namespace SpringCard.PCSC.CardHelpers
{
    public class FakeCardTransmitter : ICardApduTransmitter, ICardTransmitter
    {
        private bool connected = true;
        private Dictionary<string, string> apduPairs = new Dictionary<string, string>();
        private int apduIndex = 0;
        private List<string> apduResponses = new List<string>();
        private ILogger logger;

        public void SetLogger(ILogger logger)
        {
            this.logger = logger;
        }

        public FakeCardTransmitter()
        {

        }

        public FakeCardTransmitter(Dictionary<CAPDU, RAPDU> ApduPairs)
        {
            foreach (KeyValuePair<CAPDU, RAPDU> entry in ApduPairs)
                AddApduPair(entry.Key, entry.Value);
        }

        public FakeCardTransmitter(List<RAPDU> ApduResponses)
        {
            foreach (RAPDU rapdu in ApduResponses)
                apduResponses.Add(rapdu.AsString());
        }

        public void AddApduPair(CAPDU Command, RAPDU Response)
        {
            AddApduPair(Command.AsString(), Response.AsString());
        }

        public void AddApduPair(string Command, string Response)
        {
            this.apduPairs[Command] = Response;
        }

        private void AddApduPair(byte[] Command, byte[] Response)
        {
            this.apduPairs[BinConvert.ToHex(Command)] = BinConvert.ToHex(Response);
        }

        private void Log(string msg, byte[] buffer)
        {
            if (logger != null)
            {
                logger.trace(msg);
                string text = BinConvert.HexDump(buffer, 0, buffer.Length);
                logger.trace("\n{0}", text);
            }
        }

        public RAPDU Transmit(CAPDU ApduCommand)
        {
            if (!connected)
                throw new Exception("FakeCardTransmitter is not connected");

            Log("C-APDU", ApduCommand.Bytes);

            RAPDU responseApdu = null;

            if (apduPairs.Count > 0)
            {
                string commandString = ApduCommand.AsString();
                if (apduPairs.ContainsKey(commandString))
                    responseApdu = new RAPDU(apduPairs[commandString]);
            }
            else if (apduResponses != null)
            {
                if (apduIndex < apduResponses.Count)
                    responseApdu = new RAPDU(apduResponses[apduIndex]);               
            }
            else
            {
                throw new Exception("FakeCardTransmitter must provide APDU responses");
            }

            if (responseApdu == null)
                responseApdu = new RAPDU(0x6F00);

            Log("R-APDU", responseApdu.Bytes);

            return responseApdu;
        }

        public byte[] Transmit(byte[] ApduCommand)
        {
            if (!connected)
                throw new Exception("FakeCardTransmitter is not connected");

            Log("C-APDU", ApduCommand);

            byte[] responseApdu = null;

            if (apduPairs.Count > 0)
            {
                string commandString = BinConvert.ToHex(ApduCommand);
                if (apduPairs.ContainsKey(commandString))
                    responseApdu = BinConvert.HexToBytes(apduPairs[commandString]);
            }
            else if (apduResponses != null)
            {
                if (apduIndex < apduResponses.Count)
                    responseApdu = BinConvert.HexToBytes(apduResponses[apduIndex]);
            }
            else
            {
                throw new Exception("FakeCardTransmitter must provide APDU responses");
            }

            if (responseApdu == null)
                responseApdu = new byte[2] { 0x6F, 0x00 };

            Log("R-APDU", responseApdu);

            return responseApdu;
        }

        public void Disconnect()
        {
            connected = false;
        }

        public void Reconnect()
        {
            connected = true;
            apduIndex = 0;
        }
    }

}