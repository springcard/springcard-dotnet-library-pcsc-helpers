using System;
using System.Drawing;
using System.Collections.Generic;
using SpringCard.PCSC;
using SpringCard.LibCs;
using System.Security.Cryptography;

namespace SpringCard.PCSC.ReaderHelpers
{
    public class SpringCardReader
    {
        protected SCardChannel channel;

        public Dictionary<string, string> Data { get; protected set; } = new Dictionary<string, string>();
        public bool IsSpringCore { get; protected set; }
        public bool IsSpringProx { get; protected set; }

        public SpringCardReader(SCardChannel channel)
        {
            this.channel = channel;
        }

        public bool SendControlApdu(byte P1, byte P2, byte[] Data = null)
        {
            return CLControlSet(P1, P2, Data);
        }

        public bool CLControlSet(byte P1, byte P2, byte[] Data = null)
        {
            CAPDU capdu = new CAPDU(0xFF, 0xFB, P1, P2, Data);
            RAPDU rapdu = channel.Transmit(capdu);
            if (rapdu == null)
                return false;
            if (rapdu.SW != 0x9000)
                return false;
            return true;
        }

        public bool CLControlGet(byte P1, byte P2, out byte[] Data)
        {
            Data = null;
            CAPDU capdu = new CAPDU(0xFF, 0xFB, P1, P2, 0);
            RAPDU rapdu = channel.Transmit(capdu);
            if (rapdu == null)
                return false;
            if (rapdu.SW != 0x9000)
                return false;
            Data = rapdu.Bytes;
            return true;
        }

        public bool CLControlGet(byte P1, byte P2, out uint Data)
        {
            Data = 0;
            if (!CLControlGet(P1, P2, out byte[] _data))
                return false;
            if ((_data == null) || (_data.Length != 4))
                return false;
            Data = BinUtils.ToDword(_data);
            return true;
        }

        public bool ResumeCardTracking()
        {
            return CLControlSet(0x00, 0x00);
        }

        public bool SuspendCardTracking()
        {
            return CLControlSet(0x01, 0x00);
        }

        public bool RFFieldOff()
        {
            return CLControlSet(0x10, 0x00);
        }

        public bool RFFieldOn()
        {
            return CLControlSet(0x10, 0x01);
        }

        public bool RFFieldReset()
        {
            return CLControlSet(0x10, 0x02);
        }

        public bool RFFieldResetOnRemoval()
        {
            return CLControlSet(0x10, 0x03);
        }

        public bool IsoAHalt()
        {
            return CLControlSet(0x12, 0x01);
        }

        public bool IsoASelectAgain()
        {
            return CLControlSet(0x13, 0x01);
        }

        public bool IsoVQuiet()
        {
            return CLControlSet(0x12, 0x04);
        }

        public bool IsoVSelect()
        {
            return CLControlSet(0x14, 0x04);
        }

        public bool TclDeselect()
        {
            return CLControlSet(0x20, 0x00);
        }

        public bool TclARats()
        {
            return CLControlSet(0x20, 0x01);
        }

        public bool TclBAttrib()
        {
            return CLControlSet(0x20, 0x02);
        }

        public bool TclReset()
        {
            return CLControlSet(0x20, 0x03);
        }

        public bool TclDisableOnce()
        {
            return CLControlSet(0x20, 0x04);
        }

        public bool TclDisableForever()
        {
            return CLControlSet(0x20, 0x05);
        }

        public bool TclEnable()
        {
            return CLControlSet(0x20, 0x06);
        }

        public bool TclGotoRaw()
        {
            return CLControlSet(0x20, 0x07);
        }

        public bool NfcFSetReadServiceCode(ushort ServiceCode)
        {
            return CLControlSet(0xFC, 0x01, BinUtils.FromWord(ServiceCode));
        }

        public bool NfcFSetWriteServiceCode(ushort ServiceCode)
        {
            return CLControlSet(0xFC, 0x02, BinUtils.FromWord(ServiceCode));
        }

        public bool NfcFSetSystemCode(ushort SystemCode)
        {
            return CLControlSet(0xFC, 0x10, BinUtils.FromWord(SystemCode));
        }

        public bool NfcFSetRequestCode(byte RequestCode)
        {
            return CLControlSet(0xFC, 0x10, new byte[1] { RequestCode });
        }

        public bool NfcVSetReadWriteOptions(byte[] ReadWriteOptions)
        {
            return CLControlSet(0xFD, 0x00, ReadWriteOptions);
        }

        public bool NfcVUseBroadcastMode()
        {
            return CLControlSet(0xFD, 0x10);
        }

        public bool NfcVUseAddressedMode()
        {
            return CLControlSet(0xFD, 0x11);
        }

        public bool NfcVUseSelectedMode()
        {
            return CLControlSet(0xFD, 0x12);
        }

        public bool PcdGetShortStats(out ushort blocks, out uint duration_ms)
        {
            blocks = 0;
            duration_ms = 0;
            if (!CLControlGet(0x21, 0x00, out byte[] _data))
                return false;
            if ((_data == null) || (_data.Length < 6))
                return false;
            blocks = BinUtils.ToWord(BinUtils.Copy(_data, 0, 2));
            duration_ms = BinUtils.ToDword(BinUtils.Copy(_data, 2, 4));
            return true;
        }

        public bool PcdGetLastPiccFdt(out uint value)
        {
            return CLControlGet(0x21, 0x01, out value);
        }

        public string GetTextData(byte index)
        {
            byte[] data = channel.Control(new byte[] { 0x58, 0x20, index });
            if ((data == null) || (data.Length < 1) || (data[0] != 0x00))
                return null;
            return StrUtils.ToStr_UTF8(data, 1);
        }

        public string GetSlotName()
        {
            byte[] data = channel.Control(new byte[] { 0x58, 0x21 });
            if ((data == null) || (data.Length < 1) || (data[0] != 0x00))
                return null;
            return StrUtils.ToStr_UTF8(data, 1);
        }

        public bool ReadData()
        {
            string t;

            IsSpringCore = false;
            IsSpringProx = false;
            Data.Clear();

            t = GetTextData(0x01);
            if (!string.IsNullOrEmpty(t))
                Data.Add("Vendor name", t);

            t = GetTextData(0x02);
            if (!string.IsNullOrEmpty(t))
                Data.Add("Product name", t);

            t = GetSlotName();
            if (!string.IsNullOrEmpty(t))
                Data.Add("Slot name", t);

            t = GetTextData(0x03);
            if (!string.IsNullOrEmpty(t))
                Data.Add("Serial number", t);

            t = GetTextData(0x04);
            if (!string.IsNullOrEmpty(t))
                Data.Add("USB ID", t);

            t = GetTextData(0x05);
            if (!string.IsNullOrEmpty(t))
                Data.Add("Version", t);

            t = GetTextData(0x06);
            if (!string.IsNullOrEmpty(t))
                Data.Add("Revision", t);

            t = GetTextData(0x07);
            if (!string.IsNullOrEmpty(t))
                Data.Add("Firmware", t);

            t = GetTextData(0x08);
            if (!string.IsNullOrEmpty(t))
                Data.Add("Build user", t);

            t = GetTextData(0x09);
            if (!string.IsNullOrEmpty(t))
                Data.Add("Build date", t);

            t = GetTextData(0x0A);
            if (!string.IsNullOrEmpty(t))
                Data.Add("Ethernet address", t);

            t = GetTextData(0x0B);
            if (!string.IsNullOrEmpty(t))
                Data.Add("Bluetooth address", t);

            t = GetTextData(0x0C);
            if (!string.IsNullOrEmpty(t))
                Data.Add("Bluetooth device name", t);

            t = GetTextData(0x0D);
            if (!string.IsNullOrEmpty(t))
                Data.Add("Unique ID", t);

            t = GetTextData(0x0E);
            if (!string.IsNullOrEmpty(t))
                Data.Add("Config ID", t);

            t = GetTextData(0x0F);
            if (!string.IsNullOrEmpty(t))
                Data.Add("Hardware", t);

            t = GetTextData(0x10);
            if (!string.IsNullOrEmpty(t))
                Data.Add("Contactless", t);

            t = GetTextData(0x11);
            if (!string.IsNullOrEmpty(t))
                Data.Add("Smartcard", t);

            t = GetTextData(0x41);
            if (!string.IsNullOrEmpty(t))
                Data.Add("Orig. Vendor name", t);

            t = GetTextData(0x42);
            if (!string.IsNullOrEmpty(t))
                Data.Add("Orig. Product name", t);

            t = GetTextData(0x4A);
            if (!string.IsNullOrEmpty(t))
                Data.Add("Orig. Ethernet address", t);

            t = GetTextData(0x4B);
            if (!string.IsNullOrEmpty(t))
                Data.Add("Orig. Bluetooth address", t);

            if (Data.Count == 0)
                return false;

            return true;
        }
    }
}
