using SpringCard.LibCs;

#if NETFRAMEWORK
using Microsoft.Win32;
#endif

namespace SpringCard.PCSC.ReaderHelpers
{
    public class PcscBridge
    {
        private static Logger logger = new Logger(typeof(PcscBridge).FullName);
        public const string BridgeDevicesRegistryKeyName = @"SOFTWARE\SpringCard\Drivers\Devices";
        public const string BridgeRuntimeRegistryKeyName = @"SOFTWARE\SpringCard\PcscBridge\Runtime";

        public static bool IsBridgeReader(string ReaderName)
        {
            return IsBridgeReader(ReaderName, out bool dummyActive, out bool dummyConnected);
        }

        public static bool IsBridgeReader(string ReaderName, out bool IsActive, out bool IsConnected)
        {
            bool IsFound = false;
            IsActive = false;
            IsConnected = false;
#if NETFRAMEWORK
            try
            {
                RegistryKey hklmKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
                RegistryKey bridgeDevicesKey = hklmKey.OpenSubKey(BridgeDevicesRegistryKeyName, RegistryKeyPermissionCheck.ReadSubTree);

                if (bridgeDevicesKey != null)
                {
                    foreach (string subkeyName in bridgeDevicesKey.GetSubKeyNames())
                    {
                        RegistryKey bridgeDeviceSubkey = bridgeDevicesKey.OpenSubKey(subkeyName, RegistryKeyPermissionCheck.ReadSubTree);
                        string instanceName = (string)bridgeDeviceSubkey.GetValue("Instance", "");
                        if (string.IsNullOrEmpty(instanceName))
                            continue;
                        if (!int.TryParse(instanceName, out int instanceNumber))
                            continue;
                        string deviceName = (string)bridgeDeviceSubkey.GetValue("DeviceName", "");
                        if (string.IsNullOrEmpty(deviceName))
                            continue;

                        for (int i = 0; i < 8; i++)
                        {
                            string slotField = string.Format("SlotName{0}", i);
                            if (bridgeDeviceSubkey.GetValue(slotField) == null)
                                continue;
                            string slotName = (string)bridgeDeviceSubkey.GetValue(slotField, "");
                            if (string.IsNullOrEmpty(slotName))
                                continue;

                            string possibleReaderName = string.Format("{0} {1} {2}", deviceName, slotName, instanceNumber);
                            if (possibleReaderName == ReaderName)
                            {
                                logger.debug("Reader {0} is a bridge (instance {0})", ReaderName, instanceName);
                                IsFound = true;
                                break;
                            }
                        }

                        if (IsFound)
                        {
                            string bridgeRuntimeKeyName = string.Format(@"{0}\{1}", BridgeRuntimeRegistryKeyName, instanceName);
                            RegistryKey bridgeRuntimeKey = hklmKey.OpenSubKey(bridgeRuntimeKeyName, RegistryKeyPermissionCheck.ReadSubTree);

                            if (bridgeRuntimeKey != null)
                            {
                                Int32 activeState = (Int32)bridgeRuntimeKey.GetValue("Active", (Int32)0);
                                if (activeState != 0)
                                    IsActive = true;
                                Int32 connectedState = (Int32)bridgeRuntimeKey.GetValue("Connected", (Int32)0);
                                if (connectedState != 0)
                                    IsConnected = true;
                                logger.debug("Active: {0}, Connected: {1}", activeState, connectedState);
                            }
                            else
                            {
                                logger.debug("No runtime data for bridge instance {0}", instanceName);
                            }

                            break;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                logger.trace("Is {0} a bridge or not? Exception {1}", ReaderName, ex.Message);
            }
#endif
            return IsFound;
        }
    }
}
