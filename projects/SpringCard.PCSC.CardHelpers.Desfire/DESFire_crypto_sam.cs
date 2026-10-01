/*
 * Created by SharpDevelop.
 * User: Jerome Izaac
 * Date: 12/09/2017
 * Time: 14:22
 * 
 * To change this template use Tools | Options | Coding | Edit Standard Headers.
 */
using Org.BouncyCastle.Crypto.Macs;
using SpringCard.LibCs;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace SpringCard.PCSC.CardHelpers
{
    /// <summary>
    /// Description of DESFire_mgmt.
    /// </summary>
    public partial class Desfire
    {
        public class DesfireCryptoContextSAM : DesfireCryptoContext
        {
            ICardApduTransmitter sam_channel;

            public DesfireCryptoContextSAM(Desfire desfire, ICardApduTransmitter sam_channel, EAuthType AuthType) : base(desfire, AuthType, EPaddMode.None, 8, 8)
            {
                this.sam_channel = sam_channel;
            }

            public bool ProcessAuth1(byte[] PiccChal1, out byte[] PcdChal1)
            {
                PcdChal1 = null;
                return false;
            }

            public bool ProcessAuth2(byte[] PiccChal2)
            {
                return false;
            }

            public override void CipherRecv(ref byte[] data)
            {

            }

            public override void CipherSend(ref byte[] data)
            {

            }

            public override byte[] ComputeCmacSend(byte[] data)
            {
                return ComputeCmac(data);
            }
            public override byte[] ComputeCmacRecv(byte[] data)
            {
                data = BinUtils.Copy(data, 1, data.Length - 1);
                return ComputeCmac(data);
            }

            public override byte[] ComputeCmac(byte[] data)
            {
                SAM_GenerateMAC(data, out byte[] cmac);
                return cmac;
            }

            public bool SAM_GenerateMAC(byte[] data_to_update_mac, out byte[] cmac)
            {
                CAPDU capdu;
                RAPDU rapdu;

                cmac = null;

                if (sam_channel == null)
                {
                    return false;
                }
                if (data_to_update_mac == null)
                {
                    return false;
                }

                /* Ask the SAM to update its CMAC */
                /* ------------------------------ */
                capdu = new CAPDU(0x80, (byte)0x7C /*INS.GenerateMac*/, 0x00, 0x00, data_to_update_mac, 0x00);
                Logger.Debug("SAM<{0}", capdu.ToString());
                rapdu = sam_channel.Transmit(capdu);
                if (rapdu == null)
                {
                    return false;
                }
                Logger.Debug("SAM>{0}", rapdu.ToString());
                if (rapdu.SW != 0x9000)
                {
                    return false;
                }

                cmac = new byte[rapdu.DataBytes.Length];
                Array.Copy(rapdu.DataBytes, 0, cmac, 0, rapdu.DataBytes.Length);
                return true;
            }

            bool SAM_VerifyMAC(byte status, byte[] mac_to_check, int MacLength, bool fKeepStatus)
            {
                CAPDU capdu;
                RAPDU rapdu;
                byte[] temp = null;
                int capdu_data_len = 0;
                int RemainingLength = 0;


                if (sam_channel == null)
                {
                    return false;
                }

                if (mac_to_check.Length > 0xFF)
                {
                    /* Several frames need to be sent to the SAM */
                    /* ----------------------------------------- */

                    /* Construct a buffer, intercaling the status byte (00) between data and CMAC, if needed */
                    /* Only one frame needs to be sent to the SAM */
                    /* ------------------------------------------ */

                    if (fKeepStatus)
                    {
                        capdu_data_len = mac_to_check.Length + 1;
                        /* Construct a buffer, intercaling the status byte (00) between data and CMAC, if needed */
                        temp = new byte[capdu_data_len];
                        Array.Copy(mac_to_check, 0, temp, 0, (mac_to_check.Length - MacLength));
                        capdu_data_len += (mac_to_check.Length - MacLength);
                        temp[capdu_data_len++] = status;
                        Array.Copy(mac_to_check, (mac_to_check.Length - MacLength), temp, capdu_data_len, MacLength);

                        RemainingLength = mac_to_check.Length + 1;
                    }
                    else
                    {
                        capdu_data_len = mac_to_check.Length;
                        /* Construct a buffer, intercaling the status byte (00) between data and CMAC, if needed */
                        temp = new byte[capdu_data_len];
                        Array.Copy(mac_to_check, 0, temp, 0, mac_to_check.Length);
                        RemainingLength = mac_to_check.Length;
                    }
                    int idx = 0;
                    byte[] frame = null;
                    while (RemainingLength > 255)
                    {
                        frame = new byte[255];
                        Array.Copy(temp, idx * 255, frame, 0, 255);
                        capdu = new CAPDU(0x80, (byte)0x5C/*INS.VerifyMac*/, 0xAF, 0x00, frame);
                        Logger.Debug("SAM<{0}", capdu.ToString());
                        rapdu = sam_channel.Transmit(capdu);
                        if (rapdu == null)
                        {
                            return false;
                        }
                        Logger.Debug("SAM>{0}", rapdu.ToString());

                        if (rapdu.SW != 0x90AF)
                        {
                            return false;
                        }
                        RemainingLength -= 255;
                        idx++;
                    }
                    frame = new byte[RemainingLength];
                    Array.Copy(temp, idx * 255, frame, 0, RemainingLength);
                    capdu = new CAPDU(0x80, (byte)0x5C/*INS.VerifyMac*/, 0x00, (byte)MacLength, frame);
                    Logger.Debug("SAM<{0}", capdu.ToString());
                    rapdu = sam_channel.Transmit(capdu);
                    if (rapdu == null)
                    {
                        return false;
                    }
                    Logger.Debug("SAM>{0}", rapdu.ToString());

                    if (rapdu.SW != 0x9000)
                    {
                        return false;
                    }

                }
                else
                {
                    /* Only one frame needs to be sent to the SAM */
                    /* ------------------------------------------ */
                    if (fKeepStatus)
                    {
                        capdu_data_len = mac_to_check.Length + 1;
                        /* Construct a buffer, intercaling the status byte (00) between data and CMAC, if needed */
                        temp = new byte[capdu_data_len];
                        Array.Copy(mac_to_check, 0, temp, 0, (mac_to_check.Length - MacLength));
                        capdu_data_len = (mac_to_check.Length - MacLength);
                        temp[capdu_data_len++] = status;
                        Array.Copy(mac_to_check, (mac_to_check.Length - MacLength), temp, capdu_data_len, MacLength);
                    }
                    else
                    {
                        temp = new byte[mac_to_check.Length];
                        Array.Copy(mac_to_check, 0, temp, 0, mac_to_check.Length);
                    }
                    capdu = new CAPDU(0x80, (byte)0x5C/*INS.VerifyMac*/, 0x00, 0x00, temp);
                    Logger.Debug("SAM<{0}", capdu.ToString());
                    rapdu = sam_channel.Transmit(capdu);
                    if (rapdu == null)
                    {
                        return false;
                    }
                    Logger.Debug("SAM>{0}", rapdu.ToString());

                    if (rapdu.SW != 0x9000)
                    {
                        return false;
                    }
                }

                return true;

            }
        }
    }
}
