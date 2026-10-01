/*
 * Crée par SharpDevelop.
 * Utilisateur: johann
 * Date: 05/01/2012
 * Heure: 12:02
 * 
 * Pour changer ce modèle utiliser Outils | Options | Codage | Editer les en-têtes standards.
 */
using Newtonsoft.Json.Linq;
using SpringCard.LibCs;
using System;
using System.Collections.Generic;
using System.Text;
using System.Xml;

namespace SpringCard.PCSC.CardEmulation
{
    /// <summary>
    /// Description of PiccEmulDesfireEV0.
    /// </summary>
    public partial class CardEmulDesfire
    {
        public class DesfireKey
        {
            public byte Version;
            public byte[] Value;

            public DesfireKey(int Length)
            {
                Version = 0;
                Value = new byte[Length];
                for (int i = 0; i < Length; i++)
                    Value[i] = 0;
            }

            public DesfireKey(byte[] Value)
            {
                this.Value = Value;
                Version = 0;
                if ((Value != null) && (Value.Length > 8))
                {
                    for (int i = 0; i < 8; i++)
                        if ((Value[i] & 0x80) != 0)
                            Version |= (byte) (1 << i);
                }
            }

            public DesfireKey(byte[] Value, byte Version)
            {
                this.Version = Version;
                this.Value = Value;
            }

            public bool IsDES()
            {
                if (Value.Length == 8)
                {
                    return true;
                }
                else if (Value.Length == 16)
                {
                    for (int i = 0; i < 8; i++)
                        if ((Value[i + 8] & 0xFE) != (Value[i] & 0xFE))
                            return false;
                    return true;
                }
                else if (Value.Length == 24)
                {
                    for (int i = 0; i < 8; i++)
                        if (((Value[i + 8] & 0xFE) != (Value[i] & 0xFE)) || ((Value[i + 16] & 0xFE) != (Value[i] & 0xFE)))
                            return false;
                    return true;
                }
                return false;
            }

            public bool Is3DES2K()
            {
                if (Value.Length == 8)
                {
                    return false;
                }
                else if (Value.Length == 16)
                {
                    bool k2_eq_k1 = true;
                    for (int i = 0; i < 8; i++)
                        if ((Value[i + 8] & 0xFE) != (Value[i] & 0xFE))
                            k2_eq_k1 = false;
                    if (k2_eq_k1)
                        return false;
                    return true;
                }
                else if (Value.Length == 24)
                {
                    bool k3_eq_k1 = true;
                    for (int i = 0; i < 8; i++)
                        if ((Value[i + 16] & 0xFE) != (Value[i] & 0xFE))
                            k3_eq_k1 = false;
                    if (!k3_eq_k1)
                        return false;
                    return true;
                }
                return false;
            }

            public bool Is3DES3K()
            {
                if (Value.Length != 24)
                    return false;
                bool k3_eq_k1 = true;
                for (int i = 0; i < 8; i++)
                    if ((Value[i + 16] & 0xFE) != (Value[i] & 0xFE))
                        k3_eq_k1 = false;
                if (!k3_eq_k1)
                    return false;
                return true;
            }

            public bool IsAES128()
            {
                if (Value.Length == 16)
                    return true;
                return false;
            }

            public bool IsAES256()
            {
                if (Value.Length == 32)
                    return true;
                return false;
            }

            public void ToXML(XmlTextWriter xtw)
            {
                xtw.WriteElementString("Version", (new CardBuffer(Version)).AsString());
                xtw.WriteElementString("Value", (new CardBuffer(Value)).AsString());
            }

            public JObject ToJObject()
            {
                JObject result = new JObject
                {
                    ["Version"] = BinConvert.ToHex(Version),
                    ["Value"] = BinConvert.ToHex(Value)
                };

                return result;
            }

        }

        public byte GetKeyVersion(CardBuffer DataIn, ref CardBuffer DataOut)
        {
            if (!CheckIn(DataIn, 1))
                return LENGTH_ERROR;

            byte KeyIndex = DataIn.GetByte(0);

            if (CurrentApplication != null)
            {
                if (KeyIndex >= CurrentApplication.Keys.Count)
                    return NO_SUCH_KEY;
                DataOut = new CardBuffer(CurrentApplication.Keys[KeyIndex].Version);
                return OPERATION_OK;
            }
            else
            {
                if (KeyIndex >= RootApplication.Keys.Count)
                    return NO_SUCH_KEY;
                DataOut = new CardBuffer(RootApplication.Keys[KeyIndex].Version);
                return OPERATION_OK;
            }
        }

        public byte ChangeKeySettings(CardBuffer DataIn, ref CardBuffer DataOut)
        {
            if (CipherContext == null)
                return AUTHENTICATION_ERROR;

            if (SessionType == ESessionType.EV2)
            {
                /* CMAC has already been checked by global receiver */
                if (!CheckIn(DataIn, CipherContext.GetBlockSize()))
                    return LENGTH_ERROR;
            }
            else if ((SessionType == ESessionType.EV0) || (SessionType == ESessionType.EV1_TDES) || (SessionType == ESessionType.EV1_AES))
            {
                switch (CipherContext.GetBlockSize())
                {
                    case 8:
                        if (!CheckIn(DataIn, 8))
                            return LENGTH_ERROR;
                        break;
                    case 16:
                        if (!CheckIn(DataIn, 16))
                            return LENGTH_ERROR;
                        break;
                    default:
                        return INTERNAL_ERROR;
                }
            }
            else
            {
                return AUTHENTICATION_ERROR;
            }

            byte[] t = DataIn.GetBytes();

            if (!CipherContext.CipherRecv(ref t))
                return INTEGRITY_ERROR;

            if (CurrentApplication == null)
            {
                RootKeySettings = t[0];
            }
            else
            {
                CurrentApplication.KeySettings = t[0];
            }

            return OPERATION_OK;
        }

    }
}