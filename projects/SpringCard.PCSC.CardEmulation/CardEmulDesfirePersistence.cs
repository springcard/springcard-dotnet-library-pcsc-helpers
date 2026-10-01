/*
 * Crée par SharpDevelop.
 * Utilisateur: johann
 * Date: 05/01/2012
 * Heure: 12:02
 * 
 * Pour changer ce modèle utiliser Outils | Options | Codage | Editer les en-têtes standards.
 */
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;

namespace SpringCard.PCSC.CardEmulation
{
    /// <summary>
    /// Description of PiccEmulDesfire.
    /// </summary>
    public partial class CardEmulDesfire
    {
        public JObject ToJObject()
        {
            JObject result = new JObject
            {
                ["Card"] = "Desfire",
                ["Type"] = CardTypeName,
                ["RootKeySettings"] = String.Format("{0:X02}", RootKeySettings),
            };

            if (RootApplication != null)
            {
                result["RootKeys"] = new JObject();
                foreach (KeyValuePair<byte, DesfireKey> kvp in RootApplication.Keys)
                    result["RootKeys"][string.Format("{0:X02}", kvp.Key)] = kvp.Value.ToJObject();
            }

            if (Applications.Count > 0)
            {
                result["Applications"] = new JObject();
                foreach (KeyValuePair<uint, DesfireApplication> kvp in Applications)
                    result["Applications"][string.Format("{0:X06}", kvp.Key)] = kvp.Value.ToJObject();
            }

            return result;
        }

        public override bool SaveToJson(string FileName)
        {
            File.WriteAllText(FileName, ToJObject().ToString());
            return true;
        }
    }
}
