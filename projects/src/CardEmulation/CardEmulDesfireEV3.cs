/*
 * Crée par SharpDevelop.
 * Utilisateur: johann
 * Date: 05/01/2012
 * Heure: 12:02
 * 
 * Pour changer ce modèle utiliser Outils | Options | Codage | Editer les en-têtes standards.
 */
using SpringCard.LibCs;
using System;
using System.Collections.Generic;
using System.Text;
using System.Xml;

namespace SpringCard.PCSC.CardEmulation
{
    /// <summary>
    /// Description of PiccEmulDesfireEV3.
    /// </summary>
    public class CardEmulDesfireEV3 : CardEmulDesfireEV2
    {
        public CardEmulDesfireEV3() : base()
        {

        }

        protected override string GetVersion()
        {
            return "EV3";
        }


    }
}
