/*
 * Crée par SharpDevelop.
 * Utilisateur: johann
 * Date: 05/01/2012
 * Heure: 12:02
 * 
 * Pour changer ce modèle utiliser Outils | Options | Codage | Editer les en-têtes standards.
 */
using System;
using SpringCard.LibCs;
using SpringCard.PCSC;

namespace SpringCard.PCSC.CardEmulation
{
	/// <summary>
	/// Description of PiccEmulDesfireEV0.
	/// </summary>
	public class CardEmulLoopback : CardEmulCardlet
	{
		public CardEmulLoopback()
		{

		}
		
		public override void Reconnect()
		{
            Logger.Info("Loopback:Select");
        }

		public override void Disconnect()
		{
            Logger.Info("Loopback:Deselect");
        }

		public override byte[] Transmit(byte[] capdu)
		{
            Logger.Info("Loopback:APDU");
            System.Threading.Thread.Sleep(100);
			return new byte[] { 0x90, 0x00 };
		}
	}
}
