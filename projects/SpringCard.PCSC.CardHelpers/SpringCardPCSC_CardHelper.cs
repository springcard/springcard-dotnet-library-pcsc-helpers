/**
 *
 * \author
 *   Johann.D et al. / SpringCard
 */
/*
 * Read LICENSE.txt for license details and restrictions.
 */
using System;
using System.Runtime.InteropServices;
using SpringCard.LibCs;
using SpringCard.PCSC;

namespace SpringCard.PCSC.CardHelpers
{
	public abstract class CardHelper
	{	
		protected ICardApduTransmitter Channel;

		public CardHelper(ICardApduTransmitter Channel)
		{
			this.Channel = Channel;
		}
		
		public abstract bool SelfTest();
	}	

	public class CardInfo : CardHelper
	{
		public CardInfo(ICardApduTransmitter Channel) : base (Channel)
		{
		}

		public byte[] GetUid()
		{
			CAPDU capdu = new CAPDU(0xFF, 0xCA, 0x00, 0x00, 0x00);
			RAPDU rapdu = Channel.Transmit(capdu);
			if ((rapdu != null) && (rapdu.SW == 0x9000))
				return rapdu.DataBytes;
			return null;
		}

		public override bool SelfTest()
		{
			return true;
		}
	}
}
