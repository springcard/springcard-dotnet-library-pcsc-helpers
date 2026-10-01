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
using System.Security.Cryptography;
using SpringCard.LibCs;
using SpringCard.PCSC;

namespace SpringCard.PCSC.CardHelpers
{
	public interface IRandomGenerator
	{
		byte[] Get(int length);
	}

	public class DefaultRandomGenerator : IRandomGenerator
	{
		RandomNumberGenerator rand;

		public DefaultRandomGenerator()
		{
			rand = RandomNumberGenerator.Create();
		}

		public byte[] Get(int length)
		{
			byte[] result = new byte[length];
            rand.GetBytes(result, 0, length);
			return result;
		}
	}

	public class FakeRandomGenerator : IRandomGenerator
	{
		byte state;
		byte[] sequence;
		uint offset;

		public FakeRandomGenerator()
		{
			Set(0);
		}

        public FakeRandomGenerator(byte state)
        {
            Set(state);
        }

        public FakeRandomGenerator(byte[] sequence)
		{
			Set(sequence);
		}

		public void Set(byte state)
		{
			this.sequence = null;
			this.state = state;
		}

		public void Set(byte[] sequence)
		{
			this.sequence = sequence;
			this.offset = 0;
		}

		public void Reset()
        {
			this.state = 0x00;
        }

		public byte[] Get(int length)
		{
			byte[] result = new byte[length];
			if (sequence != null)
			{
				for (int i = 0; i < result.Length; i++)
				{
					if (offset >= sequence.Length)
						offset = 0;
					result[i] = sequence[offset++];
				}
			}
			else
			{ 
				for (int i = 0; i < result.Length; i++)
					result[i] = state++;
			}
			return result;
		}
	}
}