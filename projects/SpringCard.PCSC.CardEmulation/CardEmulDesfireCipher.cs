namespace SpringCard.PCSC.CardEmulation
{
    public abstract partial class CardEmulDesfire
    {
        public interface IDesfireCipher
        {
            void InitSession();

            bool CipherRecv(ref byte[] data);
            bool Unpadd(ref byte[] data);

            bool Padd(ref byte[] data);
            bool CipherSend(ref byte[] data);

            void IncrementCounter();

            byte[] ComputeCmac(byte[] buffer);
            void AppendCmac(ref byte[] buffer);
            bool CheckCmac(byte[] buffer);

            byte[] ComputeCrc(byte[] buffer);
            void AppendCrc(ref byte[] buffer);
            bool CheckCrc(byte[] buffer);

            int GetCmacSize();
            int GetCrcSize();
            int GetBlockSize();
        }
    }
}
