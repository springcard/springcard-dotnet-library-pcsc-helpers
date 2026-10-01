/*
 * Created by SharpDevelop.
 * User: Jerome Izaac
 * Date: 08/09/2017
 * Time: 14:03
 * 
 * To change this template use Tools | Options | Coding | Edit Standard Headers.
 */
//using System.Net.NetworkInformation;
//using System.Runtime.InteropServices.WindowsRuntime;
using SpringCard.LibCs;

namespace SpringCard.PCSC.CardHelpers
{
    /// <summary>
    /// Description of Smid_core.
    /// </summary>
    public partial class Smid
    {
        private bool isCommandOk(long status)
        {
            if( (status == Smid.Success) || (status == 0x9000) || (status == 0x9100) || (status == 0x91AF))
                return true;

            return false;
        }
        private bool Command(ref long status)
        {
            status = 0x0000;
            if (Exchange() != true)
            {
                if (xfer_length <= 1)
                {
                    status = (0x6F00) | xfer_buffer[0];
                    logger.trace("Exchange(): received block with inappropriate number of bytes {0:X02} ", status);
                }
                else
                {
                    status = (xfer_buffer[xfer_length-2] << 8) | xfer_buffer[xfer_length - 1];
                    logger.trace("Exchange(): communication error {0:X02} ", status);
                }
            }
            else
            {
                status = (xfer_buffer[xfer_length - 2] << 8) | xfer_buffer[xfer_length - 1];
            }

            if ( isCommandOk(status) == false)
            {
                logger.trace("Command(): command failed with status {0:X04}", status);
                return false;
            }
            status = Smid.Success;
            return true;
        }

        bool Exchange()
        {
            byte[] recv_buffer = new byte[256];
            UInt16 recv_length = (UInt16)recv_buffer.Length;

            logger.debug("<< {0}", BinConvert.ToHex(xfer_buffer, xfer_length));
            byte[] to_send = new byte[xfer_length];
            Array.ConstrainedCopy(xfer_buffer, 0, to_send, 0, xfer_length);

            recv_buffer = transmitter.Transmit(to_send);

            if (recv_buffer != null)
            {
                recv_length = (ushort)recv_buffer.Length;
            }
            else
            {
                logger.trace(">> ERROR");
                return false;
            }
            /* Copy the buffer */
            xfer_length = recv_length;
            Array.ConstrainedCopy(recv_buffer, 0, xfer_buffer, 0, recv_length);
            /* Error: block with inappropriate number of bytes received from the PICC. 
             APDU minimum two bytes SW1 SW2 */
            if (xfer_length <= 1)
            {                
                return false;
            }

            logger.debug(">> {0}", BinConvert.ToHex(xfer_buffer, xfer_length));

            return true;
        }

    }
}
