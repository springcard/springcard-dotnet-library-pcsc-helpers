/**
 *
 * @addtogroup Smid
 *
 * @brief Smid library (.NET only, no native depedency)
 *
 * @copyright
 *   Copyright (c) 2018 SpringCard - www.springcard.com
 *   All right reserved
 *
 * @author
 *   Johann.D et al. / SpringCard
 *
 */
/*
 * Read LICENSE.txt for license details and restrictions.
 */
using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.Serialization;
using SpringCard.LibCs;
using SpringCard.PCSC;
using SpringCard.PCSC.CardHelpers;

namespace SpringCard.PCSC.CardHelpers
{
    /// <summary>
    /// Description of Smid.
    /// </summary>
    public partial class Smid
    {
        [Serializable]
        public class Context : ISerializable
        {
           
            //public SmidIsoWrapping IsoWrapping {  get; set; }
            //public uint CurrentAid { get; set; }
            public SmidCryptoContext CryptoContext { get; set; }

            public void GetObjectData(SerializationInfo info, StreamingContext context)
            {
                //info.AddValue("IsoWrapping", IsoWrapping);
                //info.AddValue("CurrentAid", CurrentAid);
                info.AddValue("CryptoContext", CryptoContext);
            }

            protected Context(SerializationInfo info, StreamingContext context)
            {
                //IsoWrapping = (SmidIsoWrapping)info.GetValue("IsoWrapping", typeof(SmidIsoWrapping));
                //CurrentAid = (uint)info.GetValue("CurrentAid", typeof(uint));
                CryptoContext = (SmidCryptoContext)info.GetValue("CryptoContext", typeof(SmidCryptoContext));
            }

            internal Context()
            {

            }
        }


        /* export current context */
        public Context ExportContext()
        {
            Context result = new Context();

            /*result.IsoWrapping = IsoWrapping;
            result.CurrentAid = CurrentAid;*/
            result.CryptoContext = SessionCryptoContext;
            
            return result;
        }

        public static Smid CreateFromContext(ICardTransmitter transmitter, Context context)
        {
            Smid result = new Smid(transmitter);

            if (!result.ImportContext(context))
                return null;

            return result;
        }

        /* Import current context */
        public bool ImportContext(Context context)
        {
            try
            {
                /*logger.debug("Setting IsoWrapping: " + context.IsoWrapping);
                IsoWrapping = context.IsoWrapping;
                logger.debug("Setting CurrentAid: " + context.CurrentAid);
                CurrentAid = context.CurrentAid;*/
                if (context.CryptoContext == null)
                {
                    logger.debug("No CryptoContext to set");
                }
                else
                {
                    logger.debug("Setting CryptoContext: " + context.CryptoContext.GetType().ToString());
                    SessionCryptoContext = context.CryptoContext;
                }
            }
            catch (Exception ex)
            {
                logger.error($"Exception {ex.GetType().FullName} while importing context: {ex.Message}");
                return false;
            }

            try
            {
                if (SessionCryptoContext != null)
                {
                    logger.debug("Associating the card to the CryptoContext");
                    SessionCryptoContext.SetCard(this);
                }
            }
            catch (Exception ex)
            {
                logger.error($"Exception {ex.GetType().FullName} while activating context: {ex.Message}");
                return false;
            }

            return true;
        }

    }
}