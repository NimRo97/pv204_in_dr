package pv204apdu;

import applets.PV204Applet;
import cardTools.CardManager;
import cardTools.RunConfig;
import cardTools.Util;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 * Test class.
 * Note: If simulator cannot be started try adding "-noverify" JVM parameter
 *
 * @author Petr Svenda (petrs), Dusan Klinec (ph4r05)
 */
public class PV204APDU {
    private static String APPLET_AID = "482871d58ab7465e5e05";
    private static byte APPLET_AID_BYTE[] = Util.hexStringToByteArray(APPLET_AID);

    private static final String STR_APDU_GETRANDOM = "B054100000";

    /**
     * Main entry point.
     *
     * @param args
     */
    public static void main(String[] args) {
        try {
            PV204APDU main = new PV204APDU();
            
            main.demoGetRandomDataCommand();
            
        } catch (Exception ex) {
            System.out.println("Exception : " + ex);
        }
    }

    public void demoGetRandomDataCommand() throws Exception {
        // CardManager abstracts from real or simulated card, provide with applet AID
        final CardManager cardMngr = new CardManager(true, APPLET_AID_BYTE);          
        
        // Get default configuration for subsequent connection to card (personalized later)
        final RunConfig runCfg = RunConfig.getDefaultConfig();

        // A) If running on physical card
        // runCfg.setTestCardType(RunConfig.CARD_TYPE.PHYSICAL); // Use real card

        // B) If running in the simulator 
        runCfg.setAppletToSimulate(PV204Applet.class); // main class of applet to simulate
        runCfg.setTestCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL); // Use local simulator

        // Connect to first available card
        // NOTE: selects target applet based on AID specified in CardManager constructor
        System.out.print("Connecting to card...");
        if (!cardMngr.Connect(runCfg)) {
            System.out.println(" Failed.");
        }
        System.out.println(" Done.");

        // Transmit single APDU
        final ResponseAPDU response = cardMngr.transmit(new CommandAPDU(Util.hexStringToByteArray(STR_APDU_GETRANDOM)));
        byte[] data = response.getData();
        
        final ResponseAPDU response2 = cardMngr.transmit(new CommandAPDU(0xB0, 0x54, 0x00, 0x00, data)); // Use other constructor for CommandAPDU
        
        System.out.println(response);
    }    
}
