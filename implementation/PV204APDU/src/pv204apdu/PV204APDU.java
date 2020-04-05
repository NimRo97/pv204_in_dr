package pv204apdu;

import applets.PV204Applet;
import cardTools.CardManager;
import cardTools.RunConfig;
import cardTools.Util;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import javax.crypto.KeyAgreement;

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
    private static final String STR_APDU_VERIFYPIN = "B05500000401020304";

    /**
     * Main entry point.
     *
     * @param args
     */
    public static void main(String[] args) {
        try {
            PV204APDU main = new PV204APDU();
            
            //main.demoGetRandomDataCommand();
            //main.demoInstallPIN();
            main.demoGenerateECDH();
            
        } catch (Exception ex) {
            System.out.println("Exception : " + ex);
        }
    }
    
    public void demoGenerateECDH() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(224);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        KeyAgreement dh = KeyAgreement.getInstance("ECDH");
        dh.init(keyPair.getPrivate());
        
        ECPoint w = ((ECPublicKey) keyPair.getPublic()).getW();
        byte[] affineX = w.getAffineX().toByteArray();
        byte[] affineY = w.getAffineY().toByteArray();
        int keyLen = 224/8 + 1;
        //if (affineX.length)
        
        byte[] x962encoded = new byte[2 * keyLen + 1];
        x962encoded[0] = (byte) 0x04;
        System.arraycopy(affineX, 0, x962encoded, 1 + keyLen - affineX.length, affineX.length);
        System.arraycopy(affineY, 0, x962encoded, 1 + 2* keyLen - affineY.length, affineY.length);
        
        byte[] data = Util.concat(Util.hexStringToByteArray("B05900003B"), x962encoded);
        System.out.println(Util.bytesToHex(data));
        
        
        final CardManager cardMngr = new CardManager(true, APPLET_AID_BYTE);
        final RunConfig runCfg = RunConfig.getDefaultConfig();
        runCfg.setAppletToSimulate(PV204Applet.class);
        runCfg.setTestCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL);
        
        byte[] installData = Util.hexStringToByteArray("0a" + APPLET_AID +
                                                       "00" +
                                                       "0401020304");
        runCfg.setInstallData(installData);
        
        System.out.print("Connecting to card...");
        if (!cardMngr.Connect(runCfg)) {
            System.out.println(" Failed.");
        }
        System.out.println(" Done.");
        
        final ResponseAPDU response = cardMngr.transmit(new CommandAPDU(data));
        byte[] responseData = response.getData();
        final ResponseAPDU response2 = cardMngr.transmit(new CommandAPDU(Util.hexStringToByteArray("B0600000")));
        byte[] secret = response2.getData();
        
        byte[] cardX = new byte[28];
        byte[] cardY = new byte[28];
        
        System.arraycopy(responseData, 1, cardX, 0, 28);
        System.arraycopy(responseData, 29, cardY, 0, 28);
        
        // generate bogus keypair(!) with named-curve params
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec gps = new ECGenParameterSpec ("secp224r1"); // NIST P-256 
        kpg.initialize(gps);
        KeyPair apair = kpg.generateKeyPair();
        ECPublicKey apub  = (ECPublicKey)apair.getPublic();
        ECParameterSpec aspec = apub.getParams();
        // could serialize aspec for later use (in compatible JRE)
        //
        // for test only reuse bogus pubkey, for real substitute values 
        ECPoint apoint = apub.getW();
        BigInteger x = new BigInteger(cardX);
        BigInteger y = new BigInteger(cardY);
        // construct point plus params to pubkey
        ECPoint bpoint = new ECPoint (x,y);
        ECPublicKeySpec bpubs = new ECPublicKeySpec (bpoint, aspec);
        KeyFactory kfa = KeyFactory.getInstance ("EC");
        ECPublicKey bpub = (ECPublicKey) kfa.generatePublic(bpubs);
        
        dh.doPhase(bpub, true);
        byte[] derivedSecret = dh.generateSecret();
        
        MessageDigest md = MessageDigest.getInstance("SHA");
        byte[] hash = md.digest(derivedSecret);
        
        System.out.println(Util.bytesToHex(hash));
        
    }
    
    public void demoInstallPIN() throws Exception {
        
        final CardManager cardMngr = new CardManager(true, APPLET_AID_BYTE);
        final RunConfig runCfg = RunConfig.getDefaultConfig();
        runCfg.setAppletToSimulate(PV204Applet.class);
        runCfg.setTestCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL);
        
        byte[] installData = Util.hexStringToByteArray("0a" + APPLET_AID +
                                                       "00" +
                                                       "0401020304");
        runCfg.setInstallData(installData);
        
        System.out.print("Connecting to card...");
        if (!cardMngr.Connect(runCfg)) {
            System.out.println(" Failed.");
        }
        System.out.println(" Done.");
        
        final ResponseAPDU response = cardMngr.transmit(new CommandAPDU(Util.hexStringToByteArray(STR_APDU_VERIFYPIN)));
        byte[] data = response.getData();
        
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
