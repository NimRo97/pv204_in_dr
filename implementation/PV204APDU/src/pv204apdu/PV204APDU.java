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
import javax.crypto.KeyAgreement;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 * 
 * @author Imrich Nagy
 * Based on work of Petr Svenda (petrs), Dusan Klinec (ph4r05)
 */
public class PV204APDU {
    private static final String APPLET_AID = "482871d58ab7465e5e05";
    private static final byte APPLET_AID_BYTE[] = Util.hexStringToByteArray(APPLET_AID);
    
    private static final String PIN_LENGTH = "04";
    
    final CardManager cardMngr = new CardManager(true, APPLET_AID_BYTE);
    byte[] ecdhSecret = null;
    byte[] pinSecret = null;
    
    public static void main(String[] args) {
        try {
            PV204APDU main = new PV204APDU();
            
            main.installPinAndConnect();
            main.startEcdhSession();
            
            System.out.println("\nControl of the correctness of the PIN and ECDH Secret:");
            main.compareSecretWithCard();
            main.comparePinWithCard();
                    
        } catch (Exception ex) {
            System.out.println("Exception: " + ex);
        }
    }
    
    public void installPinAndConnect() throws Exception {
        final RunConfig runCfg = RunConfig.getDefaultConfig();
        runCfg.setAppletToSimulate(PV204Applet.class);
        runCfg.setTestCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL);
        
        byte[] installCommand = Util.hexStringToByteArray("0a" + APPLET_AID + "00" + PIN_LENGTH);
        byte[] pin = {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04};
        
        byte[] installData = Util.concat(installCommand, pin);
        runCfg.setInstallData(installData);
        
        System.out.print("Connecting to card...");
        if (!cardMngr.Connect(runCfg)) {
            System.out.println(" Failed.");
        }
        System.out.println(" Done.");
        
        pinSecret = pin;
    }
    
    public void startEcdhSession() throws Exception {

        KeyAgreement dh = KeyAgreement.getInstance("ECDH");
        
        //These are the bytes to send to card
        byte[] pcEcdhShare = prepareKeyPair(dh);
        
        //send PC ECDH share and receive card ECDH share
        byte[] cardEcdhShare = exchangeEcdhShares(pcEcdhShare);
        
        ECPublicKey cardPublicKey = extractCardPublicKey(cardEcdhShare);
        dh.doPhase(cardPublicKey, true);
        byte[] derivedSecret = dh.generateSecret();
        
        MessageDigest md = MessageDigest.getInstance("SHA");
        ecdhSecret = md.digest(derivedSecret);
        
        deriveSessionKey();
    }
    
    //derive session key from shared ECDH secret
    private void deriveSessionKey() {
        //TODO
    }
    
    //for debugging
    public void compareSecretWithCard() throws Exception {
        
        //get shared ECDH secret from card
        final ResponseAPDU response = cardMngr.transmit(new CommandAPDU(Util.hexStringToByteArray("B0600000")));
        byte[] cardEcdhSecret = response.getData();
        
        System.out.println("PC   ECDH secret: " + Util.bytesToHex(ecdhSecret));
        System.out.println("Card ECDH secret: " + Util.bytesToHex(cardEcdhSecret));
    }
    
    //for debugging
    public void comparePinWithCard() throws Exception {
        
        //get PIN from card
        final ResponseAPDU response = cardMngr.transmit(new CommandAPDU(Util.hexStringToByteArray("B0610000")));
        byte[] cardPin = response.getData();
        
        System.out.println("PC   PIN: " + Util.bytesToHex(pinSecret));
        System.out.println("Card PIN: " + Util.bytesToHex(cardPin));
    }
    
    public byte[] exchangeEcdhShares(byte[] pcEcdhShare) throws Exception {
        byte[] command = {(byte) 0xb0, (byte) 0x59, (byte) 0x00, (byte) 0x00,
                          (byte) pcEcdhShare.length};
        byte[] sendData = Util.concat(command, pcEcdhShare);
        
        final ResponseAPDU response = cardMngr.transmit(new CommandAPDU(sendData));
        return response.getData();
    }
    
    public byte[] prepareKeyPair(KeyAgreement dh) throws Exception {
        KeyPair keyPair = getRandomEcKeyPair();
        
        dh.init(keyPair.getPrivate());
        
        return encodeEcPublicKey((ECPublicKey) keyPair.getPublic());
    }
    
    public byte[] encodeEcPublicKey(ECPublicKey key) {
        ECPoint w = key.getW();
        byte[] affineX = w.getAffineX().toByteArray();
        byte[] affineY = w.getAffineY().toByteArray();
        int keyLen = 224/8 + 1;
        
        byte[] x962encoded = new byte[2 * keyLen + 1];
        x962encoded[0] = (byte) 0x04;
        System.arraycopy(affineX, 0, x962encoded, 1 + keyLen - affineX.length, affineX.length);
        System.arraycopy(affineY, 0, x962encoded, 1 + 2* keyLen - affineY.length, affineY.length);
        
        return x962encoded;
    }
    
    ECPublicKey extractCardPublicKey(byte[] cardEcdhShare) throws Exception {
        byte[] cardX = new byte[28];
        byte[] cardY = new byte[28];
        
        System.arraycopy(cardEcdhShare, 1, cardX, 0, 28);
        System.arraycopy(cardEcdhShare, 29, cardY, 0, 28);
        
        BigInteger x = new BigInteger(cardX);
        BigInteger y = new BigInteger(cardY);
        
        ECPoint ecPoint = new ECPoint (x,y);

        ECParameterSpec ecSpec = ((ECPublicKey) getRandomEcKeyPair().getPublic()).getParams();
        ECPublicKeySpec ecPkeySpec = new ECPublicKeySpec (ecPoint, ecSpec);
        
        return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(ecPkeySpec);
    }
    
    public KeyPair getRandomEcKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec ("secp224r1"));
        return keyGen.generateKeyPair();
    }
    
}
