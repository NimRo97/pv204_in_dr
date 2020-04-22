package pv204apdu;

import static pv204apdu.PV204Utils.*;

import applets.PV204Applet;
import cardTools.CardManager;
import cardTools.RunConfig;
import cardTools.Util;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.IvParameterSpec;
import java.util.Arrays;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 * 
 * @author Imrich Nagy
 * Based on work of Petr Svenda (petrs), Dusan Klinec (ph4r05)
 */
public class PV204APDU {
    
    // Constants
    private static final String APPLET_AID = "482871d58ab7465e5e05";
    private static final byte APPLET_AID_BYTE[] = Util.hexStringToByteArray(APPLET_AID);
    
    // PIN Constants
    private static final String PIN_LENGTH = "04";
    
    // Card
    private final CardManager cardMngr = new CardManager(true, APPLET_AID_BYTE);
    
    // Session attributes
    Cipher aes_encrypt = null;
    Cipher aes_decrypt = null;
    
    
    /**
     * Main program to showcase the implementation
     * 
     * @param args program takes no arguments
     */
    public static void main(String[] args) {
        try {
            PV204APDU main = new PV204APDU();
            
            System.out.println("Installing applet with PIN to card.");
            main.installPinAndConnect();
            int PINtries = 3;

            System.out.println("\nStarting new secure channel session.");
            while ( ! main.startEcdhSession(getUserPIN())) {
                PINtries -= 1;
                if (PINtries < 1) {
                    System.out.println("Card blocked! Aborting");
                    return;
                }
            }
            
            System.out.println("\nCommunicating with the card using secure channel.");
            System.out.println("Marco-Polo:");
            main.doMarcoPolo();
            
            String secretMessage = "J.E. did not commit suicide. " +
                                   "Also, the cake is a lie.";
            System.out.println("\nStoring '" + secretMessage + "' on card...");
            main.storeData(secretMessage.getBytes());
            
            System.out.println("\n...and receiving '" +
                               new String(main.loadData()) + "' back.");
            
            System.out.println("\nNow, Marco-Polo will be performed 17 times " +
                               "to exhaust the session message limit");
            for (int i = 0; i < 17; i++) {
                main.doMarcoPolo();
            }
            
            System.out.println("\nNow, the secret message will be read, " +
                               "but new session is required");
            System.out.println("\nReceived '" + new String(main.loadData()) + "'.");
            
            System.out.println("\nClosing channel.");
            main.closeEcdhSession();
            System.out.println("Channel closed.");
            
        } catch (Exception ex) {
            System.out.println("Exception: " + ex);
        }
    }
    
    /**
     * Installs applet with random PIN
     * @throws Exception 
     */
    public void installPinAndConnect() throws Exception {
        final RunConfig runCfg = RunConfig.getDefaultConfig();
        runCfg.setAppletToSimulate(PV204Applet.class);
        runCfg.setTestCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL);
        
        byte[] installCommand = Util.hexStringToByteArray("0a" + APPLET_AID + "00" + PIN_LENGTH);
        byte[] pin = generatePin();
        byte[] nullPin = {(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};

        while (Arrays.equals(pin, nullPin)) {
            pin = generatePin();
        }
        
        byte[] installData = Util.concat(installCommand, pin);
        runCfg.setInstallData(installData);
        
        System.out.print("Connecting to card...");
        if (!cardMngr.Connect(runCfg)) {
            System.out.println(" Failed.");
        }
        System.out.println(" Done.");
        printPin(pin);
    }
    
    /**
     * Wrapper method to create and send encrypted APDU using secure channel
     * and receive response from the card
     * 
     * @param data data to be sent to the card
     * @param instruction instruction byte for the card
     * @return data received from the card
     * @throws Exception 
     */
    public byte[] encryptAndSendAPDU(byte[] data, byte instruction) throws Exception {
        
        byte[] encrypted = aes_encrypt.doFinal(data);
        byte[] command = {(byte) 0xb0, instruction, (byte) 0x00, (byte) 0x00,
                          (byte) encrypted.length};
        byte[] sendData = Util.concat(command, encrypted);
        
        final ResponseAPDU response = cardMngr.transmit(new CommandAPDU(sendData));
        
        if (response.getSW() == 0x6901) {
            System.out.println("Session needs to be reestablished.");
            startEcdhSession(getUserPIN());
            
            return encryptAndSendAPDU(data, instruction);
        }
        
        return decryptData(response.getData());
    }
    
    /**
     * Decrypts data received using secure channel
     * 
     * @param encrypted encrypted data
     * @return decrypted data
     * @throws Exception 
     */
    private byte[] decryptData(byte[] encrypted) throws Exception {
        return aes_decrypt.doFinal(encrypted);
    }
    
    /**
     * Does Marco-Polo with the card
     * 
     * @throws Exception 
     */
    public void doMarcoPolo() throws Exception {
        byte[] marco = {0x6d, 0x61, 0x72, 0x63, 0x6f};
        byte[] response = encryptAndSendAPDU(marco, (byte) 0x70);
            
        System.out.println("Received '" + Util.bytesToHex(response) +
                           "', which is 'polo' in ASCII.");
    }
    
    /**
     * Performs sending of data securely to the card
     * 
     * @param data data to be stored
     * @throws Exception 
     */
    public void storeData(byte[] data) throws Exception {
        encryptAndSendAPDU(data, (byte) 0x71);
    }
    
    /**
     * Gets data previously stored on the card
     * 
     * @return the data previously stored on the card
     * @throws Exception 
     */
    public byte[] loadData() throws Exception {
        return encryptAndSendAPDU(new byte[0], (byte) 0x72);
    }
    
    public boolean startEcdhSession(byte[] pin) throws Exception {

        byte [] hashedPIN = new byte[16];
        hashedPIN = hashPIN(pin);


        KeyAgreement dh = KeyAgreement.getInstance("ECDH");
        
        //prepare arrays for shared keys
        byte[] pcEcdhShare = prepareKeyPair(dh);
        byte[] encPcEcdhShare = new byte[64];
        byte[] cardEcdhShare = new byte[57];
        byte[] encCardEcdhShare = new byte[64];
        
        
        //prompt card to start key exchange via PAKE protocol
        encCardEcdhShare = sendECDHInitCommand();
        cardEcdhShare = decDataByHashPIN(encCardEcdhShare, hashedPIN);

        ECPublicKey cardPublicKey = extractCardPublicKey(cardEcdhShare);

        dh.doPhase(cardPublicKey, true);
        byte[] derivedSecret = dh.generateSecret();
        MessageDigest md = MessageDigest.getInstance("SHA");
        byte[] ecdhSecret = md.digest(derivedSecret);

        deriveSessionKey(ecdhSecret);
        
        //create chalenge
        SecureRandom random = new SecureRandom();
        byte[] challenge = new byte[31];
        byte[] encChallenge;
        random.nextBytes(challenge);
        encChallenge = aes_encrypt.doFinal(challenge);
        
        byte[] cardChallengeMix = sendECDHChallenge(pcEcdhShare, encChallenge, hashedPIN);
        byte[] authResponse = authCard(challenge, cardChallengeMix);
        
        if (authResponse[0] == (byte) 01)
            System.out.println("Authentication was successful!");
        else
            System.out.println("Authentication FAILED!");
                    // TODO: auth failure
        return true;
        
    }
    
    public void closeEcdhSession() throws Exception {
        byte[] sendData = Util.hexStringToByteArray("b065000000");
        final ResponseAPDU response = cardMngr.transmit(new CommandAPDU(sendData));
    }
    
    /**
     * Derives session key from shared ECDH secret
     * 
     * @param ecdhSecret shared ECDH secret
     * @throws Exception 
     */
    private void deriveSessionKey(byte[] ecdhSecret) throws Exception {
        
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] derived = md.digest(ecdhSecret);
        
        SecretKeySpec aesKeySpecEnc = new SecretKeySpec(derived, 0, 16, "AES");
        IvParameterSpec ivSpecEnc = new IvParameterSpec(derived, 16, 16);
        
        SecretKeySpec aesKeySpecDec = new SecretKeySpec(derived, 16, 16, "AES");
        IvParameterSpec ivSpecDec = new IvParameterSpec(derived, 0, 16);
        
        aes_encrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aes_encrypt.init(Cipher.ENCRYPT_MODE, aesKeySpecEnc, ivSpecEnc);
        
        aes_decrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aes_decrypt.init(Cipher.DECRYPT_MODE, aesKeySpecDec, ivSpecDec);
    }
    
    private byte[] authCard(byte[] challenge, byte[] cardChallengeMix) throws Exception {
        byte[] decMix = aes_decrypt.doFinal(cardChallengeMix);
        byte[] incChallenge = new byte[31];
        System.arraycopy(decMix, (short) 0, incChallenge, (short) 0, (short) 31);
        byte[] challengeAns = new byte[31];
        System.arraycopy(decMix, (short) 31, challengeAns, (short) 0, (short) 31);
        
        if (! Arrays.equals(challengeAns, challenge) ) {
            System.out.println("Auth of card failed on PC!");
            // TODO: auth failure
        }

        byte[] encPayload = aes_encrypt.doFinal(incChallenge);
        byte[] command = {(byte) 0xb0, (byte) 0x64, (byte) 0x00, (byte) 0x00, (byte) encPayload.length};
        byte[] sendData = Util.concat(command, encPayload);


        final ResponseAPDU response = cardMngr.transmit(new CommandAPDU(sendData));
        return response.getData();
        
    }
    
    private byte[] sendECDHInitCommand() throws Exception {
        byte[] command = {(byte) 0xb0, (byte) 0x62, (byte) 0x00, (byte) 0x00};
        
        final ResponseAPDU response = cardMngr.transmit(new CommandAPDU(command));
        return response.getData();
    }
    
    private byte[] sendECDHChallenge(byte[] pcEcdhShare, byte[] encChallenge, byte[] hashedPIN) throws Exception {
        byte[] payload = Util.concat(pcEcdhShare, encChallenge);
        byte[] encPayload = encDataByHashPIN(payload, hashedPIN);
        byte[] command = {(byte) 0xb0, (byte) 0x63, (byte) 0x00, (byte) 0x00, (byte) encPayload.length};

        byte[] sendData = Util.concat(command, encPayload);
        
        final ResponseAPDU response = cardMngr.transmit(new CommandAPDU(sendData));
        return response.getData();
    }
    
    private byte[] prepareKeyPair(KeyAgreement dh) throws Exception {
        KeyPair keyPair = getRandomEcKeyPair();
        
        dh.init(keyPair.getPrivate());
        
        return encodeEcPublicKey((ECPublicKey) keyPair.getPublic());
    }
    
    private byte[] hashPIN(byte[] pin) throws Exception {
        
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] key = md.digest(pin);
        return Arrays.copyOf(key, 16);
    }
    
    private byte[] encDataByHashPIN(byte[] data, byte[] key) throws Exception {

        SecretKeySpec aesKey = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(new byte[16]));
        
        return cipher.doFinal(data);
    }
    private byte[] decDataByHashPIN(byte[] data, byte[] PINkey) throws Exception {

        SecretKeySpec AESKey = new SecretKeySpec(PINkey, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        cipher.init(Cipher.DECRYPT_MODE, AESKey, new IvParameterSpec(new byte[16]));
        return cipher.doFinal(data);

    }
    private void abort_PIN(int PINtries) throws Exception {
        PINtries -= 1;
        if (PINtries < 1) {
            System.out.println("Card is blocked!");
            closeEcdhSession();
        }
        else
        System.out.format("Aborting: incorrect PIN\n%d tries remaining", PINtries);
    }
}
