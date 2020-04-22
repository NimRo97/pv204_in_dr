/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pv204apdu;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;

/**
 *
 * @author NimRo97
 */
public class PV204Utils {
    
    public static final int PIN_DIGITS = 4;
    
    /**
     * Prints PIN to user
     * @param pin PIN
     */
    public static void printPin(byte[] pin) {
        System.out.print("User PIN: ");
        for (int i = 0; i < PIN_DIGITS; i++) {
            System.out.print((char) ('0' + pin[i]));
        }
        System.out.println("");
    }
    
    /**
     * Generates random PIN
     * @return PIN array
     */
    public static byte[] generatePin() {
        byte[] pin = new byte[PIN_DIGITS];
        SecureRandom rng = new SecureRandom();
        rng.nextBytes(pin);
        
        for (int i = 0; i < PIN_DIGITS; i++) {
            pin[i] %= (byte) 10;
            if (pin[i] < 0) {
                pin[i] += 10;
            }
        }
                
        return pin;
    }
    
    /**
     * Gets PIN from user
     * @return PIN array
     * @throws IOException in case of IO failure
     */
    public static byte[] getUserPIN() throws IOException {
        
        System.in.read(new byte[System.in.available()]);
        
        byte[] pin = new byte[PIN_DIGITS];
        System.out.print("Please enter " + PIN_DIGITS + "-digit PIN: ");
        
        try {
            System.in.read(pin, 0, PIN_DIGITS);
        } catch (IOException e) {
            System.out.println("Error reading PIN.");
            throw e;
        }
        
        for (int i = 0; i < PIN_DIGITS; i++) {
            pin[i] -= '0';
            if (pin[i] < 0 || pin[i] > 9) {
                System.out.println("PIN contains invalid character.");
                return getUserPIN();
            }
        }
        
        return pin;
    }
    
    /**
     * Encodes EC public key in ANSI X9.62 format
     * 
     * @param key EC public key
     * @return ANSI X9.62 encoding of the provided key
     */
    public static byte[] encodeEcPublicKey(ECPublicKey key) {
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
    
    /**
     * Creates EC public key from ANSI X9.62 encoded representation
     * 
     * @param cardEcdhShare ANSI X9.62 encoded public key
     * @return EC public key
     * @throws Exception 
     */
    public static ECPublicKey extractCardPublicKey(byte[] cardEcdhShare) throws Exception {
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
    
    /**
     * Generates and returns random EC keypair
     * 
     * @return random EC keypair
     * @throws Exception 
     */
    public static KeyPair getRandomEcKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec ("secp224r1"));
        return keyGen.generateKeyPair();
    }
}
