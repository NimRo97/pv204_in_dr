package applets;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class PV204Applet extends javacard.framework.Applet {

    // Main instruction class
    final static byte CLA_PV204_APPLET = (byte) 0xB0;

    // Session control nstructions
    final static byte INS_ECDHINIT = (byte) 0x62;
    final static byte INS_SOLVE_CHALLENGE = (byte) 0x63;
    final static byte INS_AUTH_PC = (byte) 0x64;
    final static byte INS_CLOSE_CHANNEL = (byte) 0x65;
    
    // Instruction over secure channel
    final static byte INS_MARCO = (byte) 0x70;
    final static byte INS_STORE = (byte) 0x71;
    final static byte INS_LOAD  = (byte) 0x72;

    // Constants
    final static byte AES_BLOCK_LENGTH = (short) 0x16;
    final static short ARRAY_LENGTH = (short) AES_BLOCK_LENGTH * 2;
    final static short PIN_LENGTH = (short) 4;

    // Error codes
    final static short SW_BAD_PIN = (short) 0x6900;
    final static short SW_NEW_SESSION_REQUIRED = (short) 0x6901;
    final static short SW_CARD_BLOCKED = (short) 0x6902;
    
    // Attributes
    private byte[] m_pin_data = new byte[PIN_LENGTH];
    private OwnerPIN m_pin = null;
    private byte[] nullPin = null;
    private byte[] hashedPIN = new byte[16];
    private byte[] challenge = new byte[31];
    private short statusVar;

    private AESKey m_aes_key = null;
    private Cipher m_aes_encrypt = null;
    private Cipher m_aes_decrypt = null;
    
    private MessageDigest m_hash = null;
    private KeyAgreement dh = null;

    // Transient array for session key
    private byte m_ramArray[] = null;
    
    // Transient session message counter
    private byte m_sessionCounter[] = null;
    
    // Local storage
    private byte m_data[] = null;
    
    /**
     * Method for installing the applet.
     *
     * @param buffer input buffer
     * @param offset the starting offset in the buffer
     * @param length the length in bytes of the data parameter in buffer
     */
    public static void install(byte[] buffer, short offset, byte length) throws ISOException {
        // applet  instance creation
        new PV204Applet(buffer, offset, length);
    }

    /**
     * Default constructor
     * @param buffer input buffer
     * @param offset the starting offset in the buffer
     * @param length the length in bytes of the data parameter in buffer
     * @throws ISOException 
     */
    protected PV204Applet(byte[] buffer, short offset, byte length) throws ISOException {
        
        short dataOffset = offset;
        
        // shift to privilege offset
        dataOffset += (short) (1 + buffer[offset]);
        // finally shift to Application specific offset
        dataOffset += (short) (1 + buffer[dataOffset]);

        // Transient session information to clear in case of power reset
        m_ramArray = JCSystem.makeTransientByteArray(ARRAY_LENGTH, JCSystem.CLEAR_ON_RESET);
        m_sessionCounter = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_RESET);
        m_sessionCounter[0] = (byte) 0;
               
        // copy PIN
        Util.arrayCopyNonAtomic(buffer, (byte) (dataOffset + 1), m_pin_data, (short)0 , PIN_LENGTH);
        m_pin = new OwnerPIN((byte) 3, (byte) PIN_LENGTH); // 3 tries, 4 digits in pin
        if (buffer[dataOffset] != (byte) PIN_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        m_pin.update(buffer, (byte) (dataOffset + 1), (byte) PIN_LENGTH);

        m_aes_key = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        
        m_aes_encrypt = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        m_aes_decrypt = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        
        m_hash = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        hashedPIN = hashPIN(m_pin_data);
        nullPin = new byte[] {(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};
        statusVar = 0;

                
        // register this instance
        register();
    }


    /**
     * Select method returns true if applet selection is supported.
     *
     * @return boolean status of selection.
     */
    @Override
    public boolean select() {
        clearSessionData();
        
        return true;
    }

    /**
     * Deselect method called by the system in the deselection process.
     */
    @Override
    public void deselect() {
        clearSessionData();
    }

    /**
     * Process an incoming APDU.
     *
     * @param apdu incoming APDU
     * @exception ISOException with the response bytes defined by ISO 7816-4
     */
    @Override
    public void process(APDU apdu) throws ISOException {
        // check for blocked card
        
            
        // get the buffer with incoming APDU
        byte[] apduBuffer = apdu.getBuffer();

        // ignore the applet select command dispached to the process
        if (selectingApplet()) {
            return;
        }

        try {
            // APDU instruction parser
            if (apduBuffer[ISO7816.OFFSET_CLA] == CLA_PV204_APPLET) {
                if (m_pin.getTriesRemaining() < (byte) 0x01)
                    cardBlocked(apdu);
                switch (apduBuffer[ISO7816.OFFSET_INS]) {
                    
                    case INS_ECDHINIT:
                        m_pin.check(nullPin, (short) 0, (byte) PIN_LENGTH);
                        dh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
                        ECDHInit(apdu, dh);
                        statusVar = 15;
                        break;
                    case INS_SOLVE_CHALLENGE:
                        if (statusVar != 15)
                            break;
                        ECDHSolveChallenge(apdu, dh);
                        statusVar = 240;
                        break;
                    case INS_AUTH_PC:
                        if (statusVar != 240)
                            break;
                        if (ECDHAuthPC(apdu, challenge)) {
                            m_sessionCounter[0] = (byte) 20; //allow secure communication
                            m_pin.reset();
                        }
                            
                        statusVar = 0;
                        break;
                    case INS_CLOSE_CHANNEL:
                        closeSecureChannel(apdu);
                        break;
                        
                    default:
                        processSecuredAPDU(apdu);
                        break;
                }
            } else {
                ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
            }
            
        } catch(ISOException e) {
            ISOException.throwIt(e.getReason());
        } catch (Exception e) {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
    }
    
    /**
     * Closes secure channel on explicit command from the PC
     * 
     * @param apdu incoming APDU
     */
    private void closeSecureChannel(APDU apdu) {
        clearSessionData();
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) 0);
    }
    
    /**
     * Wrapper to implement secure channel
     * All methods for processing instructions receive
     * length of the incoming data
     * and return the length of the outgoing data,
     * both in unencrypted form
     * 
     * @param apdu incoming APDU
     * @throws ISOException 
     */
    private void processSecuredAPDU(APDU apdu) throws ISOException {
        
        if (m_sessionCounter == null ||
            m_sessionCounter[0] <= 0 || m_sessionCounter[0] > 20) {
            ISOException.throwIt(SW_NEW_SESSION_REQUIRED);
        }
        m_sessionCounter[0]--;
        
        short dataLen = decryptAPDU(apdu);
        byte[] apduBuffer = apdu.getBuffer();
        
        try {
            // APDU instruction parser
            if (apduBuffer[ISO7816.OFFSET_CLA] == CLA_PV204_APPLET) {
                switch (apduBuffer[ISO7816.OFFSET_INS]) {
                    case INS_MARCO:
                        dataLen = marcoPolo(apdu, dataLen);
                        break;
                    case INS_STORE:
                        dataLen = storeData(apdu, dataLen);
                        break;
                    case INS_LOAD:
                        dataLen = loadData(apdu, dataLen);
                        break;
                    default:
                        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                        break;
                }
            } else {
                ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
            }
            
        } catch (ISOException e) {
            ISOException.throwIt(e.getReason());
        }
        
        if (dataLen >= 0) {
            encryptAndSendAPDU(apdu, dataLen);
        }
    }
    
    /**
     * Decrypts contents of the incoming APDU
     * 
     * @param apdu incoming APDU
     * @return the length of the decrypted data
     * @throws ISOException 
     */
    private short decryptAPDU(APDU apdu) throws ISOException {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();
        if (dataLen % 16 != 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH); 
        }
        m_aes_decrypt.doFinal(apdubuf, ISO7816.OFFSET_CDATA, dataLen, apdubuf, ISO7816.OFFSET_CDATA);
        
        return (short) (dataLen - apdubuf[dataLen - 1]);
    }
    
    /**
     * Encrypts contents of the outgoing APDU
     * 
     * @param apdu outgoing APDU
     * @param dataLen length of the unencrypted APDU data
     * @return the length of the encrypted outgoing data
     * @throws ISOException 
     */
    private void encryptAndSendAPDU(APDU apdu, short dataLen) throws ISOException {
        byte[] apdubuf = apdu.getBuffer();
         
        // PKCS#5 padding requires additional block if length % 16 == 0
        short nearest = (short) (dataLen + 16 - (dataLen % 16));
        Util.arrayFillNonAtomic(apdubuf, (short) (ISO7816.OFFSET_CDATA + dataLen),
        (short) (nearest - dataLen), (byte) (16 - dataLen % 16));
        
        m_aes_encrypt.doFinal(apdubuf, ISO7816.OFFSET_CDATA, nearest, apdubuf, ISO7816.OFFSET_CDATA);
        
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, nearest);
    }
    
    /**
     * Test method that receive "marco" and returns "polo"
     * 
     * @param apdu incoming decrypted APDU
     * @param dataLen length of the decrypted incoming data
     * @return length of the unencrypted outgoing data
     * @throws ISOException in case of wrong incoming data
     */
    private short marcoPolo(APDU apdu, short dataLen) throws ISOException {
        
        if (dataLen != 5) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        
        byte[] apdubuf = apdu.getBuffer();
        byte[] marco = new byte[] {0x6d, 0x61, 0x72, 0x63, 0x6f};
        byte[] polo = new byte[] {0x70, 0x6f, 0x6c, 0x6f};
        
        if (Util.arrayCompare(apdubuf, ISO7816.OFFSET_CDATA, marco, (short) 0, (short) 5) != 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        Util.arrayCopyNonAtomic(polo, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, (short) polo.length);
        
        return (short) polo.length;
    }
    
    /**
     * Stores data on the card. Unencrypted, just for demo purposes.
     * 
     * @param apdu incoming decrypted APDU
     * @param dataLen length of the decrypted incoming data
     * @return 0 to respond with no data
     * @throws ISOException 
     */
    private short storeData(APDU apdu, short dataLen) throws ISOException {
        
        byte[] apdubuf = apdu.getBuffer();
        
        m_data = new byte[dataLen];
        Util.arrayCopyNonAtomic(apdubuf, ISO7816.OFFSET_CDATA, m_data, (short) 0, dataLen);
        
        return 0;
    }
    
    /**
     * 
     * @param apdu incoming decrypted APDU
     * @param dataLen length of the decrypted incoming data, should be zero
     * @return length of the unencrypted outgoing data
     * @throws ISOException 
     */
    private short loadData(APDU apdu, short dataLen) throws ISOException {
        
        if (dataLen != 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        
        byte[] apdubuf = apdu.getBuffer();
        
        Util.arrayCopyNonAtomic(m_data, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, (short) m_data.length);
        
        return (short) m_data.length;
    }

    /**
     * Clears temporal shared secret and resets session counter
     */
    private void clearSessionData() {
        
        // Zero out the RAM array
        Util.arrayFillNonAtomic(m_ramArray, (short) 0, (short) m_ramArray.length, (byte) 0);
        
        // Reset session counter
        m_sessionCounter[0] = (byte) 0;
        
        // Clear AES session key
        m_aes_key.clearKey();
    }
    
    private void ECDHInit(APDU apdu, KeyAgreement dh) throws ISOException, CryptoException {

        byte[] apdubuf = apdu.getBuffer();
        apdu.setIncomingAndReceive();

        KeyPair m_ECDH_keyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_224);
        m_ECDH_keyPair.genKeyPair();
        
        dh.init(m_ECDH_keyPair.getPrivate());

        //bytes to send to PC
        byte[] card_ecdh_share = new byte[57];
        short len = ((ECPublicKey) m_ECDH_keyPair.getPublic()).getW(card_ecdh_share, (short) 0);
 
        byte[] enc_card_ecdh_share = new byte[64]; // aes output size
        enc_card_ecdh_share = encDataByHashPIN(card_ecdh_share, hashedPIN, (short) 57);

        Util.arrayCopy(enc_card_ecdh_share, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, (short) 64);

        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) (64));
    }
    
    private void ECDHSolveChallenge(APDU apdu, KeyAgreement dh) throws Exception {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();
        
        byte[] recData = new byte[dataLen];
        Util.arrayCopy(apdubuf, ISO7816.OFFSET_CDATA, recData, (short) 0, dataLen);

        byte[] decryptedData;
        byte[] pc_ecdh_share = new byte[59];
        byte[] ecdh_secret = new byte[20];
        byte[] encPcChallenge = new byte[32];
        byte [] pcChallenge = new byte[32];
        byte[] sendData = new byte[64];
        
        RandomData random = RandomData.getInstance(RandomData.ALG_TRNG);
        
        // there is a chance of failing when pin is incorrect
        try {
            decryptedData = decDataByHashPIN(recData, hashedPIN, (short) recData.length);
            Util.arrayCopy(decryptedData, (short) 0, pc_ecdh_share, (short) 0, (short) 59);
        
            dh.generateSecret(pc_ecdh_share, (short) 0, (short) pc_ecdh_share.length, ecdh_secret, (byte) 0);
            deriveSessionKey(ecdh_secret);
        
            Util.arrayCopy(decryptedData, (short) 59, encPcChallenge, (short) 0, (short) 32);

        }
        catch(Exception e) {
            wrongPIN(apdu, apdubuf);
            return;
        }
      
        m_aes_decrypt.doFinal(encPcChallenge, (short) 0, (short) 32, pcChallenge, (short) 0);
        
        random.nextBytes(challenge, (short) 0, (short) 31);
        
        Util.arrayCopy(challenge, (short) 0, sendData, (short) 0, (short) 31);
        Util.arrayCopy(pcChallenge, (short) 0, sendData, (short) 31, (short) 31);
        sendData[63] = (byte) 02; // pkcs5 padding
        sendData[62] = (byte) 02; // pkcs5 padding
        m_aes_encrypt.doFinal(sendData, (short) 0, (short) 64, sendData, (short) 0);
        
        Util.arrayCopy(sendData, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, (short) 64);
        
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) (64));
    }
    
    private boolean ECDHAuthPC(APDU apdu, byte[] challenge) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();
        
        byte[] recData = new byte[dataLen];
        Util.arrayCopy(apdubuf, ISO7816.OFFSET_CDATA, recData, (short) 0, dataLen);
        
        byte[] solvedChallenge = new byte[32];
        try {
            m_aes_decrypt.doFinal(recData, (short) 0, (short) 32, solvedChallenge, (short) 0);
        }
        catch (Exception e){
            wrongPIN(apdu, apdubuf);
            return false;
        }
        
        if (Util.arrayCompare(challenge, (short) 0, solvedChallenge, (short) 0, (short) 31) == 0) {
            apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) (0));   
            return true;
        }
        else {
            wrongPIN(apdu, apdubuf);
            return false;
        }  
    }
    
    /**
     * Derives session keys from shared ECDH secret
     * 
     * @param ecdh_secret shared ECDH secret
     */
    private void deriveSessionKey(byte[] ecdh_secret) {
        
        m_hash.doFinal(ecdh_secret, (short) 0, (short) ecdh_secret.length, m_ramArray, (short) 0);
        
        m_aes_key.setKey(m_ramArray, (short) 16);
        m_aes_encrypt.init(m_aes_key, Cipher.MODE_ENCRYPT, m_ramArray, (short) 0, (short) 16);
        
        m_aes_key.setKey(m_ramArray, (short) 0);
        m_aes_decrypt.init(m_aes_key, Cipher.MODE_DECRYPT, m_ramArray, (short) 16, (short) 16);
        
        
    }
    
    private byte[] hashPIN(byte[] pin) throws ISOException {
        
        MessageDigest md = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
        byte[] hashed = new byte[20];
        byte[] PINsecret = new byte[16];
        md.doFinal(pin, (short) 0, (short) 4, hashed, (short) 0);
        Util.arrayCopy(hashed, (short) 0, PINsecret, (short) 0, (short) 16);
        return PINsecret;

    }
    
    private byte[] encDataByHashPIN(byte[] data, byte[] key, short dataLen) throws ISOException, CryptoException {

        AESKey aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        aesKey.setKey(key, (short) 0);
        
        byte[] aesICV = new byte[16];
        
        byte[] paddedData = new byte[64];
        short nearest = (short) (dataLen + 16 - (dataLen % 16));
        Util.arrayCopy(data, (short) 0, paddedData, (short) 0, dataLen);
        Util.arrayFillNonAtomic(paddedData, (short) dataLen,
        (short) (nearest - dataLen), (byte) (16 - dataLen % 16));

        Cipher ciph = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        ciph.init(aesKey, Cipher.MODE_ENCRYPT, aesICV, (short) 0, (short) 16);
        ciph.doFinal(paddedData, (short) 0, nearest, paddedData, (short) 0);

        return paddedData;
    }
    
    private byte[] decDataByHashPIN(byte[] data, byte[] key, short dataLength) throws ISOException, CryptoException {
        AESKey aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        aesKey.setKey(key, (short) 0);
        
        byte[] aesICV = new byte[16];
        
        Cipher cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        cipher.init(aesKey, Cipher.MODE_DECRYPT, aesICV, (short) 0, (short) 16);
        
        byte[] decrypted = new byte[96];
        cipher.doFinal(data, (short) 0, dataLength, decrypted, (short) 0);
        return decrypted;
    }
    
    private void cardBlocked(APDU apdu) {
        ISOException.throwIt(SW_CARD_BLOCKED);    
    }
    private void wrongPIN(APDU apdu, byte[] apdubuf) {
        ISOException.throwIt(SW_BAD_PIN);
    }
}
