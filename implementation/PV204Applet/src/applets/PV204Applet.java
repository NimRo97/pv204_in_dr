package applets;

import java.util.Arrays;
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class PV204Applet extends javacard.framework.Applet {

    // MAIN INSTRUCTION CLASS
    final static byte CLA_PV204APPLET = (byte) 0xB0;

    // INSTRUCTIONS
    final static byte INS_ECDHINIT_OLD = (byte) 0x59; // deprected
    final static byte INS_GETSECRET = (byte) 0x60;
    final static byte INS_GETPIN = (byte) 0x61;
    
    final static byte INS_MARCO = (byte) 0x70;
    final static byte INS_ECDHINIT = (byte) 0x62;
    final static byte INS_SOLVE_CHALLENGE = (byte) 0x63;
    final static byte INS_AUTH_PC = (byte) 0x64;


    final static short ARRAY_LENGTH = (short) 0xff;
    final static byte AES_BLOCK_LENGTH = (short) 0x16;

    final static short SW_BAD_TEST_DATA_LEN = (short) 0x6680;
    final static short SW_KEY_LENGTH_BAD = (short) 0x6715;
    final static short SW_CIPHER_DATA_LENGTH_BAD = (short) 0x6710;
    final static short SW_OBJECT_NOT_AVAILABLE = (short) 0x6711;
    final static short SW_BAD_PIN = (short) 0x6900;

    final static short SW_Exception = (short) 0xff01;
    final static short SW_ArrayIndexOutOfBoundsException = (short) 0xff02;
    final static short SW_ArithmeticException = (short) 0xff03;
    final static short SW_ArrayStoreException = (short) 0xff04;
    final static short SW_NullPointerException = (short) 0xff05;
    final static short SW_NegativeArraySizeException = (short) 0xff06;
    final static short SW_CryptoException_prefix = (short) 0xf100;
    final static short SW_SystemException_prefix = (short) 0xf200;
    final static short SW_PINException_prefix = (short) 0xf300;
    final static short SW_TransactionException_prefix = (short) 0xf400;
    final static short SW_CardRuntimeException_prefix = (short) 0xf500;
    
    final static short PIN_LENGTH = (short) 4;
    /**
     * Method installing the applet.
     *
     * @param bArray the array containing installation parameters
     * @param bOffset the starting offset in bArray
     * @param bLength the length in bytes of the data parameter in bArray
     * @throws java.lang.Exception
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
        // applet  instance creation
        new PV204Applet(bArray, bOffset, bLength);
    }

    private RandomData m_secureRandom = null;
    private byte[] m_pin_data = new byte[PIN_LENGTH];
    private OwnerPIN m_pin = null;
    private byte[] hashedPIN = new byte[16];
    private byte[] challenge = new byte[31];

    private byte m_ecdh_secret[] = null;
    private AESKey m_aes_key = null;
    private Cipher m_aes_encrypt = null;
    private Cipher m_aes_decrypt = null;
    
    private MessageDigest m_hash = null;
    private KeyAgreement dh = null;

    // TEMPORARRY ARRAY IN RAM
    private byte m_ramArray[] = null;
    // PERSISTENT ARRAY IN EEPROM
    private byte m_dataArray[] = null;

    /**
     * PV204Applet default constructor Only this class's install method should
     * create the applet object.
     */
    protected PV204Applet(byte[] buffer, short offset, byte length) throws ISOException {
        // data offset is used for application specific parameter.
        // initialization with default offset (AID offset).
        
        short dataOffset = offset;
        // Install parameter detail. Compliant with OP 2.0.1.

        // | size | content
        // |------|---------------------------
        // |  1   | [AID_Length]
        // | 5-16 | [AID_Bytes]
        // |  1   | [Privilege_Length]
        // | 1-n  | [Privilege_Bytes] (normally 1Byte)
        // |  1   | [Application_Proprietary_Length]
        // | 0-m  | [Application_Proprietary_Bytes]
        // shift to privilege offset
        dataOffset += (short) (1 + buffer[offset]);
        // finally shift to Application specific offset
        dataOffset += (short) (1 + buffer[dataOffset]);

        m_dataArray = new byte[ARRAY_LENGTH];
        Util.arrayFillNonAtomic(m_dataArray, (short) 0, ARRAY_LENGTH, (byte) 0);

        // CREATE RANDOM DATA GENERATORS
        m_secureRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        //m_secureRandom.generateData(m_dataArray, (short) 0, (short) 32);
        
        System.out.println(" Initializing...");

        // TEMPORARY BUFFER USED FOR FAST OPERATION WITH MEMORY LOCATED IN RAM
        m_ramArray = JCSystem.makeTransientByteArray((short) 260, JCSystem.CLEAR_ON_DESELECT);
        
        //copy PIN
        Util.arrayCopy(buffer, (byte) (dataOffset + 1), m_pin_data, (short)0 , PIN_LENGTH);
        m_pin = new OwnerPIN((byte) 3, (byte) PIN_LENGTH); // 5 tries, 4 digits in pin
        if (buffer[dataOffset] != (byte) PIN_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        m_pin.update(buffer, (byte) (dataOffset + 1), (byte) PIN_LENGTH); // set initial random pin*/

        m_aes_key = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        m_aes_key.setKey(m_dataArray, (short) 0);
        m_aes_encrypt = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        m_aes_decrypt = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        
        //jcardsim does not support the padding
        //m_aes_encrypt = Cipher.getInstance(Cipher.ALG_AES_CBC_PKCS5, false);
        //m_aes_decrypt = Cipher.getInstance(Cipher.ALG_AES_CBC_PKCS5, false);
        
        m_hash = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        hashedPIN = hashPIN(m_pin_data);
        
                
        // register this instance
        register();
    }


    /**
     * Select method returns true if applet selection is supported.
     *
     * @return boolean status of selection.
     */
    public boolean select() {
        clearSessionData();
        
        return true;
    }

    /**
     * Deselect method called by the system in the deselection process.
     */
    public void deselect() {
        clearSessionData();
    }

    /**
     * Method processing an incoming APDU.
     *
     * @see APDU
     * @param apdu the incoming APDU
     * @exception ISOException with the response bytes defined by ISO 7816-4
     */
    public void process(APDU apdu) throws ISOException {
        // get the buffer with incoming APDU
        byte[] apduBuffer = apdu.getBuffer();

        // ignore the applet select command dispached to the process
        if (selectingApplet()) {
            return;
        }

        try {
            // APDU instruction parser
            if (apduBuffer[ISO7816.OFFSET_CLA] == CLA_PV204APPLET) {
                switch (apduBuffer[ISO7816.OFFSET_INS]) {
                    case INS_ECDHINIT_OLD:
                        ECDHInit_old(apdu);
                        deriveSessionKey();
                        break;
                    case INS_GETSECRET:
                        getEcdhSecret(apdu);
                        break;
                    case INS_GETPIN:
                        getPin(apdu);
                        break;
                    case INS_ECDHINIT:
                        dh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
                        ECDHInit(apdu, dh);
                        break;
                    case INS_SOLVE_CHALLENGE:
                        ECDHSolveChallenge(apdu, dh);
                        break;
                    case INS_AUTH_PC:
                        ECDHAuthPC(apdu, challenge);
                        break;
                        
                        
                    default:
                        processSecuredAPDU(apdu);
                        break;
                }
            } else {
                ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
            }
            
        } catch (Exception e) {
            ISOException.throwIt(SW_Exception);
        }
    }
    
    public void processSecuredAPDU(APDU apdu) throws ISOException {
        
        decryptAPDU(apdu);
        byte[] apduBuffer = apdu.getBuffer();
        boolean apduToSend = false;
        short dataLen = 0;
        
        try {
            // APDU instruction parser
            if (apduBuffer[ISO7816.OFFSET_CLA] == CLA_PV204APPLET) {
                switch (apduBuffer[ISO7816.OFFSET_INS]) {
                    case INS_MARCO:
                        dataLen = marcoPolo(apdu);
                        apduToSend = true;
                        break;
                    default:
                        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                        break;
                }
            } else {
                ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
            }
            
        } catch (Exception e) {
            ISOException.throwIt(SW_Exception);
        }
        
        if (apduToSend) {
            encryptAndSendAPDU(apdu, dataLen);
        }
    }
    
    public void decryptAPDU(APDU apdu) throws ISOException {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();
        if (dataLen % 16 != 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH); 
        }
        m_aes_decrypt.doFinal(apdubuf, ISO7816.OFFSET_CDATA, dataLen, apdubuf, ISO7816.OFFSET_CDATA);
    }
    
    public void encryptAndSendAPDU(APDU apdu, short dataLen) throws ISOException {
        byte[] apdubuf = apdu.getBuffer();
         
        //PKCS#5 padding requires additional block if length % 16 == 0
        short nearest = (short) (dataLen + 16 - (dataLen % 16));
        Util.arrayFillNonAtomic(apdubuf, (short) (ISO7816.OFFSET_CDATA + dataLen),
        (short) (nearest - dataLen), (byte) (16 - dataLen % 16));
        
        m_aes_encrypt.doFinal(apdubuf, ISO7816.OFFSET_CDATA, nearest, apdubuf, ISO7816.OFFSET_CDATA);
        
        
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, nearest);
    }
    
    short marcoPolo(APDU apdu) throws ISOException {
        byte[] apdubuf = apdu.getBuffer();
        byte[] marco = new byte[] {0x6d, 0x61, 0x72, 0x63, 0x6f};
        byte[] polo = new byte[] {0x70, 0x6f, 0x6c, 0x6f};
        
        if (Util.arrayCompare(apdubuf, ISO7816.OFFSET_CDATA, marco, (short) 0, (short) 5) != 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        Util.arrayCopy(polo, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, (short) polo.length);
        
        return (short) polo.length;
    }

    void clearSessionData() {
        // E.g., fill sesssion data in RAM with zeroes
        Util.arrayFillNonAtomic(m_ramArray, (short) 0, (short) m_ramArray.length, (byte) 0);
        // Or better fill with random data
        m_secureRandom.generateData(m_ramArray, (short) 0, (short) m_ramArray.length);
    }
    
    void ECDHInit_old(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();
        
        //bytes received from PC
        byte[] pc_ecdh_share = new byte[dataLen];
        Util.arrayCopy(apdubuf, ISO7816.OFFSET_CDATA, pc_ecdh_share, (short) 0, dataLen);
        
        KeyPair m_ECDH_keyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_224);
        m_ECDH_keyPair.genKeyPair();
        
        KeyAgreement dh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
        dh.init(m_ECDH_keyPair.getPrivate());
        
        m_ecdh_secret = new byte[20];
        dh.generateSecret(pc_ecdh_share, (short) 0, (short) pc_ecdh_share.length, m_ecdh_secret, (byte) 0);
        
        //bytes to send to PC
        byte[] card_ecdh_share = new byte[57];
        short len = ((ECPublicKey) m_ECDH_keyPair.getPublic()).getW(card_ecdh_share, (short) 0);
        
        Util.arrayCopy(card_ecdh_share, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, (short) 57);
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) (len));
    }
    
    void ECDHInit(APDU apdu, KeyAgreement dh) throws ISOException, CryptoException {

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
    
    void ECDHSolveChallenge(APDU apdu, KeyAgreement dh) throws Exception {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();
        
        byte[] recData = new byte[dataLen];
        Util.arrayCopy(apdubuf, ISO7816.OFFSET_CDATA, recData, (short) 0, dataLen);

        byte[] decryptedData = decDataByHashPIN(recData, hashedPIN, (short) recData.length);
        byte[] pc_ecdh_share = new byte[59];
        Util.arrayCopy(decryptedData, (short) 0, pc_ecdh_share, (short) 0, (short) 59);
        m_ecdh_secret = new byte[20];
        dh.generateSecret(pc_ecdh_share, (short) 0, (short) pc_ecdh_share.length, m_ecdh_secret, (byte) 0);
        deriveSessionKey();
        
        byte[] encPcChallenge = new byte[32];
        byte [] pcChallenge = new byte[32];
        Util.arrayCopy(decryptedData, (short) 59, encPcChallenge, (short) 0, (short) 32);

        m_aes_decrypt.doFinal(encPcChallenge, (short) 0, (short) 32, pcChallenge, (short) 0);
        //System.out.printf("aplet:: pc challenge: %s\n", cardTools.Util.toHex(pcChallenge), pcChallenge.length);
        
        RandomData random = RandomData.getInstance(RandomData.ALG_TRNG);
        random.nextBytes(challenge, (short) 0, (short) 31);
        byte[] sendData = new byte[64];
        Util.arrayCopy(challenge, (short) 0, sendData, (short) 0, (short) 31);
        Util.arrayCopy(pcChallenge, (short) 0, sendData, (short) 31, (short) 31);
        sendData[63] = (byte) 02; // pkcs5 padding
        sendData[62] = (byte) 02; // pkcs5 padding
        m_aes_encrypt.doFinal(sendData, (short) 0, (short) 64, sendData, (short) 0);
        
        Util.arrayCopy(sendData, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, (short) 64);
        
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) (64));
    }
    
    void ECDHAuthPC(APDU apdu, byte[] challenge) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();
        
        byte[] recData = new byte[dataLen];
        Util.arrayCopy(apdubuf, ISO7816.OFFSET_CDATA, recData, (short) 0, dataLen);
        
        byte[] solvedChallenge = new byte[32];
        m_aes_decrypt.doFinal(recData, (short) 0, (short) 32, solvedChallenge, (short) 0);
        //System.out.printf("aplet ch: %s\n", cardTools.Util.toHex(solvedChallenge), challenge.length);
        //System.out.printf("aplet ch: %s\n", cardTools.Util.toHex(pcChallenge), challenge.length);


        
        if (Util.arrayCompare(challenge, (short) 0, solvedChallenge, (short) 0, (short) 31) == 0)
            apdubuf[ISO7816.OFFSET_CDATA + 1] = (byte) 01;
        else {
            apdubuf[ISO7816.OFFSET_CDATA + 1] = (byte) 01;
            System.out.println("Auth of PC failed on card!");
            // TODO: auth failed
        }
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) (64));
            
        
    }
    //Derive session key from shared secret
    void deriveSessionKey() {
        byte[] iv = new byte[16]; //TODO derive instead
        Util.arrayFillNonAtomic(iv, (short) 0, (short) 16, (byte) 0);
        
        m_hash.doFinal(m_ecdh_secret, (short) 0, (short) m_ecdh_secret.length, m_ramArray, (short) 0);
        
        m_aes_key.setKey(m_ramArray, (short) 0); //TODO derive instead
        
        m_aes_encrypt.init(m_aes_key, Cipher.MODE_ENCRYPT, m_ramArray, (short) 16, (short) 16);
        m_aes_decrypt.init(m_aes_key, Cipher.MODE_DECRYPT, m_ramArray, (short) 16, (short) 16);
    }
    
    //only for debugging
    void getEcdhSecret(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        Util.arrayCopy(m_ecdh_secret, (short) 0, apdubuf, (short) (ISO7816.OFFSET_CDATA), (short) m_ecdh_secret.length);
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) m_ecdh_secret.length);
    }
    
    //only for debugging
    void getPin(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        Util.arrayCopy(m_pin_data, (short) 0, apdubuf, (short) (ISO7816.OFFSET_CDATA), (short) m_pin_data.length);
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) m_pin_data.length);
    }
    
    private byte[] hashPIN(byte[] pin) throws ISOException {
        
        MessageDigest md = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
        byte[] hashed = new byte[20];
        md.doFinal(pin, (short) 0, (short) 4, hashed, (short) 0);
        return Arrays.copyOf(hashed, 16);

    }
    
    public byte[] encDataByHashPIN(byte[] data, byte[] key, short dataLen) throws ISOException, CryptoException {

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
    
    public byte[] decDataByHashPIN(byte[] data, byte[] key, short dataLength) throws ISOException, CryptoException {
        AESKey aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        aesKey.setKey(key, (short) 0);
        
        byte[] aesICV = new byte[16];
        
        Cipher cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        cipher.init(aesKey, Cipher.MODE_DECRYPT, aesICV, (short) 0, (short) 16);
        
        byte[] decrypted = new byte[96];
        cipher.doFinal(data, (short) 0, dataLength, decrypted, (short) 0);
        return decrypted;
    }

}
