package ee.ut.math.lemmo.readnfctag;

import android.app.Activity;
import android.nfc.NfcAdapter;
import android.nfc.tech.IsoDep;
import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends Activity {

    private static final byte[] master = { // select master file
            (byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x0C, (byte) 0x10,
            (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x77,
            (byte) 0x01, (byte) 0x08, (byte) 0x00, (byte) 0x07, (byte) 0x00,
            (byte) 0x00, (byte) 0xFE, (byte) 0x00, (byte) 0x00, (byte) 0x01,
            (byte) 0x00,
    };

    private static final byte[] MSESetAT = { // manage security environment: set authentication template
            (byte) 0x00, (byte) 0x22, (byte) 0xC1, (byte) 0xA4, (byte) 0x0F,
            (byte) 0x80, (byte) 0x0A, (byte) 0x04, (byte) 0x00, (byte) 0x7F,
            (byte) 0x00, (byte) 0x07, (byte) 0x02, (byte) 0x02, (byte) 0x04,
            (byte) 0x02, (byte) 0x04, (byte) 0x83, (byte) 0x01, (byte) 0x02,
            (byte) 0x00,
    };

    private static final byte[] GAGetNonce = { // general authenticate: get nonce
            (byte) 0x10, (byte) 0x86, (byte) 0x00, (byte) 0x00, (byte) 0x02,
            (byte) 0x7C, (byte) 0x00, (byte) 0x00,
    };

    private static final byte[] GAMapNonceIncomplete = { // general authenticate: map nonce
            (byte) 0x10, (byte) 0x86, (byte) 0x00, (byte) 0x00, (byte) 0x45,
            (byte) 0x7C, (byte) 0x43, (byte) 0x81, (byte) 0x41,
    };

    private static final byte[] GAKeyAgreementIncomplete = {
            (byte) 0x10, (byte) 0x86, (byte) 0x00, (byte) 0x00, (byte) 0x45,
            (byte) 0x7C, (byte) 0x43, (byte) 0x83, (byte) 0x41,
    };

    private static final byte[] dataForMACIncomplete = {
            (byte) 0x7F, (byte) 0x49, (byte) 0x4F, (byte) 0x06, (byte) 0x0A,
            (byte) 0x04, (byte) 0x00, (byte) 0x7F, (byte) 0x00, (byte) 0x07,
            (byte) 0x02, (byte) 0x02, (byte) 0x04, (byte) 0x02, (byte) 0x04,
            (byte) 0x86, (byte) 0x41,
    };

    private static final byte[] GAMutualAuthenticationIncomplete = {
            (byte) 0x00, (byte) 0x86, (byte) 0x00, (byte) 0x00, (byte) 0x0C,
            (byte) 0x7C, (byte) 0x0A, (byte) 0x85, (byte) 0x08,
    };

    private static final byte[] personal = { // select personal data DF
            (byte) 0x0C, (byte) 0xA4, (byte) 0x01, (byte) 0x0C, (byte) 0x1D,
            (byte) 0x87, (byte) 0x11, (byte) 0x01,
    };

    private static final byte[] read = { // read binary
            (byte) 0x0C, (byte) 0xB0, (byte) 0x00, (byte) 0x00, (byte) 0x0D,
            (byte) 0x97, (byte) 0x01, (byte) 0x00,
    };

    private static final byte[] idcode = { // select identification code EF
            (byte) 0x00, (byte) 0xA4, (byte) 0x02, (byte) 0x0C, (byte) 0x02,
            (byte) 0x50, (byte) 0x06,
    };

    private volatile String result;

    /**
     * Decrypts the encrypted nonce using the provided CAN
     * @param encryptedNonce the encrypted nonce received from the chip
     * @param CAN the CAN provided by the user
     * @return decrypted nonce as a byte array
     */
    private byte[] decryptNonce(byte[] encryptedNonce, String CAN) throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        byte[] decryptionKey = createKey(CAN.getBytes(StandardCharsets.UTF_8), (byte) 3);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(new byte[16]);
        SecretKeySpec secretKeySpec = new SecretKeySpec(decryptionKey, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        return cipher.doFinal(encryptedNonce);
    }

    /**
     * Creates an application protocol data unit using predefined templates and supplied data
     * @param template the byte array to be used as a template
     * @param data the necessary data for completing the APDU
     * @param extra the missing length of the APDU being created
     * @return the complete APDU as a byte array
     */
    private byte[] createAPDU(byte[] template, byte[] data, int extra) {
        byte[] APDU = Arrays.copyOf(template, template.length + extra);
        System.arraycopy(data, 0, APDU, template.length, data.length);
        return APDU;
    }

    /**
     * Creates a cipher key by constructing an array in a particular format and hashing it
     * @param unpadded the array to be used as the basis for this key
     * @param last the last byte in the padding
     * @return the constructed key as a byte array
     */
    private byte[] createKey(byte[] unpadded, byte last) throws NoSuchAlgorithmException {
        byte[] padded = Arrays.copyOf(unpadded, unpadded.length + 4);
        padded[padded.length - 1] = last;
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        return messageDigest.digest(padded);
    }

    /**
     * Attempts to use PACE to create a secure channel with an Estonian ID-card
     * @param idCard the IsoDep link to the card
     * @param CAN card access number
     * @return status words 1 & 2 of the mutual authentication response
     */
    private byte[] PACE(IsoDep idCard, String CAN) throws IOException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {

        byte[] response;
        byte[] APDU;
        byte[] decryptedNonce;
        byte[] encodedSecret;
        byte[] KeyEnc;
        byte[] KeyMAC;
        byte[] MAC;
        BigInteger privateKey;
        ECPoint publicKey;
        ECPoint cardPublicKey;
        ECPoint sharedSecret;
        ECPoint mappedECBasePoint;
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256r1");

        idCard.connect();

        response = idCard.transceive(master);
        System.out.println(Hex.toHexString(response));

        response = idCard.transceive(MSESetAT);
        System.out.println(Hex.toHexString(response));

        response = idCard.transceive(GAGetNonce);
        System.out.println(Hex.toHexString(response));
        decryptedNonce = decryptNonce(Arrays.copyOfRange(response, 4, response.length - 2), CAN);

        privateKey = new BigInteger(255, new SecureRandom()).add(BigInteger.ONE);
        publicKey = spec.getG().multiply(privateKey).normalize();
        APDU = createAPDU(GAMapNonceIncomplete, publicKey.getEncoded(false), 66);
        response = idCard.transceive(APDU);
        System.out.println(Hex.toHexString(response));
        cardPublicKey = spec.getCurve().decodePoint(Arrays.copyOfRange(response, 4, 69));

        sharedSecret = cardPublicKey.multiply(privateKey);
        mappedECBasePoint = spec.getG().multiply(new BigInteger(1, decryptedNonce)).add(sharedSecret).normalize();
        privateKey = new BigInteger(255, new SecureRandom()).add(BigInteger.ONE);
        publicKey = mappedECBasePoint.multiply(privateKey).normalize();
        APDU = createAPDU(GAKeyAgreementIncomplete, publicKey.getEncoded(false), 66);
        response = idCard.transceive(APDU);
        System.out.println(Hex.toHexString(response));
        cardPublicKey = spec.getCurve().decodePoint(Arrays.copyOfRange(response, 4, 69));

        sharedSecret = cardPublicKey.multiply(privateKey).normalize();
        encodedSecret = sharedSecret.getAffineXCoord().getEncoded();
        KeyEnc = createKey(encodedSecret, (byte) 1);
        KeyMAC = createKey(encodedSecret, (byte) 2);
        APDU = createAPDU(dataForMACIncomplete, cardPublicKey.getEncoded(false), 65);
        MAC = getMAC(KeyMAC, APDU);
        APDU = createAPDU(GAMutualAuthenticationIncomplete, MAC, 9);
        response = idCard.transceive(APDU);
        System.out.println(Hex.toHexString(response));

        APDU = createAPDU(dataForMACIncomplete, publicKey.getEncoded(false), 65);
        MAC = getMAC(KeyMAC, APDU);

        idCard.close();

        assert response.length == 2 || (Hex.toHexString(response, 4, 8).equals(Hex.toHexString(MAC)));

        return Arrays.copyOfRange(response, response.length - 2, response.length);
    }

    /**
     * Get contents of personal data file
     * @param idCard
     * @param KeyEnc
     * @param KeyMAC
     * @return
     */
    private byte[] doBeRefactored(IsoDep idCard, byte[] KeyEnc, byte[] KeyMAC) throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, IOException {

        byte[] sscByteArray = new byte[16];
        sscByteArray[sscByteArray.length - 1] = (byte) 1;
        byte[] data = Hex.decode("50008000000000000000000000000000");

        byte[] apdu = createSecureAPDU(data, KeyEnc, KeyMAC, sscByteArray, personal);
        byte[] response = idCard.transceive(apdu);
        System.out.println(Hex.toHexString(response));

        sscByteArray[sscByteArray.length - 1] = (byte) 3;
        data = Hex.decode("50018000000000000000000000000000");

        apdu = createSecureAPDU(data, KeyEnc, KeyMAC, sscByteArray, personal);

        response = idCard.transceive(apdu);
        System.out.println(Hex.toHexString(response));

        sscByteArray[sscByteArray.length - 1] = (byte) 5;
        data = new byte[0];

        apdu = createSecureAPDU(data, KeyEnc, KeyMAC, sscByteArray, read);

        response = idCard.transceive(apdu);
        System.out.println(Hex.toHexString(response));

        sscByteArray[sscByteArray.length - 1] = (byte) 6;
        byte[] decryptedData = __cryptAPDUData(Arrays.copyOfRange(response, 3, 19), KeyEnc, sscByteArray, Cipher.DECRYPT_MODE);

        idCard.close();

        return decryptedData;

    }

    /**
     * Calculates the message authentication code
     * @param keyMAC the key for the cipher
     * @param APDU the constructed byte array on which the CMAC algorithm is performed
     * @return MAC
     */
    private byte[] getMAC(byte[] keyMAC, byte[] APDU) {
        BlockCipher blockCipher = new AESEngine();
        CMac cmac = new CMac(blockCipher);
        cmac.init(new KeyParameter(keyMAC));
        cmac.update(APDU, 0, APDU.length);
        byte[] MAC = new byte[cmac.getMacSize()];
        cmac.doFinal(MAC, 0);
        return Arrays.copyOf(MAC, 8);
    }

    /**
     * construct APDUs after secure channel establishment. To be refactored.
     * @param data
     * @param Kenc
     * @param Kmac
     * @param sscByteArray
     * @param incomplete
     * @return
     */
    private byte[] createSecureAPDU(byte[] data, byte[] Kenc, byte[] Kmac, byte[] sscByteArray, byte[] incomplete) throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {

        byte[] encryptedData = new byte[0];

        byte[] macData = new byte[data.length > 0 ? 64 : 48];
        System.arraycopy(sscByteArray, 0, macData, 0, sscByteArray.length);
        System.arraycopy(incomplete, 0, macData, sscByteArray.length, 4);
        macData[sscByteArray.length + 4] = (byte) 0x80;
        System.arraycopy(incomplete, 5, macData, sscByteArray.length * 2, 3);
        if (data.length > 0) {
            encryptedData = __cryptAPDUData(data, Kenc, sscByteArray, Cipher.ENCRYPT_MODE);
            System.arraycopy(encryptedData, 0, macData, sscByteArray.length * 2 + 3, encryptedData.length);
            macData[sscByteArray.length * 2 + 3 + encryptedData.length] = (byte) 0x80;
        } else {
            macData[sscByteArray.length * 2 + 3] = (byte) 0x80;
        }

        AESEngine blockCipher = new AESEngine();
        CMac cmac = new CMac(blockCipher);
        cmac.init(new KeyParameter(Kmac));
        cmac.update(macData, 0, macData.length);
        byte[] MAC = new byte[cmac.getMacSize()];
        cmac.doFinal(MAC, 0);
        MAC = Arrays.copyOf(MAC, 8);

        byte[] apdu = new byte[incomplete.length + MAC.length + encryptedData.length + 3];
        System.arraycopy(incomplete, 0, apdu, 0, incomplete.length);
        if (encryptedData.length > 0) {
            System.arraycopy(encryptedData, 0, apdu, incomplete.length, encryptedData.length);
        }
        apdu[incomplete.length + encryptedData.length] = (byte) 0x8E;
        apdu[incomplete.length + encryptedData.length + 1] = (byte) 0x08;
        System.arraycopy(MAC, 0, apdu, incomplete.length + encryptedData.length + 2, MAC.length);

        return apdu;

    }

    /**
     * Encrypts or decrypts the APDU data
     * @param data the array containing the data to be processed
     * @param Kenc the cipher key
     * @param ssc the send sequence counter
     * @param mode indicates whether to en- or decrypt the data
     * @return the result of encryption or decryption, depending on the mode
     */
    private byte[] __cryptAPDUData(byte[] data, byte[] Kenc, byte[] ssc, int mode) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(Kenc, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        byte[] iv = Arrays.copyOf(cipher.doFinal(ssc), 16);
        cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(mode, secretKeySpec, new IvParameterSpec(iv));
        return cipher.doFinal(data);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        setContentView(R.layout.activity_main);

        TextView textView = findViewById(R.id.returnCode);
        EditText editText = findViewById(R.id.CAN);
        Button button = findViewById(R.id.button);

        button.setOnClickListener(view -> textView.setText("No card found."));

        NfcAdapter nfcAdapter = NfcAdapter.getDefaultAdapter(this);
        if (nfcAdapter == null) {
            return;
        }
        nfcAdapter.enableReaderMode(this, discoveredTag -> {

            runOnUiThread(() -> textView.setText("Card found."));
            button.setOnClickListener(view -> new Thread(() -> {

                IsoDep idCard = IsoDep.get(discoveredTag);
                idCard.setTimeout(32768);

                try {
                    result = Hex.toHexString(PACE(idCard, editText.getText().toString()));
                    runOnUiThread(() -> textView.setText(result));
                    idCard.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }

            }).start());

        }, NfcAdapter.FLAG_READER_NFC_A, null);

    }
}