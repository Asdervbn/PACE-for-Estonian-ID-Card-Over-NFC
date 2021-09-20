package ee.ut.math.lemmo.readnfctag;

import android.content.Intent;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.KeyEncapsulation;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
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
import java.util.concurrent.atomic.AtomicLong;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends AppCompatActivity {

    byte[] master = { // select master file
            (byte) 0x00, // Class
            (byte) 0xA4, // Instruction
            (byte) 0x04, // Parameter 1
            (byte) 0x0C, // Parameter 2
            (byte) 0x10, // Length
            (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x77,
            (byte) 0x01, (byte) 0x08, (byte) 0x00, (byte) 0x07, (byte) 0x00,
            (byte) 0x00, (byte) 0xFE, (byte) 0x00, (byte) 0x00, (byte) 0x01,
            (byte) 0x00,
    };
    byte[] personal = { // select personal data DF
            (byte) 0x0C, (byte) 0xA4, (byte) 0x01, (byte) 0x0C, (byte) 0x1D,
            (byte) 0x87, (byte) 0x11, (byte) 0x01,
    };
    byte[] idcode = { // select identification code EF
            (byte) 0x00, (byte) 0xA4, (byte) 0x02, (byte) 0x0C, (byte) 0x02,
            (byte) 0x50, (byte) 0x06,
    };
    byte[] docnum = { // select document number EF
            (byte) 0x00, (byte) 0xA4, (byte) 0x02, (byte) 0x0C, (byte) 0x02,
            (byte) 0xD0, (byte) 0x03,
    };
    byte[] cardaccess = { // select card access EF
            (byte) 0x00, (byte) 0xA4, (byte) 0x02, (byte) 0x0C, (byte) 0x02,
            (byte) 0x01, (byte) 0x1C,
    };
    byte[] read = { // read binary
            (byte) 0x00, (byte) 0xB0, (byte) 0x00, (byte) 0x00, (byte) 0x00,
    };
    byte[] MSESetAT = { // manage security environment: set authentication template
            (byte) 0x00, (byte) 0x22, (byte) 0xC1, (byte) 0xA4, (byte) 0x0F,
            (byte) 0x80, (byte) 0x0A, // cryptographic protocol: id-PACE-ECDH-GM-AES-CBC-CMAC-256
            (byte) 0x04, (byte) 0x00, (byte) 0x7F, (byte) 0x00, (byte) 0x07,
            (byte) 0x02, (byte) 0x02, (byte) 0x04, (byte) 0x02, (byte) 0x04,
            (byte) 0x83, (byte) 0x01, // password: CAN
            (byte) 0x02,
            (byte) 0x00,
    };
    byte[] GAGetNonce = { // general authenticate: get nonce
            (byte) 0x10, (byte) 0x86, (byte) 0x00, (byte) 0x00, (byte) 0x02,
            (byte) 0x7C, (byte) 0x00,
            (byte) 0x00,
    };
    byte[] GAMapNonceIncomplete = { // general authenticate: map nonce
            (byte) 0x10, (byte) 0x86, (byte) 0x00, (byte) 0x00, (byte) 0x45,
            (byte) 0x7C, (byte) 0x43, (byte) 0x81, (byte) 0x41,
    };
    byte[] GAKeyAgreementIncomplete = { // general authenticate: map nonce
            (byte) 0x10, (byte) 0x86, (byte) 0x00, (byte) 0x00, (byte) 0x45,
            (byte) 0x7C, (byte) 0x43, (byte) 0x83, (byte) 0x41,
    };
    byte[] dataForMACIncomplete = {
            (byte) 0x7F, (byte) 0x49, (byte) 0x4F, (byte) 0x06, (byte) 0x0A,
            (byte) 0x04, (byte) 0x00, (byte) 0x7F, (byte) 0x00, (byte) 0x07,
            (byte) 0x02, (byte) 0x02, (byte) 0x04, (byte) 0x02, (byte) 0x04,
            (byte) 0x86, (byte) 0x41,

    };
    byte[] GAMutualAuthenticationIncomplete = { // general authenticate: mutual authentication
            (byte) 0x00, (byte) 0x86, (byte) 0x00, (byte) 0x00, (byte) 0x0C,
            (byte) 0x7C, (byte) 0x0A, (byte) 0x85, (byte) 0x08,
    };

    public byte[] decryptNonce(byte[] encryptedNonce, String CANString) throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {

        byte[] CAN = CANString.getBytes(StandardCharsets.UTF_8);
        byte[] CANPlusThree = Arrays.copyOf(CAN, CAN.length + 4);
        CANPlusThree[CANPlusThree.length - 1] = 3;
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        byte[] decryptionKey = messageDigest.digest(CANPlusThree);

        byte[] iv = new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(decryptionKey,"AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        return cipher.doFinal(encryptedNonce);
    }

    public byte[] createMapNonceAPDU(byte[] publicKey) {

        byte[] GAMapNonce = Arrays.copyOf(GAMapNonceIncomplete, GAMapNonceIncomplete.length + 66);
        System.arraycopy(publicKey, 0, GAMapNonce, GAMapNonceIncomplete.length, publicKey.length);
        return GAMapNonce;
    }

    public byte[] createKeyAgreementAPDU(byte[] publicKey) {

        byte[] GAKeyAgreement = Arrays.copyOf(GAKeyAgreementIncomplete, GAKeyAgreementIncomplete.length + 66);
        System.arraycopy(publicKey, 0, GAKeyAgreement, GAKeyAgreementIncomplete.length, publicKey.length);
        return GAKeyAgreement;
    }

    public byte[] createMutualAuthenticationAPDU(byte[] mac) {

        byte[] GAMutualAuthentication = Arrays.copyOf(GAMutualAuthenticationIncomplete, GAMutualAuthenticationIncomplete.length + 9);
        System.arraycopy(mac, 0, GAMutualAuthentication, GAMutualAuthenticationIncomplete.length, 8);
        return GAMutualAuthentication;
    }

    public byte[] getCardPublicKeyFromResponse(byte[] response) {

        byte[] cardPublicKey = new byte[65];
        System.arraycopy(response, 4, cardPublicKey, 0, 65);
        return cardPublicKey;
    }

    public void printResponseAPDU(byte[] response) {

        StringBuilder sb = new StringBuilder();
        for (byte b : response) sb.append(String.format("%02X ", b));
        System.out.println(sb);
    }

    public void process(IsoDep idCard, String CAN, TextView textView) throws IOException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {

        idCard.connect();
        byte[] response;

        response = idCard.transceive(master);
        printResponseAPDU(response);

        response = idCard.transceive(MSESetAT);
        printResponseAPDU(response);

        response = idCard.transceive(GAGetNonce);
        printResponseAPDU(response);

        byte[] encryptedNonce = Arrays.copyOfRange(response, 4, response.length - 2);
        byte[] decryptedNonce = decryptNonce(encryptedNonce, CAN);

        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256r1");

        AsymmetricCipherKeyPair keyPair = generateKeyPair(spec.getCurve(), spec.getG(), spec.getN(), spec.getH(), spec.getSeed());
        ECPrivateKeyParameters privateKeyParameters = (ECPrivateKeyParameters) keyPair.getPrivate();
        ECPublicKeyParameters publicKeyParameters = (ECPublicKeyParameters) keyPair.getPublic();
        BigInteger privateKey = privateKeyParameters.getD();
        ECPoint publicKey = publicKeyParameters.getQ();

        byte[] GAMapNonce = createMapNonceAPDU(publicKey.getEncoded(false));
        response = idCard.transceive(GAMapNonce);
        printResponseAPDU(response);

        byte[] cardPublicKeyEncoded = getCardPublicKeyFromResponse(response);
        ECPoint cardPublicKey = spec.getCurve().decodePoint(cardPublicKeyEncoded);

        ECPoint sharedSecret = cardPublicKey.multiply(privateKey).normalize();
        ECPoint mappedECBasePoint = spec.getG().multiply(new BigInteger(decryptedNonce)).add(sharedSecret).normalize();

        keyPair = generateKeyPair(spec.getCurve(), mappedECBasePoint, spec.getN(), spec.getH(), spec.getSeed());
        privateKeyParameters = (ECPrivateKeyParameters) keyPair.getPrivate();
        publicKeyParameters = (ECPublicKeyParameters) keyPair.getPublic();
        privateKey = privateKeyParameters.getD();
        publicKey = publicKeyParameters.getQ();

        byte[] GAKeyAgreement = createKeyAgreementAPDU(publicKey.getEncoded(false));
        response = idCard.transceive(GAKeyAgreement);
        printResponseAPDU(response);

        cardPublicKeyEncoded = getCardPublicKeyFromResponse(response);
        cardPublicKey = spec.getCurve().decodePoint(cardPublicKeyEncoded);

        sharedSecret = cardPublicKey.multiply(privateKey).normalize();

        byte[] secretEncoded = sharedSecret.getAffineXCoord().getEncoded();
        byte[] secretPlusOne = Arrays.copyOf(secretEncoded, secretEncoded.length + 4);
        secretPlusOne[secretPlusOne.length - 1] = 1;
        byte[] secretPlusTwo = Arrays.copyOf(secretEncoded, secretEncoded.length + 4);
        secretPlusTwo[secretPlusTwo.length - 1] = 2;
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        byte[] Kenc = messageDigest.digest(secretPlusOne);
        byte[] Kmac = messageDigest.digest(secretPlusTwo);

        byte[] dataForMAC = Arrays.copyOf(dataForMACIncomplete, dataForMACIncomplete.length + 65);
        System.arraycopy(cardPublicKey.getEncoded(false), 0, dataForMAC, dataForMACIncomplete.length, 65);
        BlockCipher blockCipher = new AESEngine();
        CMac cmac = new CMac(blockCipher);
        cmac.init(new KeyParameter(Kmac));
        cmac.update(dataForMAC, 0, dataForMAC.length);
        byte[] mac = new byte[cmac.getMacSize()];
        cmac.doFinal(mac, 0);

        byte[] GAMutualAuthentication = createMutualAuthenticationAPDU(mac);
        response = idCard.transceive(GAMutualAuthentication);
        printResponseAPDU(response);

        dataForMAC = Arrays.copyOf(dataForMACIncomplete, dataForMACIncomplete.length + 65);
        System.arraycopy(publicKey.getEncoded(false), 0, dataForMAC, dataForMACIncomplete.length, 65);
        cmac.update(dataForMAC, 0, dataForMAC.length);
        cmac.doFinal(mac, 0);
//        System.out.println(Hex.toHexString(mac, 0, 8));

//        if (response.length == 2) {
//            textView.setText(Hex.toHexString(response));
//        } else {
//            assert (Hex.toHexString(response, 4, 8).equals(Hex.toHexString(mac, 0, 8)));
//            textView.setText("Hurray");
//        }

        byte[] sscByteArray = new byte[16];
        sscByteArray[sscByteArray.length - 1] = (byte) 1;

        byte[] selectPersonal = constructSecureChannelAPDU(new byte[0], Kenc, sscByteArray);


        sscByteArray = Hex.decode("000000000000000000000000000000010CA4010C800000000000000000000000871101");
        byte[] macdata = new byte[64];
        System.arraycopy(sscByteArray, 0, macdata, 0, sscByteArray.length);
        System.arraycopy(selectPersonal, 0, macdata, sscByteArray.length, selectPersonal.length);
        macdata[sscByteArray.length + selectPersonal.length] = (byte) 0x80;
        System.out.println(Hex.toHexString(macdata));
        blockCipher = new AESEngine();
        cmac = new CMac(blockCipher);
        cmac.init(new KeyParameter(Kmac));
        cmac.update(macdata, 0, macdata.length);
        mac = new byte[cmac.getMacSize()];
        cmac.doFinal(mac, 0);
        mac = Arrays.copyOf(mac, 8);
        byte[] asdf = new byte[personal.length + mac.length + selectPersonal.length + 3];
        System.arraycopy(personal, 0, asdf, 0, personal.length);
        System.arraycopy(selectPersonal, 0, asdf, personal.length, selectPersonal.length);
        System.arraycopy(mac, 0, asdf, personal.length + selectPersonal.length + 2, mac.length);
        System.arraycopy(new byte[]{(byte) 0x8E, (byte) 0x08}, 0, asdf, personal.length + selectPersonal.length, 2);
        System.out.println(Hex.toHexString(asdf));

        response = idCard.transceive(asdf);
        printResponseAPDU(response);

        idCard.close();

    }

    private byte[] constructSecureChannelAPDU(byte[] message, byte[] Kenc, byte[] ssc) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        byte[] data = Hex.decode("50008000000000000000000000000000");

        SecretKeySpec secretKeySpec = new SecretKeySpec(Kenc, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        byte[] iv = Arrays.copyOf(cipher.doFinal(ssc), 16);

        cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(iv));
        return cipher.doFinal(data);
    }

    private AsymmetricCipherKeyPair generateKeyPair(ECCurve curve, ECPoint g, BigInteger n, BigInteger h, byte[] seed) {

        ECDomainParameters parameters = new ECDomainParameters(curve, g, n, h, seed);
        ECKeyGenerationParameters generationParameters = new ECKeyGenerationParameters(parameters, new SecureRandom());
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        generator.init(generationParameters);
        return generator.generateKeyPair();

    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        AtomicLong i = new AtomicLong(1);

        setContentView(R.layout.activity_main);

        TextView textView = findViewById(R.id.returnCode);
        EditText editText = findViewById(R.id.CAN);
        Button button = findViewById(R.id.button);
        button.setOnClickListener(view -> {

            Intent intent = getIntent();

            if (intent.getAction().equals("android.nfc.action.TECH_DISCOVERED")) {

                textView.setText("Found card.");

                Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
                IsoDep idCard = IsoDep.get(tag);

                try {
                    process(idCard, editText.getText().toString(), textView);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            } else {
                textView.setText(String.format("%s: No card found.", i.getAndIncrement()));
            }

        });

        System.out.println("Done.");

    }
}