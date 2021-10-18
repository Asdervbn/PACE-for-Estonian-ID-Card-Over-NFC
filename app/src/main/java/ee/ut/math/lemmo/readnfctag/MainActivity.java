package ee.ut.math.lemmo.readnfctag;

import android.app.Activity;
import android.content.Context;
import android.nfc.NfcAdapter;
import android.nfc.NfcManager;
import android.nfc.tech.IsoDep;
import android.os.Bundle;
import android.widget.EditText;
import android.widget.TextView;

public class MainActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        setContentView(R.layout.activity_main);

        TextView textView = findViewById(R.id.response);
        EditText CAN = findViewById(R.id.CAN);
        EditText PIN = findViewById(R.id.PIN);

        NfcManager manager = (NfcManager) getSystemService(Context.NFC_SERVICE);
        NfcAdapter nfcAdapter = manager.getDefaultAdapter();
        if (nfcAdapter != null) {
            nfcAdapter.enableReaderMode(this, discoveredTag -> {

                runOnUiThread(() -> textView.setText(R.string.card_found));
                new Thread(() -> {

                    try (IsoDep idCard = IsoDep.get(discoveredTag)) {

                        idCard.setTimeout(Short.MAX_VALUE);

                        Comms comms = new Comms(idCard, CAN.getText().toString());

                        String[] response = comms.readPersonalData(new byte[]{2});
                        String welcome = String.format("Hello, %s.", response[0].charAt(0) + response[0].substring(1).toLowerCase());
                        runOnUiThread(() -> textView.setText(welcome));

//                        byte[] certificate = comms.getCertificate(true);
//                        CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
//                        X509Certificate x509Certificate = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certificate));
//                        Log.i("Certificate subject", x509Certificate.getSubjectX500Principal().getName());
//
//                        comms.authenticate(PIN.getText().toString(), new byte[16]);

                    } catch (Exception e) {
                        e.printStackTrace();
                        runOnUiThread(() -> textView.setText(e.getMessage()));
                    }

                }).start();

            }, NfcAdapter.FLAG_READER_NFC_A, null);
        }
    }
}