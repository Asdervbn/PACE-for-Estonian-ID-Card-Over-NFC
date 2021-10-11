package ee.ut.math.lemmo.readnfctag;

import android.app.Activity;
import android.content.Context;
import android.nfc.NfcAdapter;
import android.nfc.NfcManager;
import android.nfc.tech.IsoDep;
import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

public class MainActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        setContentView(R.layout.activity_main);

        TextView textView = findViewById(R.id.response);
        EditText editText = findViewById(R.id.CAN);
        Button button = findViewById(R.id.connect);

        button.setOnClickListener(view -> textView.setText("Card not found."));

        NfcManager manager = (NfcManager) getSystemService(Context.NFC_SERVICE);
        NfcAdapter nfcAdapter = manager.getDefaultAdapter();
        if (nfcAdapter != null) {
            nfcAdapter.enableReaderMode(this, discoveredTag -> {

                runOnUiThread(() -> textView.setText("Card found."));
                button.setOnClickListener(view -> new Thread(() -> {

                    try (IsoDep idCard = IsoDep.get(discoveredTag)) {

                        idCard.setTimeout(Short.MAX_VALUE);

                        Comms comms = new Comms(idCard, editText.getText().toString());

//                        String[] response = comms.readPersonalData(new byte[]{2});
//                        String welcome = String.format("Hello, %s.", response[0].charAt(0) + response[0].substring(1).toLowerCase());
//                        runOnUiThread(() -> textView.setText(welcome));

                        comms.getAuthenticationCertificate("0000");

                    } catch (Exception e) {
                        e.printStackTrace();
                        runOnUiThread(() -> textView.setText(e.getMessage()));
                    }

                }).start());

            }, NfcAdapter.FLAG_READER_NFC_A, null);
        }
    }
}