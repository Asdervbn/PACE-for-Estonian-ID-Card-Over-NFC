package ee.ut.math.lemmo.readnfctag;

import android.app.Activity;
import android.nfc.NfcAdapter;
import android.nfc.tech.IsoDep;
import android.os.Bundle;
import android.util.Log;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import org.bouncycastle.util.encoders.Hex;

import java.util.Arrays;

public class MainActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        setContentView(R.layout.activity_main);

        TextView textView = findViewById(R.id.response);
        EditText editText = findViewById(R.id.CAN);
        Button button = findViewById(R.id.connect);

        button.setOnClickListener(view -> textView.setText("Card not found."));

        NfcAdapter nfcAdapter = NfcAdapter.getDefaultAdapter(this);
        if (nfcAdapter != null) {
            nfcAdapter.enableReaderMode(this, discoveredTag -> {

                runOnUiThread(() -> textView.setText("Card found."));
                button.setOnClickListener(view -> new Thread(() -> {

                    IsoDep idCard = IsoDep.get(discoveredTag);
                    idCard.setTimeout(32768);

                    try {
                        Comms comms = new Comms();
                        idCard.connect();
                        byte[][] response = comms.PACE(idCard, editText.getText().toString());
                        if (response == null) {
                            runOnUiThread(() -> textView.setText("Invalid CAN."));
                        } else {
                            response = comms.readPersonalData(idCard, response[0], response[1]);
                            for (byte[] datum : response) {
                                Log.i("Data", new String(datum));
                            }
                            int indexOfTerminator = Hex.toHexString(response[1]).lastIndexOf("80") / 2;
                            String firstName = new String(Arrays.copyOfRange(response[1], 0, indexOfTerminator));
                            String welcome = String.format("Hello, %s.", firstName.charAt(0) + firstName.substring(1).toLowerCase());
                            runOnUiThread(() -> textView.setText(welcome));
                        }
                        idCard.close();

                    } catch (Exception e) {
                        e.printStackTrace();
                        runOnUiThread(() -> textView.setText(e.getMessage()));
                    }

                }).start());

            }, NfcAdapter.FLAG_READER_NFC_A, null);
        }
    }
}