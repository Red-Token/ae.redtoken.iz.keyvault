package ae.redtoken.iz.keymaster;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.widget.Toast;

public class NoReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        // Do your "No" action here
        Toast.makeText(context, "User pressed NO", Toast.LENGTH_SHORT).show();
    }
}
