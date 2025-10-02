package ae.redtoken.iz.keymaster;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.widget.Toast;

public class YesReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        // Do your "Yes" action here
        Toast.makeText(context, "User pressed YES", Toast.LENGTH_SHORT).show();
        Intent newIntent = new Intent(context, ConfirmActivity.class);
        intent.putExtra("cookie", "vanilla");
        context.startActivity(newIntent);
    }
}
