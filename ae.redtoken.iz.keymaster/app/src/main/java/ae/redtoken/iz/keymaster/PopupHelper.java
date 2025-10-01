package ae.redtoken.iz.keymaster;

import android.app.AlertDialog;
import android.app.Dialog;
import android.content.Context;

import java.util.concurrent.FutureTask;

public class PopupHelper {

    public interface DialogCallback {
        void onResult(boolean result);
    }

    public static void showYesNoDialog(Context context, DialogCallback callback) {
        new AlertDialog.Builder(context)
                .setTitle("Confirm")
                .setMessage("Do you want to continue?")
                .setPositiveButton("Yes", (dialog, which) -> {
                    callback.onResult(true);
                })
                .setNegativeButton("No", (dialog, which) -> {
                    // Handle NO here
                    callback.onResult(false);
                })
                .show();
    }
}
