package ae.redtoken.iz.keymaster;

import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.util.Log;

import androidx.core.app.NotificationCompat;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.wallet.DeterministicSeed;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.net.InetSocketAddress;
import java.security.Security;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.SynchronousQueue;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.ssh.SshConfigurationStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.ssh.SshProtocolMessages;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.AvatarSpawnPoint;
import ae.redtoken.iz.keyvault.bitcoin.keyvault.KeyVault;
import ae.redtoken.iz.keyvault.bitcoin.scenario.LoginInfo;

public class Zool {

    static LoginInfo parseQR(String qr) {
        ObjectMapper om = new ObjectMapper();
        try {
            return om.readValue(qr, LoginInfo.class);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }


    static Map<Integer, PopupHelper.DialogCallback> confirmations = new HashMap<>();

    static void notifyX(Context context, int id) {

//        YesReceiver yr = new YesReceiver();
//
//        ContextCompat.registerReceiver(context, yr, new IntentFilter("com.example.YES_ACTION"), ContextCompat.RECEIVER_NOT_EXPORTED);
//        ContextCompat.registerReceiver(context, new NoReceiver(), new IntentFilter("com.example.NO_ACTION"), ContextCompat.RECEIVER_NOT_EXPORTED);


        // 1. Get NotificationManager
        NotificationManager notificationManager =
                (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);

        String channelId = "my_channel_id";

// 2. Create notification channel for Android 8+
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    channelId,
                    "My Notifications",
                    NotificationManager.IMPORTANCE_HIGH
            );
            notificationManager.createNotificationChannel(channel);
        }

// 3. Create PendingIntents for Yes/No actions
        Intent intent = new Intent(context, ConfirmActivity.class);
        intent.putExtra("cookie", "vanilla-" + id);
        intent.putExtra("id", id);
        PendingIntent pendingIntent = PendingIntent.getActivity(
                context,
                0,
                intent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
        );

//        Intent yesIntent = new Intent(context, YesReceiver.class);
//        PendingIntent yesPendingIntent = PendingIntent.getBroadcast(
//                context, 0, yesIntent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
//
//        Intent noIntent = new Intent(context, NoReceiver.class);
//        PendingIntent noPendingIntent = PendingIntent.getBroadcast(
//                context, 0, noIntent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

// 4. Build the notification
        NotificationCompat.Builder builder = new NotificationCompat.Builder(context, channelId)
                .setSmallIcon(R.mipmap.ic_launcher)
                .setContentTitle("Confirm action")
                .setContentText("Do you want to continue?")
                .setPriority(NotificationCompat.PRIORITY_MAX)
                .setContentIntent(pendingIntent);
//                .addAction(new NotificationCompat.Action(0, "Yes", yesPendingIntent))
//                .addAction(new NotificationCompat.Action(0, "No", noPendingIntent));

// 5. Show the notification
        notificationManager.notify((int) System.currentTimeMillis(), builder.build());
    }

    static String mainX(Context context, String address, int port, String password) {
        try {
//
//            System.out.println("SFSDFSDFSD");


            Security.removeProvider("BC");
            Security.addProvider(new BouncyCastleProvider());

            String mn = "almost option thing way magic plate burger moral almost question follow light sister exchange borrow note concert olive afraid guard online eager october axis";
            DeterministicSeed ds = DeterministicSeed.ofMnemonic(mn, "");
            KeyVault kv = new KeyVault(ds);

//            RegTestParams params = RegTestParams.get();
            BitcoinNetwork network = BitcoinNetwork.REGTEST;
            ScriptType scriptType = ScriptType.P2PKH;
            List<ScriptType> scriptTypes = List.of(scriptType);

            String email = "bob@teahouse.wl";
//            String password = "Open Sesame!";

            IZKeyMaster km = new IZKeyMaster(kv, email, network, scriptTypes);

            km.scss.granter = new SshConfigurationStackedService.Granter() {
                @Override
                public boolean grantSignEventAccess(SshProtocolMessages.SshSignEventRequest request) {
                    Log.d("ThreadCheck", "Current thread: " + Thread.currentThread().getName());

                    SynchronousQueue<Boolean> q = new SynchronousQueue<>();

                    PopupHelper.DialogCallback dc = new PopupHelper.DialogCallback() {

                        @Override
                        public void onResult(boolean result) {
                            q.add(result);
                        }
                    };

                    int id = (int) System.currentTimeMillis();
                    confirmations.put(id, dc);


                    // Do your "Yes" action here
//                    Intent newIntent = new Intent(context, ConfirmActivity.class);
//                    newIntent.putExtra("cookie", "vanilla");
//                    newIntent.putExtra("id", id);
//                    context.startActivity(newIntent);

                    notifyX(context, id);

//                    new Thread(() -> {
//                        new Handler(Looper.getMainLooper()).post(() -> {
//                            PopupHelper.showYesNoDialog(context, new PopupHelper.DialogCallback() {
//                                @Override
//                                public void onResult(boolean result) {
//                                    q.add(result);
//                                }
//                            });
//                        });
//                    }).start();


//                    new Thread(() -> {
//                        new Handler(Looper.getMainLooper()).post(() -> {
//                            PopupHelper.showYesNoDialog(context, new PopupHelper.DialogCallback() {
//                                @Override
//                                public void onResult(boolean result) {
//                                    q.add(result);
//                                }
//                            });
//                        });
//                    }).start();

                    try {
                        boolean res = q.take();
                        return res;
                    } catch (InterruptedException e) {
                        throw new RuntimeException(e);
                    }
                }
            };

            InetSocketAddress iaddress = new InetSocketAddress(address, port);
            km.login(password, iaddress);

        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        return "ZZZZZ";
    }
}
