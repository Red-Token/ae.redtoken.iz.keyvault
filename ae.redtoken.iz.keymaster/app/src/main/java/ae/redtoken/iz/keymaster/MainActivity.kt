package ae.redtoken.iz.keymaster

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import ae.redtoken.iz.keymaster.ui.theme.IZKeyMasterTheme
import ae.redtoken.iz.keyvault.bitcoin.scenario.LoginInfo
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.TextButton
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import com.google.zxing.BarcodeFormat
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : FragmentActivity() {

    var loginInfo: LoginInfo = LoginInfo();

    // Register the scanner result callback
    public val barcodeLauncher = registerForActivityResult(ScanContract()) { result ->
        if (result.contents != null) {
            Log.d("QR", "Scanned QR: ${result.contents}")
            // TODO: handle scanned value
            loginInfo = Zool.parseQR(result.contents);
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Request notification permission on Android 13+
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), 1)
            }
        }

        enableEdgeToEdge()
        setContent {
            IZKeyMasterTheme {
                Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                    Greeting(
                        name = "Android",
                        modifier = Modifier.padding(innerPadding),
                        activity = this
                    )
                }
            }
        }
    }

    public fun showFingerprintPrompt() {
        val executor = ContextCompat.getMainExecutor(this)

        val biometricPrompt = BiometricPrompt(this, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    // Fingerprint verified — user approved action
                    Toast.makeText(this@MainActivity, "Action verified!", Toast.LENGTH_SHORT).show()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    Toast.makeText(this@MainActivity, "Error: $errString", Toast.LENGTH_SHORT)
                        .show()
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    Toast.makeText(
                        this@MainActivity,
                        "Fingerprint not recognized",
                        Toast.LENGTH_SHORT
                    ).show()
                }
            }
        )

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Confirm action")
            .setSubtitle("Verify with your fingerprint")
            .setNegativeButtonText("Cancel")
            .build()

        biometricPrompt.authenticate(promptInfo)
    }
}

suspend fun sendUdpMessage(
    context: ComponentActivity,
    address: String,
    port: Int,
    password: String
) {
    withContext(Dispatchers.IO) {
        Zool.mainX(context, address, port, password)
    }
}

@Composable
fun Greeting(name: String, modifier: Modifier = Modifier, activity: MainActivity) {

    // State to control if the dialog is shown
    var showDialog by remember { mutableStateOf(false) }

    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(text = "Hello $name!")

        Spacer(modifier = Modifier.height(16.dp))

//        Button(onClick = { showDialog = true }) {
//            Text("Show Popup")
//        }

        Button(onClick = {
            val a: MainActivity = activity as MainActivity

            val intent = Intent(activity, LoginActivity::class.java)
            intent.putExtra("password", a.loginInfo.password)
            intent.putExtra("address", a.loginInfo.address)
            intent.putExtra("port", a.loginInfo.port)
            activity.startActivity(intent)
        }) {
            Text("Login ")
        }


//        Button(onClick = {
//            Zool.notifyX(activity)
//        }) {
//            Text("Notify Me!")
//        }

//        Button(onClick = {
//            val intent = Intent(activity, ConfirmActivity::class.java)
//            intent.putExtra("cookie", "chockolate")
//            activity.startActivity(intent)
//        }) {
//            Text("Lets roll!")
//        }

        Button(onClick = {

            val a: MainActivity = activity as MainActivity
            val x: Collection<String> = listOf(BarcodeFormat.QR_CODE.toString())

            activity.barcodeLauncher.launch(ScanOptions().apply {
                setDesiredBarcodeFormats(x)
                setPrompt("Scan a QR code")
                setBeepEnabled(true)
                setCameraId(0) // 0 = back camera
            })

//            val integrator = IntentIntegrator(activity)
//            integrator.setDesiredBarcodeFormats(IntentIntegrator.QR_CODE)
//            integrator.setPrompt("Scan a QR code")
//            integrator.setBeepEnabled(true)
//            integrator.initiateScan()


        }) {
            Text("Action!")
        }

        Button(onClick = { activity.showFingerprintPrompt() }) {
            Text("Verify Action")
        }

    }

    // The popup dialog
    if (showDialog) {
        AlertDialog(
            onDismissRequest = { showDialog = false },
            title = { Text("Popup Title") },
            text = { Text("This is a Compose popup window!") },
            confirmButton = {
                TextButton(onClick = {
                    activity.lifecycleScope.launch {
//                        sendUdpMessage(activity, address, port, password)
                    }

                    showDialog = false
                }) {
                    Text("OK")
                }
            },
            dismissButton = {
                TextButton(onClick = { showDialog = false }) {
                    Text("Cancel")
                }
            }
        )
    }
}

@Preview(showBackground = true)
@Composable
fun GreetingPreview() {
    IZKeyMasterTheme {
//        Greeting("Android", activity =)
    }
}