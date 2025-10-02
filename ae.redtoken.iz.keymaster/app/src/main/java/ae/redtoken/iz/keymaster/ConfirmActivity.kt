package ae.redtoken.iz.keymaster

import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity


class ConfirmActivity : FragmentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val message = intent.getStringExtra("cookie") ?: "Do you want to continue?";

        showFingerprintPrompt()


        setContent {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(16.dp),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text(text = message, fontSize = 20.sp)

                Spacer(modifier = Modifier.height(20.dp))

                Row {
                    Button(onClick = {
                        Zool.confirmations.get(intent.getIntExtra("id",-1))?.onResult(true)
                        finish() // Close this activity
                    }) {
                        Text("Yes")
                    }

                    Spacer(modifier = Modifier.width(16.dp))

                    Button(onClick = {
                        Zool.confirmations.get(intent.getIntExtra("id",-1))?.onResult(false)
                        finish()
                    }) {
                        Text("No")
                    }
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
                    Toast.makeText(this@ConfirmActivity, "Action verified!", Toast.LENGTH_SHORT).show()
                    Zool.confirmations.get(intent.getIntExtra("id",-1))?.onResult(true)
                    finish() // Close this activity
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    Toast.makeText(this@ConfirmActivity, "Error: $errString", Toast.LENGTH_SHORT)
                        .show()
                    Zool.confirmations.get(intent.getIntExtra("id",-1))?.onResult(false)
                    finish()
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    Toast.makeText(
                        this@ConfirmActivity,
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
            .setDescription("Once Upon a time\n in a Castel far far away")
            .build()

        biometricPrompt.authenticate(promptInfo)
    }
}
