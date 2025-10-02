package ae.redtoken.iz.keymaster

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyHorizontalGrid
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Divider
import androidx.compose.material3.HorizontalDivider
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

import androidx.compose.material3.Text
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch


class LoginActivity : ComponentActivity() {

    class User(val name: String, val age: Int) {
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        var password: String = intent.getStringExtra("password").toString()
        var address = intent.getStringExtra("address")
        val port: Int = intent.getIntExtra("port", -1)

        if(address == null)
            address = "Unknown"

        setContent {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(16.dp),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text(text = "Logged In", fontSize = 20.sp)
                Text(text = "$address:$port", fontSize = 20.sp)

                val users: List<User> = listOf(User("alice", 10),User("Bob", 11),User("C", 131))

                Column(modifier = Modifier.fillMaxSize()) {
                    // Header
                    Row(modifier = Modifier.fillMaxWidth()) {
                        Text("Name", modifier = Modifier.weight(1f).padding(4.dp), fontWeight = FontWeight.Bold)
                        Text("Age", modifier = Modifier.weight(1f).padding(4.dp), fontWeight = FontWeight.Bold)
                    }
                    HorizontalDivider(color = Color.Black, thickness = 1.dp)

                    // Data
                    LazyColumn {
                        items(users) { user ->
                            Row(modifier = Modifier.fillMaxWidth()) {
                                Text(user.name, modifier = Modifier.weight(1f).padding(4.dp))
                                Text(user.age.toString(), modifier = Modifier.weight(1f).padding(4.dp))
                            }
                            HorizontalDivider(color = Color.Gray, thickness = 0.5.dp)
                        }
                    }
                }
//                LazyVerticalGrid(
//                    columns = GridCells.Fixed(2),
//                    modifier = Modifier.fillMaxSize()
//                ) {
//                    item {
//                        Column(
//                            modifier = Modifier
//                                .border(1.dp, Color.Black)
//                                .padding(8.dp)
//                        ) {
//                            Text("Name", fontWeight = FontWeight.Bold)
//                            Text("Age", fontWeight = FontWeight.Bold)
//                        }
//                    }
//                    items(users) { user ->
//                        Column (
//                            modifier = Modifier
//                                .padding(8.dp)
//                                .border(1.dp, Color.Gray)
//                        ) {
//                            Text("Age: ${user.age}")
//                            Text("Name: ${user.name}")
//                        }
//                    }
//                }

            }
        }

        this@LoginActivity.lifecycleScope.launch {
            sendUdpMessage(this@LoginActivity, address, port, password)
        }
    }
}
