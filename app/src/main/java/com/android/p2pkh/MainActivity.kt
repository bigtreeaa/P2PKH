package com.android.p2pkh

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import android.view.View
import android.widget.Button
import androidx.compose.runtime.key
import com.android.p2pkh.BuildConfig
import com.google.gson.JsonElement
import com.pubnub.api.PNConfiguration
import com.pubnub.api.PubNub
import com.pubnub.api.UserId
import com.pubnub.api.callbacks.SubscribeCallback
import com.pubnub.api.enums.PNLogVerbosity
import com.pubnub.api.models.consumer.PNStatus
import com.pubnub.api.models.consumer.pubsub.PNMessageResult
import com.pubnub.api.models.consumer.pubsub.PNPresenceEventResult
import org.bitcoinj.core.Base58
import org.bitcoinj.core.Sha256Hash.hash
import org.bitcoinj.core.Utils.sha256hash160
import java.security.*
import java.security.cert.Certificate
import java.security.spec.ECGenParameterSpec
import java.util.*
import org.json.JSONObject

// data class for information of input and output
data class InputData (var output_txid: Int, var output_index : Int, var input_index : Int)
data class OutputData (var address: String, var gruut : Int, var output_index : Int)

// temporary data for inputs and outputs
// mutableList를 사용하여 user가 원하는 대로 data를 추가하거나 변경할 수 있다.
var input_data = mutableListOf<InputData>(InputData(0, 0, 0))
var ouput_data = mutableListOf<OutputData>(OutputData("aaaa",10,0), OutputData("bbbb", 20, 1))

// constant information of wallet
private const val alias : String = "userKey"
private var channelId = "PubNubDemoChannel"

class MainActivity : AppCompatActivity() {

    private lateinit var pubNub: PubNub
    private val filePath = "jsons/coinBase_A.json"

    private lateinit var keyStore : KeyStore
    private lateinit var keyEntry : KeyStore.Entry


    private lateinit var message : JsonElement

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        val btnGenKP = findViewById<Button>(R.id.btnGenKey)
        btnGenKP.setOnClickListener {
            val Key = initKey(alias)
            keyEntry = keyStore.getEntry(alias, null)

            if (keyEntry !is KeyStore.PrivateKeyEntry) {
                Log.d("GenPK", "Not an instance of a PrivateKeyEntry")
            } else {
                Log.d("GenPK", "There is PrivateKeyEntry")
            }
            genAddress(keyStore, alias)
        }

        val btnGenAddress = findViewById<Button>(R.id.btnGenAddress)
        btnGenAddress.setOnClickListener {
            val ks: KeyStore = KeyStore.getInstance("AndroidStudio").apply {
                load(null)
            }
            val cert: Certificate = ks.getCertificate(alias)
            val address = genAddress(ks, alias)
            Log.d("Address", address)
        }

        // Initialize PubNub
        pubNub = PubNub(
            PNConfiguration(userId = UserId(value = "FirstUser")).apply {
                // BuildConfig is created after compiling
                publishKey = BuildConfig.PUBLISH_KEY
                subscribeKey = BuildConfig.SUBSCRIBE_KEY
                // Logcat Verbosity
                logVerbosity = PNLogVerbosity.BODY
            }
        )

        // Subscribe Channel
        // Basic usage with no options
        pubNub.subscribe(
            channels = listOf(channelId)
        )

        pubNub.history(
            channel = channelId,
            reverse = true,
            includeTimetoken = true,
            count = 100
        )

        // Add Listener of a channel to pubNub
        pubNub.addListener(object : SubscribeCallback() {
            override fun status(pubnub: PubNub, pnStatus: PNStatus) {
                Log.v("Status", "${pnStatus.category}")
                // PNConnectedCategory, PNReconnectedCategory, PNDisconnectedCategory
                Log.v("Status", "${pnStatus.operation}")
                // PNSubscribeOperation, PNHeartbeatOperation
                Log.v("Status", "${pnStatus.error}")
                // true or false
            }

            override fun presence(pubnub: PubNub, pnPresenceEventResult: PNPresenceEventResult) {
                Log.v("Presence", "Presence event: ${pnPresenceEventResult.event}")
                Log.v("Presence", "Presence channel: ${pnPresenceEventResult.channel}")
                Log.v("Presence", "Presence uuid: ${pnPresenceEventResult.uuid}")
                Log.v("Presence", "Presence timeToken: ${pnPresenceEventResult.timetoken}")
                Log.v("Presence", "Presence occupancy: ${pnPresenceEventResult.occupancy}")
            }

            override fun message(pubnub: PubNub, pnMessageResult: PNMessageResult) {
                Log.v("Message", "Message payload: ${pnMessageResult.message}")
                Log.v("Message", "Message channel: ${pnMessageResult.channel}")
                Log.v("Message", "Message publisher: ${pnMessageResult.publisher}")
                Log.v("Message", "Message timeToken: ${pnMessageResult.timetoken}")

                // Deliver a message to predefined variable
                message = pnMessageResult.message
            }

        })

        // Add publishing to button
        val btnPublish : Button = findViewById<Button>(R.id.btnPublish)
        btnPublish.setOnClickListener(View.OnClickListener {
            publishing(pubNub, filePath)
        })

    } // end of main function

    // create KeyStore
    private fun createKeyStore() : KeyStore {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply {
            load(null)
        }
        return keyStore
    }

    // set Key Spec
    private fun setSpec(alias: String) : KeyGenParameterSpec {
        val parameterSpec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN and KeyProperties.PURPOSE_VERIFY
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(
                KeyProperties.DIGEST_SHA512,
                KeyProperties.DIGEST_SHA256
            )
            .setUserAuthenticationRequired(false)
            .build()
        return parameterSpec
    }

    // set Key Pair Generator
    private fun genKPG(paramSpec : KeyGenParameterSpec) : KeyPairGenerator{
        val kpg : KeyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            "AndroidKeyStore"
        )
        kpg.initialize(paramSpec)
        return kpg
    }

    // generate Public Key Pair for user
    private fun genKP(kpg : KeyPairGenerator) : KeyPair {
        val PKP = kpg.genKeyPair()
        val aliases : Enumeration<String> = keyStore.aliases()
        return PKP
    }

    // initialize KeyStore and user Key
    fun initKey(alias: String): KeyPair {
        keyStore = createKeyStore()
        val keySpec = setSpec(alias)
        val kpg = genKPG(keySpec)
        val userKey = genKP(kpg)
        return userKey
    }

    // generate address for user
    fun genAddress(keyStore: KeyStore, alias: String) : String{
        val cert : Certificate = keyStore.getCertificate(alias)
        Log.d("KeyCertificate", cert.toString())
        val pubKey : ByteArray = cert.publicKey.encoded
        // Kotlin이나 JAVA에서 RIPEMD-160을 지원하는 마땅한 함수가 없어서, bitcoinj 라이브러리 함수지만 사용하였다.
        // hash를 2번 이용하여 주소를 더욱 랜덤하게 만든다.
        val address = Base58.encode(sha256hash160(hash(pubKey)))
        // batse58로 encoding 한다.
        Log.d("Address", address.toString())
//        여러.. 실패들
//        Log.d("KeyHash", pubKey.toString())
//        val md : MessageDigest = MessageDigest.getInstance("SHA-256")
//        md.update(pubKey)
//        Log.d("KeyHash", md.digest().toString())
//        val keyHash = String(Base64.encode(md.digest(), 0))
//        Log.d("KeyHash", keyHash)
        return address
    }

    // function for P2PKH script
    fun P2PKH(sign : ByteArray, pubKey : PublicKey, PK_HASH : String, tranx: ByteArray) : Boolean {
        val hashedPubKey : String = OP_HASH160(pubKey)
        val eqalVerify : Boolean = OP_EQUALVERIFY(PK_HASH, hashedPubKey)
        val checkSig : Boolean = OP_CHECKSIG(pubKey, sign, tranx)

        return eqalVerify and checkSig
    }

    // OP_DUP function
    private fun OP_DUP(pubKey: PublicKey) : PublicKey{
        return pubKey
    }

    // OP_HASH_160 function
    // Use base58 encoding, Convert to String
    private fun OP_HASH160(pubKey: PublicKey) : String {
        return Base58.encode(sha256hash160(hash(pubKey.encoded)))
    }
    // OP_EQUALVERIFY
    private fun OP_EQUALVERIFY(PK_HASH1 : String, PK_HASH2 : String) : Boolean {
        return PK_HASH1.contentEquals(PK_HASH2)
    }

    // OP_CHECKSIG
    // transaction은 임의로 ByteArray type으로 해두었다.
    private fun OP_CHECKSIG(pubKey: PublicKey, sign: ByteArray, tranx : ByteArray) : Boolean {
        val valid: Boolean = Signature.getInstance("SHA256withECDSA").run {
            initVerify(pubKey)
            update(tranx)
            verify(sign)
        }
        return valid
    }

    // json 파일 읽기
    fun readJson(fileName: String): JSONObject {
        val json = assets.open(fileName).reader().readText()
        return JSONObject(json).getJSONObject("data")
    }

    // Publish Message to a channel
    // Basic usage of publishing a message to a channel
    fun publishing(pubNub: PubNub, message : String) {//filePath : String){
        pubNub.publish(
            message = assets.open(filePath).reader().readText(),
            channel = channelId,
            shouldStore = true,
            ttl = 24
        ).async { result, status ->
            if (!status.error) {
                Log.v("Publishing", "Publish timeToken ${result!!.timetoken}")
            }
            Log.v("Publishing", "Status code ${status.statusCode}")
        }
    }

    fun inputInfo(output_txid : Int, output_index : Int, input_index : Int) : String{
        return """"{
            |output_txid" : $output_txid,
            |"output_index" : $output_index,
            |"input_index" : $input_index
            |},
        """.trimMargin()
    }

    fun outputInfo(address : String, gruut :Int, output_index: Int) : String{
        val pubKeyHash = genPubKeyHash(alias, keyStore)
        val signature = genSign()
        return """{
            |"address" : $address,
            |"gruut" : $gruut,
            |"signature : ,
            |"script_code : "76a914${pubKeyHash}88ac",
        """.trimMargin()
    }

    fun genPubKeyHash(alias : String, keyStore: KeyStore) : String {
        // get information of certain key pair
        val cert : Certificate = keyStore.getCertificate(alias)
        val pubKey = cert.publicKey
        return OP_HASH160(pubKey)
    }

    fun genSign(address: String, alias: String, keyStore: KeyStore) : String {
        val entry : KeyStore.Entry = keyStore.getEntry(alias, null)
        val signature : ByteArray = Signature.getInstance("SHA256withECDSA").run {
            initSign(entry.privateKey)
        }
    }

    fun genTranx(input_data : List<InputData>, output_data : List<OutputData>, pubKey: PublicKey){
        var message : String = """{"unspent_output" : [
            |{
            |   "input_number" : $input_data.size,
            |   "inputs" : [
            |   """.trimMargin()
        for (info in input_data){
            message += inputInfo(info.output_txid, info.input_index, info.input_index)
            message += """,
                |
            """.trimMargin()
        }
        message.replace(".$".toRegex(), "")
        message += """
            |],
            |"output_number : $output_data.size,
            |"outputs" : [
            |
        """.trimMargin()

        for (info in output_data){
            message += outputInfo()
            message += """,
                |
            """.trimMargin()
        }
        message.replace(".$".toRegex(), "")

        message += """
            |]
            |
        """.trimMargin()
    }

}