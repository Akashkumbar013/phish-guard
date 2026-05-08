package com.phishguard.mobile.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import android.util.Log
import com.phishguard.mobile.scanner.SmsThreatScanner
import com.phishguard.mobile.utils.NotificationHelper

class SmsReceiver : BroadcastReceiver() {

    private val scanner = SmsThreatScanner()

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Telephony.Sms.Intents.SMS_RECEIVED_ACTION) {
            val messages = Telephony.Sms.Intents.getMessagesFromIntent(intent)
            
            for (sms in messages) {
                val sender = sms.displayOriginatingAddress ?: "Unknown"
                val body = sms.messageBody ?: ""
                
                Log.d("PhishGuard", "Intercepted SMS from $sender: $body")
                
                // 1. Analyze the SMS
                val result = scanner.scan(body)
                
                // 2. Alert user if suspicious or phishing
                if (result.category != "SAFE") {
                    Log.w("PhishGuard", "THREAT DETECTED! Category: ${result.category}, Score: ${result.score}")
                    val notificationHelper = NotificationHelper(context)
                    notificationHelper.showThreatNotification(sender, result)
                } else {
                    Log.i("PhishGuard", "SMS from $sender is Safe.")
                }
            }
        }
    }
}
