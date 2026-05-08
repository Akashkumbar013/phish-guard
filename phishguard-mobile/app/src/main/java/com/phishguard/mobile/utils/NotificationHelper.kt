package com.phishguard.mobile.utils

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.os.Build
import androidx.core.app.NotificationCompat
import com.phishguard.mobile.scanner.ThreatResult

class NotificationHelper(private val context: Context) {

    private val CHANNEL_ID = "PhishGuardThreats"
    private val CHANNEL_NAME = "PhishGuard SMS Alerts"

    init {
        createNotificationChannel()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val importance = NotificationManager.IMPORTANCE_HIGH
            val channel = NotificationChannel(CHANNEL_ID, CHANNEL_NAME, importance).apply {
                description = "Alerts for suspicious or phishing SMS messages"
            }
            val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            notificationManager.createNotificationChannel(channel)
        }
    }

    fun showThreatNotification(sender: String, result: ThreatResult) {
        if (result.category == "SAFE") return

        val icon = if (result.category == "PHISHING") "🚨" else "⚠"
        val title = "$icon PhishGuard: ${result.category} SMS detected"
        val content = "From: $sender\nScore: ${result.score}/100\nSignals: ${result.signals.joinToString(", ")}"

        val builder = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle(title)
            .setContentText("Tap to view threat details")
            .setStyle(NotificationCompat.BigTextStyle().bigText(content))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)

        val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        notificationManager.notify(System.currentTimeMillis().toInt(), builder.build())
    }
}
