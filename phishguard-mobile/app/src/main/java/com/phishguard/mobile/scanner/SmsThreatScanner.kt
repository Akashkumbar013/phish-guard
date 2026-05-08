package com.phishguard.mobile.scanner

data class ThreatResult(
    val isPhishing: Boolean,
    val score: Int,
    val category: String, // SAFE, SUSPICIOUS, PHISHING
    val signals: List<String>
)

class SmsThreatScanner {

    private val urgencyPatterns = listOf(
        "urgent", "immediately", "expires", "suspended", "action required", 
        "final warning", "10 mins", "minutes", "shortlisted", "congratulations"
    ).map { it.toRegex(RegexOption.IGNORE_CASE) }

    private val authorityPatterns = listOf(
        "ceo", "it support", "admin", "hr", "government", "official", "bank", "kyc"
    ).map { it.toRegex(RegexOption.IGNORE_CASE) }

    private val actionPatterns = listOf(
        "login", "otp", "click here", "verify", "update", "transfer", 
        "wire", "money", "help", "upi", "pay"
    ).map { it.toRegex(RegexOption.IGNORE_CASE) }

    fun scan(text: String): ThreatResult {
        if (text.isBlank()) return ThreatResult(false, 0, "SAFE", emptyList())

        val detectedSignals = mutableListOf<String>()
        var score = 0
        var urgencyCount = 0
        var authorityCount = 0
        var actionCount = 0

        // 1. Check Urgency
        urgencyPatterns.forEach { regex ->
            if (regex.containsMatchIn(text)) {
                if (urgencyCount == 0) {
                    score += 35
                    detectedSignals.add("Urgency Cue: ${regex.pattern}")
                }
                urgencyCount++
            }
        }

        // 2. Check Authority
        authorityPatterns.forEach { regex ->
            if (regex.containsMatchIn(text)) {
                if (authorityCount == 0) {
                    score += 25
                    detectedSignals.add("Authority Impersonation: ${regex.pattern}")
                }
                authorityCount++
            }
        }

        // 3. Check Action
        actionPatterns.forEach { regex ->
            if (regex.containsMatchIn(text)) {
                if (actionCount == 0) {
                    score += 30
                    detectedSignals.add("Dangerous Action: ${regex.pattern}")
                }
                actionCount++
            }
        }

        // 4. Synergies (Combinations)
        val activeVectors = listOf(urgencyCount > 0, authorityCount > 0, actionCount > 0).count { it }
        if (activeVectors == 3) score += 50
        else if (activeVectors == 2) score += 20

        // 5. URL Detection
        val urlRegex = "(https?://[^\\s]+)".toRegex()
        val urls = urlRegex.findAll(text).map { it.value }.toList()
        if (urls.isNotEmpty()) {
            score += 15
            detectedSignals.add("Contains external URL(s)")
            
            // Shortened URL check
            val shortenedPatterns = listOf("bit.ly", "t.co", "tinyurl", "is.gd", "buff.ly")
            urls.forEach { url ->
                if (shortenedPatterns.any { url.contains(it) }) {
                    score += 25
                    detectedSignals.add("Shortened URL: Masking real destination")
                }
            }
        }

        // 6. Newly Registered Domain (NRD) Heuristic
        val suspiciousTlds = setOf("tk", "ml", "ga", "cf", "gq", "pw", "top", "xyz", "icu", "cyou")
        val domainRegex = "([^\\s.]+\\.[^\\s.]+)(?=/|$)".toRegex()
        domainRegex.findAll(text).forEach { match ->
            val domain = match.value
            val tld = domain.substringAfterLast(".")
            if (suspiciousTlds.contains(tld)) {
                score += 25
                detectedSignals.add("Newly Registered Domain Pattern: .$tld")
            }
        }

        // Final score capping and categorization
        val finalScore = score.coerceIn(0, 100)
        
        // Priority logic: Never SAFE if signals exist
        val category = when {
            finalScore >= 61 -> "PHISHING"
            finalScore >= 21 || detectedSignals.isNotEmpty() -> "SUSPICIOUS"
            else -> "SAFE"
        }

        return ThreatResult(
            isPhishing = finalScore >= 61,
            score = if (category != "SAFE" && finalScore <= 20) 21 else finalScore,
            category = category,
            signals = detectedSignals
        )
    }
}
