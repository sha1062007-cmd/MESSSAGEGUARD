package com.messageguard.threatvision.data.model

enum class ThreatCategory {
    SAFE,
    SPAM,
    PHISHING,
    SPOOFED,
    IMPERSONATION,
    MALWARE,
    BEC,
    FRAUD,
    SUSPICIOUS,
    // Aliases preserved for backwards compatibility with existing models/rules
    SCAM,
    OTP_FRAUD,
    FAKE_JOB,
    BEC_FRAUD,
    SPOOFING
}

enum class ThreatVerdict {
    SAFE,
    WARNING,
    DANGER
}
