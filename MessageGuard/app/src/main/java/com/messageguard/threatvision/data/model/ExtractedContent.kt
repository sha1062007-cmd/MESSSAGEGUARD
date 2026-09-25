package com.messageguard.threatvision.data.model

data class ExtractedContent(
    val rawText: String,
    val urls: List<String> = emptyList(),
    val phoneNumbers: List<String> = emptyList(),
    val emails: List<String> = emptyList()
)
