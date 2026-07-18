package net.lapisphilosophorum.lapisnet.browser

import io.ipfs.cid.Cid
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey

/**
 * A raw candidate for [TimelineBuilder.build] to score and sort - one per tracked
 * [PostAnnouncement]/[IndexedPost]. [confirmers] is always `emptyList()` in this wave - see
 * [CredibilityCalculator.credibility]'s doc comment.
 */
data class TimelineCandidate(
    val cid: Cid,
    val author: Secp256k1PublicKey,
    val publishedAtEpochSeconds: Long,
    val confirmers: List<Secp256k1PublicKey> = emptyList(),
)

/**
 * A [TimelineCandidate] after [TimelineBuilder.build] has scored it: its resolved
 * [credibility][Credibility], its accumulated Virtus/LTR sort-weight ([ltrWeightMsat]), and whether
 * it falls below the caller's credibility filter threshold ([filteredOut]).
 */
data class TimelineEntry(
    val cid: Cid,
    val author: Secp256k1PublicKey,
    val publishedAtEpochSeconds: Long,
    val credibility: Credibility,
    val ltrWeightMsat: Double,
    val ltrRecordCount: Int,
    val filteredOut: Boolean,
)
