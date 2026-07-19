package net.lapisphilosophorum.lapisnet.madli

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

private fun testCid(seed: Byte): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { seed })

class MadliReplicationPolicyTest :
    FunSpec({
        test("NEVER never replicates, regardless of the candidate") {
            val candidate =
                ReplicationCandidate(
                    cid = testCid(1),
                    authorVeritasMicros = 1_000_000,
                    socialResonance = 1.0,
                    currentProviderCount = 0,
                )

            MadliReplicationPolicies.NEVER.shouldReplicate(candidate) shouldBe false
        }

        test("underServedImportant replicates high-Veritas-author under-served content") {
            val policy =
                MadliReplicationPolicies.underServedImportant(
                    minAuthorVeritasMicros = 800_000,
                    minSocialResonance = 0.8,
                    maxProviderCount = 2,
                )
            val candidate =
                ReplicationCandidate(
                    cid = testCid(1),
                    authorVeritasMicros = 900_000,
                    socialResonance = 0.1,
                    currentProviderCount = 1,
                )

            policy.shouldReplicate(candidate) shouldBe true
        }

        test("underServedImportant replicates high-resonance under-served content even with a low-standing author") {
            val policy =
                MadliReplicationPolicies.underServedImportant(
                    minAuthorVeritasMicros = 800_000,
                    minSocialResonance = 0.8,
                    maxProviderCount = 2,
                )
            val candidate =
                ReplicationCandidate(
                    cid = testCid(1),
                    authorVeritasMicros = 0,
                    socialResonance = 0.95,
                    currentProviderCount = 0,
                )

            policy.shouldReplicate(candidate) shouldBe true
        }

        test("underServedImportant declines important content that is already well-served") {
            val policy =
                MadliReplicationPolicies.underServedImportant(
                    minAuthorVeritasMicros = 800_000,
                    minSocialResonance = 0.8,
                    maxProviderCount = 2,
                )
            val candidate =
                ReplicationCandidate(
                    cid = testCid(1),
                    authorVeritasMicros = 900_000,
                    socialResonance = 0.9,
                    currentProviderCount = 10,
                )

            policy.shouldReplicate(candidate) shouldBe false
        }

        test("underServedImportant declines under-served content that is neither high-standing nor high-resonance") {
            val policy =
                MadliReplicationPolicies.underServedImportant(
                    minAuthorVeritasMicros = 800_000,
                    minSocialResonance = 0.8,
                    maxProviderCount = 2,
                )
            val candidate =
                ReplicationCandidate(
                    cid = testCid(1),
                    authorVeritasMicros = 10_000,
                    socialResonance = 0.05,
                    currentProviderCount = 0,
                )

            policy.shouldReplicate(candidate) shouldBe false
        }

        test("underServedImportant boundary: exactly at the thresholds counts as satisfying them") {
            val policy =
                MadliReplicationPolicies.underServedImportant(
                    minAuthorVeritasMicros = 800_000,
                    minSocialResonance = 0.8,
                    maxProviderCount = 2,
                )
            val candidate =
                ReplicationCandidate(
                    cid = testCid(1),
                    authorVeritasMicros = 800_000,
                    socialResonance = 0.0,
                    currentProviderCount = 2,
                )

            policy.shouldReplicate(candidate) shouldBe true
        }
    })
