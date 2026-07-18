package net.lapisphilosophorum.lapisnet.cli

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import kotlin.time.Duration.Companion.seconds

/**
 * Exercises [runMultiNodeTrustPropagationDemo] directly (bypassing [main]'s console output),
 * asserting real correctness rather than just "didn't throw" - a grant announced on node A must
 * propagate through relay node B to node C and resolve to the EXACT granted score, with the
 * trust-graph edge counted as 1 hop (A->C directly), not the 2 network hops (A->B->C) it actually
 * traveled - see [runMultiNodeTrustPropagationDemo]'s doc comment for that distinction.
 */
class MultiNodeTrustPropagationDemoTest :
    FunSpec({
        test(
            "grant announced on A propagates to B and C and resolves to the exact granted score",
        ).config(timeout = 90.seconds) {
            val result = runMultiNodeTrustPropagationDemo(narrate = {})

            result.grantsOnA shouldBe listOf(result.grant) // A's own local index after announce()
            result.grantsOnB shouldBe listOf(result.grant) // relay node durably tracked it too
            result.grantsOnC shouldBe listOf(result.grant) // final endpoint converged

            result.resolvedPathOnC.shouldNotBeNull()
            result.resolvedPathOnC.scoreMicros shouldBe 900_000
            result.resolvedPathOnC.hops shouldBe 1 // trust-graph edge is direct A->C, despite 2 network hops
        }
    })
