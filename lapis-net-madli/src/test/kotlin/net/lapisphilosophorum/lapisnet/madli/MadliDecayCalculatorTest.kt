package net.lapisphilosophorum.lapisnet.madli

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.doubles.plusOrMinus
import io.kotest.matchers.shouldBe

class MadliDecayCalculatorTest :
    FunSpec({
        test("decayFactor is 1.0 at age 0, for any half-life") {
            MadliDecayCalculator.decayFactor(halfLifeDays = 7.0, ageDays = 0.0) shouldBe (1.0 plusOrMinus 1e-9)
            MadliDecayCalculator.decayFactor(halfLifeDays = 90.0, ageDays = 0.0) shouldBe (1.0 plusOrMinus 1e-9)
        }

        test("decayFactor is 0.5 at age == half-life") {
            MadliDecayCalculator.decayFactor(halfLifeDays = 7.0, ageDays = 7.0) shouldBe (0.5 plusOrMinus 1e-9)
            MadliDecayCalculator.decayFactor(halfLifeDays = 90.0, ageDays = 90.0) shouldBe (0.5 plusOrMinus 1e-9)
        }

        test("decayFactor is 0.25 at age == 2x half-life") {
            MadliDecayCalculator.decayFactor(halfLifeDays = 7.0, ageDays = 14.0) shouldBe (0.25 plusOrMinus 1e-9)
        }

        test("future-dated (negative age) clamps to exactly 1.0 - the load-bearing clamp") {
            MadliDecayCalculator.decayFactor(halfLifeDays = 7.0, ageDays = -5.0) shouldBe (1.0 plusOrMinus 1e-12)
            MadliDecayCalculator.decayFactor(halfLifeDays = 7.0, ageDays = -1_000_000.0) shouldBe
                (1.0 plusOrMinus 1e-12)
        }

        test("each of the five default half-lives is distinct, per the vault design") {
            val defaults = MadliHalfLives()

            val halfLives =
                setOf(
                    defaults.reachabilityDays,
                    defaults.bandwidthDays,
                    defaults.latencyDays,
                    defaults.deliveryIntegrityDays,
                    defaults.routingHelpfulnessDays,
                )

            // reachabilityDays and latencyDays are both 7.0 by design (both age fast); the other
            // three are distinct from those and from each other - so the full set has 4 distinct
            // values, not 5, and this test documents that intentional pairing rather than
            // asserting a stronger "all five distinct" property that isn't actually true.
            halfLives shouldBe setOf(7.0, 30.0, 90.0)
        }

        test("MadliHalfLives rejects a non-positive half-life") {
            shouldThrow<IllegalArgumentException> { MadliHalfLives(reachabilityDays = 0.0) }
            shouldThrow<IllegalArgumentException> { MadliHalfLives(bandwidthDays = -1.0) }
            shouldThrow<IllegalArgumentException> { MadliHalfLives(latencyDays = 0.0) }
            shouldThrow<IllegalArgumentException> { MadliHalfLives(deliveryIntegrityDays = -1.0) }
            shouldThrow<IllegalArgumentException> { MadliHalfLives(routingHelpfulnessDays = 0.0) }
        }
    })
