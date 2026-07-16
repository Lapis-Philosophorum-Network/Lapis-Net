package net.lapisphilosophorum.lapisnet.test

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

class TestFixturesTest :
    FunSpec({
        test("describe returns the expected message") {
            TestFixtures.describe() shouldBe "Hello from lapis-net-test"
        }
    })
