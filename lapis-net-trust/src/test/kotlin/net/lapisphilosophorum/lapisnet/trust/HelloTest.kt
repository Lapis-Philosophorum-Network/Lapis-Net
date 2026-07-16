package net.lapisphilosophorum.lapisnet.trust

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

class HelloTest :
    FunSpec({
        test("greet returns the expected message") {
            Hello.greet() shouldBe "Hello from lapis-net-trust"
        }
    })
