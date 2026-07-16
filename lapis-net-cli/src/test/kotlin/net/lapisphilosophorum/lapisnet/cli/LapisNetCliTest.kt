package net.lapisphilosophorum.lapisnet.cli

import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.core.spec.style.FunSpec

class LapisNetCliTest :
    FunSpec({
        test("main runs without throwing") {
            shouldNotThrowAny { main() }
        }
    })
