package net.lapisphilosophorum.lapisnet.browser

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldStartWith

class QrCodeSvgTest :
    FunSpec({
        test("render output starts with <svg and contains a <path element") {
            val svg = QrCodeSvg.render("lapisnet://connect?maddr=%2Fip4%2F203.0.113.10%2Ftcp%2F4001&pk=abc")

            svg shouldStartWith "<svg"
            svg shouldContain "<path"
        }

        test("render is deterministic for identical input") {
            val payload = "lapisnet://connect?maddr=%2Fip4%2F203.0.113.10%2Ftcp%2F4001&pk=abc"

            QrCodeSvg.render(payload) shouldBe QrCodeSvg.render(payload)
        }
    })
