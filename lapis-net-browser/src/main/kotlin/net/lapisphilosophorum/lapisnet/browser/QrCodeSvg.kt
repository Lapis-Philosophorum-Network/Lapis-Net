package net.lapisphilosophorum.lapisnet.browser

import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel

/**
 * Renders a string as a minimal, self-contained QR-code SVG - server-side, no `java.awt`, no
 * raster. One black `<path>` of module squares on a white background. Deterministic: identical
 * input always yields byte-identical SVG. Used by `GET /api/connect/qr.svg` so a second user can
 * scan the local node's `lapisnet://` connect URI with a phone camera instead of copy-pasting a
 * multiaddr.
 */
object QrCodeSvg {
    private const val MODULE_PX = 8
    private const val QUIET_ZONE_MODULES = 4

    fun render(payload: String): String {
        val hints =
            mapOf(
                EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M,
                EncodeHintType.MARGIN to QUIET_ZONE_MODULES,
            )
        val matrix = QRCodeWriter().encode(payload, BarcodeFormat.QR_CODE, 0, 0, hints)
        val w = matrix.width
        val h = matrix.height
        val sizePx = w * MODULE_PX
        val path =
            buildString {
                for (y in 0 until h) {
                    for (x in 0 until w) {
                        if (matrix.get(x, y)) {
                            append("M${x * MODULE_PX} ${y * MODULE_PX}h$MODULE_PX v$MODULE_PX h-${MODULE_PX}z ")
                        }
                    }
                }
            }
        val svgOpenTag =
            """<svg xmlns="http://www.w3.org/2000/svg" width="$sizePx" height="$sizePx" """ +
                """viewBox="0 0 $sizePx $sizePx" shape-rendering="crispEdges">"""
        val background = """<rect width="$sizePx" height="$sizePx" fill="#ffffff"/>"""
        val pathElement = """<path d="$path" fill="#000000"/>"""
        return "$svgOpenTag$background$pathElement</svg>"
    }
}
