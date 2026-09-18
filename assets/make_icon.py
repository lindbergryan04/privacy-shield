"""Draws the app icon and writes assets/PrivacyShield.icns. build_app.sh runs this if the .icns
is missing; `python assets/make_icon.py preview.png` writes a single 1024px PNG instead."""
import os, subprocess, sys, tempfile

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PyQt5.QtCore import QRectF, Qt
from PyQt5.QtGui import QColor, QGuiApplication, QImage, QLinearGradient, QPainter, QPainterPath, QPen

HERE = os.path.dirname(os.path.abspath(__file__))


def draw(size):
    """The icon at size x size pixels, drawn on the 1024-unit grid macOS icons use."""
    img = QImage(size, size, QImage.Format_ARGB32)
    img.fill(Qt.transparent)
    p = QPainter(img)
    p.setRenderHint(QPainter.Antialiasing)
    p.scale(size / 1024, size / 1024)

    body = QPainterPath()
    body.addRoundedRect(QRectF(100, 100, 824, 824), 185, 185)
    gradient = QLinearGradient(0, 100, 0, 924)
    gradient.setColorAt(0, QColor("#3A7BFF"))
    gradient.setColorAt(1, QColor("#1B3FA8"))
    p.fillPath(body, gradient)

    shield = QPainterPath()
    shield.moveTo(512, 232)
    shield.cubicTo(590, 290, 670, 312, 742, 316)
    shield.lineTo(742, 520)
    shield.cubicTo(742, 660, 650, 752, 512, 812)
    shield.cubicTo(374, 752, 282, 660, 282, 520)
    shield.lineTo(282, 316)
    shield.cubicTo(354, 312, 434, 290, 512, 232)
    shield.closeSubpath()
    p.fillPath(shield, QColor("white"))

    p.setPen(QPen(QColor("#2356D8"), 64, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
    check = QPainterPath()
    check.moveTo(412, 528)
    check.lineTo(492, 608)
    check.lineTo(626, 452)
    p.drawPath(check)
    p.end()
    return img


def main():
    app = QGuiApplication(sys.argv[:1])  # noqa: F841 (Qt wants one before painting)
    if len(sys.argv) > 1:
        draw(1024).save(sys.argv[1])
        return
    with tempfile.TemporaryDirectory() as tmp:
        iconset = os.path.join(tmp, "PrivacyShield.iconset")
        os.mkdir(iconset)
        for base in (16, 32, 128, 256, 512):
            draw(base).save(os.path.join(iconset, f"icon_{base}x{base}.png"))
            draw(base * 2).save(os.path.join(iconset, f"icon_{base}x{base}@2x.png"))
        out = os.path.join(HERE, "PrivacyShield.icns")
        subprocess.run(["/usr/bin/iconutil", "-c", "icns", iconset, "-o", out], check=True)
    print(f"Wrote {out}")


if __name__ == "__main__":
    main()
