"""The analytics page: what Privacy Shield has blocked, over any period, from the all-time
history dns_proxy.Stats keeps. Charts are drawn with QPainter, so there's no charting
dependency."""
import datetime, html, math, os

from PyQt5.QtCore import QPointF, QRectF, Qt, QTimer
from PyQt5.QtGui import QColor, QFont, QFontMetrics, QPainter, QPainterPath, QPalette, QPen
from PyQt5.QtWidgets import (QApplication, QButtonGroup, QDialog, QFrame, QGridLayout, QHBoxLayout,
                             QHeaderView, QLabel, QPushButton, QStackedWidget, QTableWidget,
                             QTableWidgetItem, QToolTip, QVBoxLayout, QWidget)

import dns_proxy

PERIODS = [("today", "Today"), ("30d", "30 days"), ("12m", "12 months"), ("all", "All time")]
UNIT_TITLE = {"hour": "per hour", "day": "per day", "month": "per month"}


class Theme:
    """Chart colors for the light or dark system appearance (one validated blue per mode)."""

    LIGHT = dict(page="#f9f9f7", surface="#fcfcfb", primary="#0b0b0b", secondary="#52514e",
                 muted="#898781", grid="#e1e0d9", axis="#c3c2b7", series="#2a78d6",
                 border="rgba(11,11,11,0.10)")
    DARK = dict(page="#0d0d0d", surface="#1a1a19", primary="#ffffff", secondary="#c3c2b7",
                muted="#898781", grid="#2c2c2a", axis="#383835", series="#3987e5",
                border="rgba(255,255,255,0.10)")

    def __init__(self):
        self.dark = QApplication.palette().color(QPalette.Window).lightness() < 128
        for name, value in (self.DARK if self.dark else self.LIGHT).items():
            setattr(self, name, value)

    def color(self, name):
        return QColor(getattr(self, name))

    def hover(self):
        """The series color, lifted a little for the mark under the pointer."""
        return self.color("series").lighter(125 if self.dark else 115)


def compact(n):
    """1,284 / 12.9K / 4.2M"""
    if n < 10000:
        return f"{n:,}"
    for size, suffix in ((1e9, "B"), (1e6, "M"), (1e3, "K")):
        if n >= size:
            return f"{n / size:.1f}".rstrip("0").rstrip(".") + suffix
    return str(n)


def share(part, whole):
    return f"{100 * part / whole:.0f}%" if whole else "–"


def nice_ticks(top, steps=4):
    """0 plus evenly spaced round numbers that cover top: 0 / 250 / 500 / 750."""
    raw = max(top, 1) / steps
    magnitude = 10 ** math.floor(math.log10(raw))
    step = max(1, next(m * magnitude for m in (1, 2, 5, 10) if m * magnitude >= raw))
    return [i * step for i in range(math.ceil(max(top, 1) / step) + 1)]


def _font(px, bold=False):
    font = QFont()
    font.setPixelSize(px)
    font.setBold(bold)
    return font


def _bar_path(x, y, w, h, radius=4.0, rounded="top"):
    """A bar with 4px rounded corners on its data end and square corners at the baseline."""
    r = min(radius, w / 2, h / 2) if rounded == "top" else min(radius, h / 2, w / 2)
    path = QPainterPath()
    if rounded == "top":  # column growing up from the baseline
        path.moveTo(x, y + h)
        path.lineTo(x, y + r)
        path.quadTo(x, y, x + r, y)
        path.lineTo(x + w - r, y)
        path.quadTo(x + w, y, x + w, y + r)
        path.lineTo(x + w, y + h)
    else:  # bar growing right from the left edge
        path.moveTo(x, y)
        path.lineTo(x + w - r, y)
        path.quadTo(x + w, y, x + w, y + r)
        path.lineTo(x + w, y + h - r)
        path.quadTo(x + w, y + h, x + w - r, y + h)
        path.lineTo(x, y + h)
    path.closeSubpath()
    return path


class ColumnChart(QWidget):
    """One series as columns: hairline grid, round ticks, a label on the peak, and a tooltip for
    whichever column the pointer is over (the whole column slot is the target, not just the bar)."""

    def __init__(self, theme):
        super().__init__()
        self.theme = theme
        self.rows = []  # (axis label or "", tooltip title, blocked, lookups)
        self.hover = None
        self.setMouseTracking(True)
        self.setMinimumHeight(190)

    def set_rows(self, rows):
        self.rows = rows
        self.hover = None
        self.update()

    def _layout(self):
        t = nice_ticks(max((r[2] for r in self.rows), default=0))
        left = QFontMetrics(_font(11)).horizontalAdvance(f"{t[-1]:,}") + 10
        plot = QRectF(left, 18, self.width() - left - 4, self.height() - 18 - 22)
        return t, plot, plot.width() / max(len(self.rows), 1)

    def paintEvent(self, _event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        th = self.theme
        ticks, plot, slot = self._layout()
        top = ticks[-1]
        p.setFont(_font(11))
        for value in ticks:  # hairline grid, baseline one step stronger
            y = round(plot.bottom() - value / top * plot.height()) + 0.5
            p.setPen(QPen(th.color("axis" if value == 0 else "grid"), 1))
            p.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y))
            p.setPen(th.color("muted"))
            p.drawText(QRectF(0, y - 8, plot.left() - 8, 16), Qt.AlignRight | Qt.AlignVCenter, f"{value:,}")

        width = max(2.0, min(24.0, slot - 2))  # <= 24px, and a 2px surface gap between bars
        peak = max(range(len(self.rows)), key=lambda i: self.rows[i][2], default=None)
        for i, (_, _, blocked, _) in enumerate(self.rows):
            if blocked <= 0:
                continue
            h = blocked / top * plot.height()
            x = plot.left() + i * slot + (slot - width) / 2
            p.fillPath(_bar_path(x, plot.bottom() - h, width, h),
                       th.hover() if i == self.hover else th.color("series"))

        fm = QFontMetrics(_font(11))
        if peak is not None and self.rows[peak][2] > 0:  # label the extreme, not every column
            value = compact(self.rows[peak][2])
            h = self.rows[peak][2] / top * plot.height()
            cx = plot.left() + (peak + 0.5) * slot
            wtext = fm.horizontalAdvance(value)
            x = min(max(cx - wtext / 2, plot.left()), plot.right() - wtext)
            p.setPen(th.color("secondary"))
            p.drawText(QRectF(x, plot.bottom() - h - 17, wtext + 1, 15), Qt.AlignCenter, value)

        labels = [(i, r[0]) for i, r in enumerate(self.rows) if r[0]]
        widest = max((fm.horizontalAdvance(text) for _, text in labels), default=0)
        # When every column has a label, skip some rather than let them collide, always keeping
        # the newest. (Hours only label every 6th column, which leaves plenty of room.)
        every = max(1, math.ceil((widest + 12) / slot)) if len(labels) == len(self.rows) else 1
        p.setPen(th.color("muted"))
        for i, text in labels:
            if (len(self.rows) - 1 - i) % every:
                continue
            cx = plot.left() + (i + 0.5) * slot
            x = min(max(cx - widest / 2 - 6, 0), self.width() - widest - 12)
            p.drawText(QRectF(x, plot.bottom() + 5, widest + 12, 16), Qt.AlignCenter, text)

        if not any(r[2] for r in self.rows):
            p.setFont(_font(13))
            p.drawText(plot, Qt.AlignCenter, "Nothing blocked in this period yet")

    def mouseMoveEvent(self, event):
        _, plot, slot = self._layout()
        i = int((event.x() - plot.left()) // slot) if plot.left() <= event.x() < plot.right() else None
        i = i if i is not None and 0 <= i < len(self.rows) else None
        if i != self.hover:
            self.hover = i
            self.update()
            if i is None:
                QToolTip.hideText()
            else:
                _, title, blocked, lookups = self.rows[i]
                QToolTip.showText(event.globalPos(),
                                  f"{html.escape(title)}<br><b>{blocked:,}</b> trackers blocked"
                                  f"<br><b>{lookups:,}</b> lookups, {share(blocked, lookups)} blocked",
                                  self)

    def leaveEvent(self, _event):
        self.hover = None
        self.update()


class BarList(QWidget):
    """Ranked horizontal bars: name on the left, bar, value at the tip."""

    ROW = 24

    def __init__(self, theme, empty="Nothing blocked yet"):
        super().__init__()
        self.theme = theme
        self.rows = []  # (name, count)
        self.empty = empty
        self.hover = None
        self.setMouseTracking(True)
        self.setMinimumHeight(self.ROW * 10)

    def set_rows(self, rows):
        self.rows = rows
        self.hover = None
        self.update()

    def paintEvent(self, _event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        th = self.theme
        p.setFont(_font(12))
        fm = QFontMetrics(_font(12))
        if not self.rows:
            p.setPen(th.color("muted"))
            p.drawText(QRectF(0, 0, self.width(), self.ROW), Qt.AlignLeft | Qt.AlignVCenter, self.empty)
            return
        # As wide as the longest name needs, up to 62% of the row; bars get the rest.
        name_w = min(max(fm.horizontalAdvance(name) for name, _ in self.rows) + 12, self.width() * 0.62)
        value_w = max(fm.horizontalAdvance(compact(n)) for _, n in self.rows) + 8
        track = self.width() - name_w - value_w
        biggest = max(n for _, n in self.rows)
        for i, (name, n) in enumerate(self.rows):
            y = i * self.ROW
            p.setPen(th.color("primary"))
            p.drawText(QRectF(0, y, name_w - 10, self.ROW), Qt.AlignLeft | Qt.AlignVCenter,
                       fm.elidedText(name, Qt.ElideMiddle, int(name_w - 10)))
            length = max(3.0, n / biggest * track)
            p.fillPath(_bar_path(name_w, y + (self.ROW - 10) / 2, length, 10, rounded="right"),
                       th.hover() if i == self.hover else th.color("series"))
            p.setPen(th.color("secondary"))
            p.drawText(QRectF(name_w + length + 6, y, value_w, self.ROW), Qt.AlignLeft | Qt.AlignVCenter,
                       compact(n))

    def mouseMoveEvent(self, event):
        i = event.y() // self.ROW
        i = i if 0 <= i < len(self.rows) else None
        if i != self.hover:
            self.hover = i
            self.update()
            if i is None:
                QToolTip.hideText()
            else:
                name, n = self.rows[i]
                QToolTip.showText(event.globalPos(), f"{html.escape(name)}<br><b>{n:,}</b> blocked", self)

    def leaveEvent(self, _event):
        self.hover = None
        self.update()


class StatTile(QFrame):
    """label, value, and an optional note underneath."""

    def __init__(self, label):
        super().__init__()
        self.setObjectName("tile")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(2)
        self.label = QLabel(label, objectName="tileLabel")
        self.value = QLabel("–", objectName="tileValue")
        self.note = QLabel("", objectName="tileNote")
        for widget in (self.label, self.value, self.note):
            widget.setTextFormat(Qt.PlainText)
            layout.addWidget(widget)

    def set(self, value, note=""):
        self.value.setText(value)
        self.note.setText(note)


class AnalyticsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Privacy Shield analytics")
        self.resize(720, 760)
        self.theme = th = Theme()
        self.setStyleSheet(f"""
            QDialog {{ background: {th.page}; }}
            QLabel {{ color: {th.primary}; }}
            QLabel#title {{ font-size: 13px; font-weight: 600; }}
            QLabel#tileLabel {{ color: {th.secondary}; font-size: 12px; }}
            QLabel#tileValue {{ font-size: 22px; font-weight: 600; }}
            QLabel#tileNote, QLabel#footnote {{ color: {th.muted}; font-size: 11px; }}
            QFrame#tile, QFrame#card {{ background: {th.surface}; border: 1px solid {th.border};
                                        border-radius: 8px; }}
            QPushButton[segment="true"] {{ color: {th.secondary}; background: {th.surface};
                border: 1px solid {th.border}; border-radius: 6px; padding: 4px 12px; }}
            QPushButton[segment="true"]:checked {{ color: {th.surface}; background: {th.primary}; }}
            QTableWidget {{ background: {th.surface}; color: {th.primary}; border: none;
                            font-size: 12px; }}
            QTableWidget::item {{ border-bottom: 1px solid {th.grid}; padding: 0 6px; }}
            QHeaderView::section {{ background: {th.surface}; color: {th.secondary}; border: none;
                                    border-bottom: 1px solid {th.axis}; padding: 4px 6px;
                                    font-size: 12px; }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 12)
        layout.setSpacing(12)

        # One filter row above everything it scopes
        filters = QHBoxLayout()
        self.periods = QButtonGroup(self)
        for i, (key, text) in enumerate(PERIODS):
            button = QPushButton(text, checkable=True)
            button.setProperty("segment", True)
            self.periods.addButton(button, i)
            filters.addWidget(button)
        self.periods.buttonClicked.connect(lambda _: self.refresh())
        filters.addStretch()
        self.table_button = QPushButton("Table", checkable=True)
        self.table_button.setProperty("segment", True)
        self.table_button.toggled.connect(lambda on: self.stack.setCurrentIndex(1 if on else 0))
        filters.addWidget(self.table_button)
        layout.addLayout(filters)

        tiles = QHBoxLayout()
        self.tiles = {key: StatTile(label) for key, label in (
            ("blocked", "Trackers blocked"), ("lookups", "Lookups"),
            ("share", "Share blocked"), ("cache", "Answered from cache"))}
        for tile in self.tiles.values():
            tiles.addWidget(tile)
        layout.addLayout(tiles)

        card = QFrame(objectName="card")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(14, 12, 14, 10)
        self.chart_title = QLabel("", objectName="title")
        card_layout.addWidget(self.chart_title)
        self.chart = ColumnChart(th)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Period", "Trackers blocked", "Lookups", "Share blocked"])
        self.table.verticalHeader().hide()
        self.table.verticalHeader().setDefaultSectionSize(24)
        self.table.setShowGrid(False)  # hairline row dividers come from the stylesheet
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        for column in range(4):  # headers line up with their columns
            self.table.horizontalHeaderItem(column).setTextAlignment(
                (Qt.AlignLeft if column == 0 else Qt.AlignRight) | Qt.AlignVCenter)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.stack = QStackedWidget()
        self.stack.addWidget(self.chart)
        self.stack.addWidget(self.table)
        card_layout.addWidget(self.stack)
        layout.addWidget(card, 1)

        lists = QGridLayout()
        lists.setHorizontalSpacing(12)
        self.top = BarList(th)
        self.by_list = BarList(th)
        for column, (title, widget) in enumerate((("Top blocked domains", self.top),
                                                  ("Blocked by list", self.by_list))):
            box = QFrame(objectName="card")
            box_layout = QVBoxLayout(box)
            box_layout.setContentsMargins(14, 12, 14, 10)
            box_layout.addWidget(QLabel(title, objectName="title"))
            box_layout.addWidget(widget)
            lists.addWidget(box, 0, column)
        layout.addLayout(lists)

        self.footnote = QLabel("", objectName="footnote")
        self.footnote.setWordWrap(True)
        layout.addWidget(self.footnote)

        self.periods.button(1).setChecked(True)  # 30 days
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh)

    def showEvent(self, event):
        self.refresh()
        self.timer.start(5000)
        super().showEvent(event)

    def hideEvent(self, event):
        self.timer.stop()  # no work while nobody's looking
        super().hideEvent(event)

    def refresh(self):
        key = PERIODS[self.periods.checkedId()][0]
        r = dns_proxy.stats.report(key)
        unit = r["unit"]
        spans_years = r["series"] and r["series"][0][0].year != r["series"][-1][0].year

        def axis_label(start):
            if unit == "hour":
                return start.strftime("%-I %p") if start.hour % 6 == 0 else ""
            if unit == "day":
                return start.strftime("%b %-d")
            return start.strftime("%b %Y" if spans_years and unit == "month" and key == "all" else "%b")

        def title(start):
            if unit == "hour":
                return f"{start:%-I %p} to {start + datetime.timedelta(hours=1):%-I %p}"
            return start.strftime("%a, %b %-d" if unit == "day" else "%B %Y")

        rows = [(axis_label(s), title(s), blocked, lookups) for s, blocked, lookups in r["series"]]
        self.chart.set_rows(rows)
        self.chart_title.setText(f"Trackers blocked {UNIT_TITLE[unit]}")
        self.table.setRowCount(len(rows))
        for i, (_, name, blocked, lookups) in enumerate(rows):
            for column, text in enumerate((name, f"{blocked:,}", f"{lookups:,}", share(blocked, lookups))):
                item = QTableWidgetItem(text)
                item.setTextAlignment((Qt.AlignLeft if column == 0 else Qt.AlignRight) | Qt.AlignVCenter)
                self.table.setItem(i, column, item)

        since = r["since"].strftime("%b %-d, %Y")
        self.tiles["blocked"].set(compact(r["blocked"]), f"since {since}" if key == "all" else "")
        self.tiles["lookups"].set(compact(r["lookups"]))
        self.tiles["share"].set(share(r["blocked"], r["lookups"]), "of all lookups")
        self.tiles["cache"].set(share(r["cached"], r["allowed"]), "of allowed lookups")
        self.top.set_rows(r["top"])
        self.by_list.set_rows(r["lists"])
        self.footnote.setText(
            f"Counting since {since}. Only blocked domains are recorded by name, never the sites you "
            f"visit. Saved in {dns_proxy.STATS_DB.replace(os.path.expanduser('~'), '~')}.")
