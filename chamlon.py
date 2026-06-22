import sys
import os
import random
import cv2
import re, signal, time
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QStackedWidget, QRadioButton, QComboBox,
    QCheckBox, QSlider, QButtonGroup, QScrollArea
)
from PyQt5.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve, QPoint, QParallelAnimationGroup, pyqtSignal, QProcess, QCoreApplication
from PyQt5.QtGui import QMovie, QImage, QPixmap, QFontDatabase, QFont, QColor
from PyQt5.QtMultimediaWidgets import QVideoWidget
from requests import options

class AnimatedStackedWidget(QStackedWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.duration = 250
        self.easing = QEasingCurve.OutCubic
        self._animating = False

    def slide_to_index(self, index, direction="left"):
        if self._animating or index == self.currentIndex():
            return
        if index < 0 or index >= self.count():
            return

        current_widget = self.currentWidget()
        next_widget = self.widget(index)

        w = self.width()
        h = self.height()

        if direction == "left":
            offset_in = QPoint(w, 0)
            offset_out = QPoint(-w, 0)
        else:
            offset_in = QPoint(-w, 0)
            offset_out = QPoint(w, 0)

        next_widget.setGeometry(0, 0, w, h)
        next_widget.move(offset_in)
        next_widget.show()
        next_widget.raise_()

        anim_out = QPropertyAnimation(current_widget, b"pos")
        anim_out.setDuration(self.duration)
        anim_out.setStartValue(QPoint(0, 0))
        anim_out.setEndValue(offset_out)
        anim_out.setEasingCurve(self.easing)

        anim_in = QPropertyAnimation(next_widget, b"pos")
        anim_in.setDuration(self.duration)
        anim_in.setStartValue(offset_in)
        anim_in.setEndValue(QPoint(0, 0))
        anim_in.setEasingCurve(self.easing)

        self._group = QParallelAnimationGroup()
        self._group.addAnimation(anim_out)
        self._group.addAnimation(anim_in)

        self._animating = True

        def on_finished():
            self.setCurrentIndex(index)
            current_widget.move(0, 0)
            self._animating = False

        self._group.finished.connect(on_finished)
        self._group.start()

class ScrambleLabel(QLabel):
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.original_text = text
        self.chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_scramble)
        self.iteration = 0
        self.setMouseTracking(True)
    def enterEvent(self, event):
        self.iteration = 0
        self.timer.start(30)
    def leaveEvent(self, event):
        self.setText(self.original_text)
        self.timer.stop()
    def update_scramble(self):
        new_text = ""
        done = True
        for i, c in enumerate(self.original_text):
            if i < int(self.iteration):
                new_text += c
            else:
                new_text += random.choice(self.chars)
                done = False
        self.setText(new_text)
        if done:
            self.timer.stop()
        else:
            self.iteration += 0.3

class ScrambleButton(QPushButton):
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.original_text = text
        self.chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_scramble)
        self.iteration = 0

    def enterEvent(self, event):
        self.iteration = 0
        self.timer.start(30)
        super().enterEvent(event)

    def leaveEvent(self, event):
        self.setText(self.original_text)
        self.timer.stop()
        super().leaveEvent(event)

    def update_scramble(self):
        new_text = ""
        done = True
        for i, c in enumerate(self.original_text):
            if i < int(self.iteration):
                new_text += c
            else:
                new_text += random.choice(self.chars)
                done = False
        self.setText(new_text)
        if done:
            self.timer.stop()
        else:
            self.iteration += 0.3

class ScrambleLineEdit(QLineEdit):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
        self.real_text = ""
        self.char_iterations = {}
        self.animation_timer = QTimer(self)
        self.animation_timer.timeout.connect(self._tick)

    def keyPressEvent(self, event):
        key = event.key()

        if key == Qt.Key_Backspace:
            if self.real_text:
                self.real_text = self.real_text[:-1]
                pos = len(self.real_text)
                self.char_iterations.pop(pos, None)
                if not self.char_iterations:
                    self.animation_timer.stop()
                self._update_display()

        elif key == Qt.Key_Return or key == Qt.Key_Enter:
            super().keyPressEvent(event)

        elif event.text() and event.text().isprintable():
            char = event.text()
            pos = len(self.real_text)
            self.real_text += char
            self.char_iterations[pos] = 0.0
            self.animation_timer.start(30)

        else:
            super().keyPressEvent(event)

    def _update_display(self):
        """Rebuild display text: scrambled for animating chars, real for settled ones."""
        display = ""
        for i, c in enumerate(self.real_text):
            if i in self.char_iterations:
                display += c if c == " " else random.choice(self.chars)
            else:
                display += c

        self.blockSignals(True)
        self.setText(display)
        self.setCursorPosition(len(display))
        self.blockSignals(False)

    def _tick(self):
        animating = False

        for i in list(self.char_iterations.keys()):
            self.char_iterations[i] += 0.3
            if self.char_iterations[i] >= 1.0:
                del self.char_iterations[i]
            else:
                animating = True

        self._update_display()

        if not animating:
            self.blockSignals(True)
            self.setText(self.real_text)
            self.setCursorPosition(len(self.real_text))
            self.blockSignals(False)
            self.animation_timer.stop()

class StateScrambleButton(QPushButton):
    CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"

    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self._target  = text
        self._state   = "idle"  # idle | connecting | connected
        self._hovered = False
        self._timer   = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._iter            = 0.0
        self._scramble_target = text
        self._after_style_fn  = None

    def set_state(self, state: str):
        self._state = state

    def scramble_to(self, text, style_fn=None):
        self._target          = text
        self._scramble_target = text
        self._after_style_fn  = style_fn
        self._iter            = 0.0
        self._timer.start(30)

    def enterEvent(self, event):
        if self._state == "connecting":
            return super().enterEvent(event)

        self._hovered = True
        if self._state == "connected":
            self._scramble_target = "disconnect"
            self._iter = 0.0
            self._timer.start(30)
            self.setStyleSheet(self._style_disconnect())
        else:
            self._scramble_target = self._target
            self._iter = 0.0
            self._timer.start(30)
        super().enterEvent(event)

    def leaveEvent(self, event):
        if self._state == "connecting":
            return super().leaveEvent(event)

        self._hovered = False
        if self._state == "connected":
            self._scramble_target = "connected"
            self._iter = 0.0
            self._timer.start(30)
            self.setStyleSheet(self._style_connected())
        else:
            self.setText(self._target)
            self._timer.stop()
            if self._after_style_fn:
                self.setStyleSheet(self._after_style_fn())
                self._after_style_fn = None
        super().leaveEvent(event)

    def _tick(self):
        target   = self._scramble_target
        new_text = ""
        done     = True
        for i, c in enumerate(target):
            if c == " ":
                new_text += " "
            elif i < int(self._iter):
                new_text += c
            else:
                new_text += random.choice(self.CHARS)
                done = False
        self.setText(new_text)
        if done:
            self._timer.stop()
            self.setText(target)
            if self._after_style_fn:
                self.setStyleSheet(self._after_style_fn())
                self._after_style_fn = None
        else:
            self._iter += 0.3

    def _style_connected(self):
        return """QPushButton {
            background-color: rgba(255,255,255,15); color: rgba(255,255,255,220);
            border-radius: 0px; padding: 10px; font-size: 16px;
            border: 1px solid rgba(255,255,255,60);
        }"""

    def _style_disconnect(self):
        return """QPushButton {
            background-color: rgba(255,80,80,60); color: white;
            border-radius: 0px; padding: 10px; font-size: 16px;
            border: 1px solid rgba(255,80,80,150);
        }"""

WIDTH, HEIGHT = 405, 720

class TransparentVideoLogo(QLabel):
    """Plays a looping video with black pixels made transparent (chroma-key style).
    Fully transparent background so the background video shows through.
    Centered horizontally in the parent widget."""

    def __init__(self, video_path, parent=None, width=200, height=120, threshold=10):
        super().__init__(parent)
        self.setFixedSize(width, height)
        self.setAlignment(Qt.AlignCenter)
        self.setStyleSheet("background-color: transparent;")
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.threshold = threshold
        self.setScaledContents(False)

        self.cap = cv2.VideoCapture(video_path)
        if not self.cap.isOpened():
            print(f"Could not open {video_path}, logo video disabled")
            self.cap = None
            self.setText("LOGO")
            self.setStyleSheet("background: transparent; color: white; font-weight: bold;")
            return

        fps = self.cap.get(cv2.CAP_PROP_FPS)
        if not fps or fps <= 0:
            fps = 24

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.next_frame)
        self.timer.start(int(1000 / fps))

    def next_frame(self):
        if self.cap is None:
            return

        ret, frame = self.cap.read()
        if not ret:
            self.cap.set(cv2.CAP_PROP_POS_FRAMES, 0)
            ret, frame = self.cap.read()
            if not ret:
                return

        b, g, r = cv2.split(frame)
        alpha = (
            (b.astype("int32") > self.threshold) |
            (g.astype("int32") > self.threshold) |
            (r.astype("int32") > self.threshold)
        ).astype("uint8") * 255
        rgba = cv2.merge((r, g, b, alpha))  # RGBA order for QImage

        h, w, ch = rgba.shape
        bytes_per_line = ch * w
        img = QImage(rgba.data, w, h, bytes_per_line, QImage.Format_RGBA8888)

        pixmap = QPixmap.fromImage(img.copy())
        scaled = pixmap.scaled(
            self.width(), self.height(),
            Qt.KeepAspectRatio,
            Qt.SmoothTransformation
        )
        self.setPixmap(scaled)

    def __del__(self):
        if self.cap is not None:
            self.cap.release()

class CustomTitleBar(QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.setFixedHeight(40)
        self.setStyleSheet("background-color: rgba(255, 255, 255, 180);")

        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 0, 10, 0)

        self.logo_label = QLabel()
        if os.path.exists("chamlon_utilities/logo.gif"):
            self.logo_movie = QMovie("chamlon_utilities/logo.gif")
            self.logo_label.setMovie(self.logo_movie)
            self.logo_movie.start()
        else:
            self.logo_label.setText("LOGO")
            self.logo_label.setStyleSheet("color: black; font-weight: bold;")
        self.logo_label.setFixedSize(32, 32)
        self.logo_label.setScaledContents(True)

        layout.addWidget(self.logo_label)
        layout.addStretch()

        self.min_btn = QPushButton("—")
        self.close_btn = QPushButton("✕")

        for btn in (self.min_btn, self.close_btn):
            btn.setFixedSize(30, 30)
            btn.setStyleSheet("""
                QPushButton {
                    background-color: #000000;
                    color: white;
                    border: none;
                    font-size: 14px;
                }
                QPushButton:hover {
                    background-color: #444;
                }
            """)

        self.min_btn.clicked.connect(self.parent.showMinimized)
        self.close_btn.clicked.connect(self.parent.close)

        layout.addWidget(self.min_btn)
        layout.addWidget(self.close_btn)

        self._drag_pos = None

    def toggle_max_restore(self):
        if self.parent.isMaximized():
            self.parent.showNormal()
        else:
            self.parent.showMaximized()

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self._drag_pos = event.globalPos() - self.parent.frameGeometry().topLeft()

    def mouseMoveEvent(self, event):
        if event.buttons() == Qt.LeftButton and self._drag_pos:
            self.parent.move(event.globalPos() - self._drag_pos)

class FrameVideoBackground(QLabel):
    """Seamlessly looping background video using OpenCV frame decoding."""
    def __init__(self, video_path, parent=None):
        super().__init__(parent)
        self.setStyleSheet("background-color: black;")
        self.setScaledContents(True)

        self.cap = cv2.VideoCapture(video_path)
        if not self.cap.isOpened():
            print(f"Could not open {video_path}, background disabled")
            self.cap = None
            return

        fps = self.cap.get(cv2.CAP_PROP_FPS)
        if not fps or fps <= 0:
            fps = 24

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.next_frame)
        self.timer.start(int(1000 / fps))

    def next_frame(self):
        if self.cap is None:
            return

        ret, frame = self.cap.read()
        if not ret:
            self.cap.set(cv2.CAP_PROP_POS_FRAMES, 0)
            ret, frame = self.cap.read()
            if not ret:
                return

        frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        h, w, ch = frame.shape
        bytes_per_line = ch * w
        img = QImage(frame.data, w, h, bytes_per_line, QImage.Format_RGB888)
        self.setPixmap(QPixmap.fromImage(img))

    def __del__(self):
        if self.cap is not None:
            self.cap.release()

class ConnectionPage(QWidget):
    connect_requested    = pyqtSignal(str, str)
    disconnect_requested = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setStyleSheet("background: transparent;")

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignTop)
        layout.setSpacing(15)
        layout.setContentsMargins(40, 260, 40, 20)

        logo_video_path = "chamlon_utilities/text_logo_bw.mp4"
        LOGO_W, LOGO_H = 400, 240
        if os.path.exists(logo_video_path):
            self.logo_overlay = TransparentVideoLogo(
                logo_video_path, self, width=LOGO_W, height=LOGO_H
            )
        else:
            self.logo_overlay = QLabel("LOGO", self)
            self.logo_overlay.setAlignment(Qt.AlignCenter)
            self.logo_overlay.setStyleSheet(
                "background: transparent; color: white; font-size: 18px; font-weight: bold;"
            )
            self.logo_overlay.setFixedSize(LOGO_W, LOGO_H)

        self._logo_w = LOGO_W
        self._logo_h = LOGO_H
        self.logo_overlay.raise_()

        self._connected  = False
        self._connecting = False

        self.ip_input = ScrambleLineEdit()
        self.ip_input.setPlaceholderText("Server IP")
        self.ip_input.setFont(QFont(family, 22, QFont.Bold))
        self.ip_input.setStyleSheet(self.input_style())
        self.ip_input.setAlignment(Qt.AlignCenter)

        self.port_input = ScrambleLineEdit()
        self.port_input.setPlaceholderText("Port")
        self.port_input.setFont(QFont(family, 22, QFont.Bold))
        self.port_input.setStyleSheet(self.input_style())
        self.port_input.setAlignment(Qt.AlignCenter)

        self.connect_btn = StateScrambleButton("connect")
        self.connect_btn.setFont(QFont(family, 22, QFont.Bold))
        self.connect_btn.setStyleSheet(self._btn_style_connect())
        self.connect_btn.setCursor(Qt.PointingHandCursor)
        self.connect_btn.clicked.connect(self._on_connect_toggle)

        self._dot_timer = None
        self._dot_count = 0

        layout.addWidget(self.ip_input)
        layout.addWidget(self.port_input)
        layout.addWidget(self.connect_btn)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        x = (self.width() - self._logo_w) // 2
        self.logo_overlay.move(x, 80)


    def _on_connect_toggle(self):
        if self._connecting:
            return
        if not self._connected:
            self.connect_requested.emit(
                self.ip_input.text().strip(),
                self.port_input.text().strip()
            )
        else:
            self.disconnect_requested.emit()

    def _start_connecting(self):
        self._connecting = True
        self.connect_btn.set_state("connecting")
        self.connect_btn.setStyleSheet(self._btn_style_pending())
        self._dot_count = 0
        self.connect_btn.setText(".")
        
        if self._dot_timer is not None:
            self._dot_timer.stop()
        self._dot_timer = QTimer(self)
        self._dot_timer.timeout.connect(self._update_dots)
        self._dot_timer.start(500)

    def _update_dots(self):
        """Cycle through . -> .. -> ..."""
        self._dot_count = (self._dot_count + 1) % 3
        dots = ". " * (self._dot_count + 1)
        self.connect_btn.setText(dots)

    def _stop_connecting(self):
        self._connecting = False
        if self._dot_timer is not None:
            self._dot_timer.stop()
            self._dot_timer = None

    def set_connected(self, connected: bool):
        self._stop_connecting()
        self._connected = connected
        if connected:
            self.connect_btn.set_state("connected")
            self.connect_btn.scramble_to("connected", style_fn=self._btn_style_connected)
        else:
            self.connect_btn.set_state("idle")
            self.connect_btn.scramble_to("connect", style_fn=self._btn_style_connect)

    def show_error(self, error_msg="invalid input"):
        """Temporarily show error message on button, then return to 'connect'."""
        self._connecting = False
        self.connect_btn.set_state("idle")
        self.connect_btn.scramble_to(error_msg, style_fn=self._btn_style_error)
        
        error_timer = QTimer(self)
        error_timer.setSingleShot(True)
        error_timer.timeout.connect(lambda: self.set_connected(False))
        error_timer.start(2000)

    def _btn_style_error(self):
        return """QPushButton {
            background-color: rgba(255,80,80,80); color: white;
            border-radius: 0px; padding: 10px; font-size: 16px;
            border: 1px solid rgba(255,80,80,150);
        }"""

    def input_style(self):
        return """
            QLineEdit {
                background-color: rgba(43, 43, 60, 180);
                color: white;
                border: 1px solid #444;
                border-radius: 6px;
                padding: 8px;
                font-size: 14px;
            }
        """

    def _btn_style_connect(self):
        return """QPushButton {
            background-color: #FFFFFF; color: black;
            border-radius: 0px; padding: 10px; font-size: 16px;
        } QPushButton:hover { background-color: #DDDDDD; }"""

    def _btn_style_pending(self):
        return """QPushButton {
            background-color: rgba(255,255,255,20);
            color: rgba(255,255,255,180);
            border-radius: 0px; padding: 10px; font-size: 16px;
            border: 1px solid rgba(255,255,255,60);
        }"""

    def _btn_style_connected(self):
        return """QPushButton {
            background-color: rgba(255,255,255,15);
            color: rgba(255,255,255,220);
            border-radius: 0px; padding: 10px; font-size: 16px;
            border: 1px solid rgba(255,255,255,60);
        }"""

    def _btn_style_disconnect(self):
        return """QPushButton {
            background-color: rgba(255,80,80,60); color: white;
            border-radius: 0px; padding: 10px; font-size: 16px;
            border: 1px solid rgba(255,80,80,150);
        }"""

class OptionsPage(QWidget):
    def __init__(self):
        super().__init__()
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setStyleSheet("background: transparent;")

        scroll = QScrollArea(self)
        scroll.setFrameShape(QScrollArea.NoFrame)
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("background: transparent; border: none;")

        content = QWidget()
        content.setAttribute(Qt.WA_TranslucentBackground)
        content.setStyleSheet("background: transparent;")

        layout = QVBoxLayout(content)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setAlignment(Qt.AlignTop)
        layout.setSpacing(14)

        scroll.setWidget(content)

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)
        outer_layout.addWidget(scroll)

        PRESET_BTN = """
            QPushButton {
                background-color: rgba(255,255,255,20);
                color: rgba(255,255,255,140);
                border: 1px solid rgba(255,255,255,40);
                border-radius: 6px;
                padding: 6px 12px;
            }
            QPushButton:checked {
                background-color: rgba(255,255,255,220);
                color: black;
                border: 1px solid white;
            }
            QPushButton:hover:!checked {
                background-color: rgba(255,255,255,40);
                color: white;
            }
        """

        preset_lbl = QLabel("privacy preset")
        preset_lbl.setFont(QFont(family, 10, QFont.Bold))
        preset_lbl.setStyleSheet("color: rgba(255,255,255,255); font-size: 15px; font-weight: 700; letter-spacing: 1.5px;")
        layout.addWidget(preset_lbl)

        preset_row = QHBoxLayout()
        preset_row.setSpacing(8)

        self.btn_basic  = QPushButton("Basic")
        self.btn_custom = QPushButton("Custom")
        self.btn_best   = QPushButton("Best")

        self.preset_group = QButtonGroup(self)
        self.preset_group.setExclusive(True)

        for i, btn in enumerate((self.btn_basic, self.btn_custom, self.btn_best)):
            btn.setCheckable(True)
            btn.setFont(QFont(family, 11, QFont.Bold))
            btn.setFixedHeight(36)
            btn.setStyleSheet(PRESET_BTN)
            self.preset_group.addButton(btn, i)
            preset_row.addWidget(btn)

        self.btn_basic.setChecked(True)
        layout.addLayout(preset_row)

        self.preset_group.buttonClicked.connect(self._on_preset_clicked)

        layout.addSpacing(8)

        frag_lbl = QLabel("fragmentation")
        frag_lbl.setFont(QFont(family, 10, QFont.Bold))
        frag_lbl.setStyleSheet("color: rgba(255,255,255,255); font-size: 15px; font-weight: 700; letter-spacing: 1.5px;")
        layout.addWidget(frag_lbl)

        frag_row = QHBoxLayout()
        frag_row.setSpacing(8)

        self.btn_frag_off = QPushButton("Off")
        self.btn_frag_mtu = QPushButton("Custom MTU")

        self.frag_group = QButtonGroup(self)
        self.frag_group.setExclusive(True)

        for btn in (self.btn_frag_off, self.btn_frag_mtu):
            btn.setCheckable(True)
            btn.setFont(QFont(family, 11, QFont.Bold))
            btn.setFixedHeight(36)
            btn.setStyleSheet(PRESET_BTN)
            self.frag_group.addButton(btn)
            frag_row.addWidget(btn)

        self.btn_frag_off.setChecked(True)
        layout.addLayout(frag_row)

        self.btn_frag_off.clicked.connect(lambda: self.mtu_container.setVisible(False))
        self.btn_frag_mtu.clicked.connect(lambda: self.mtu_container.setVisible(True))

        self.mtu_label = QLabel("MTU: 1200 bytes")
        self.mtu_label.setFont(QFont(family, 10, QFont.Bold))
        self.mtu_label.setStyleSheet("color: white; font-size: 12px;")

        self.slider_mtu = QSlider(Qt.Orientation.Horizontal)
        self.slider_mtu.setRange(300, 1200)
        self.slider_mtu.setValue(1200)
        self.slider_mtu.setStyleSheet("""
            QSlider::groove:horizontal {
                background: #888888;
                height: 6px;
                border-radius: 3px;
            }
            QSlider::handle:horizontal {
                background: white;
                border: 2px solid #cccccc;
                width: 14px;
                height: 14px;
                margin: -5px 0;
                border-radius: 7px;
            }
            QSlider::sub-page:horizontal {
                background: white;
                border-radius: 3px;
            }
            QSlider::add-page:horizontal {
                background: #888888;
                border-radius: 3px;
            }
        """)
        self.slider_mtu.valueChanged.connect(lambda v: self.mtu_label.setText(f"MTU: {v} bytes"))

        self.mtu_container = QWidget()
        self.mtu_container.setAttribute(Qt.WA_TranslucentBackground)
        mtu_layout = QVBoxLayout(self.mtu_container)
        mtu_layout.setContentsMargins(0, 4, 0, 0)
        mtu_layout.addWidget(self.mtu_label)
        mtu_layout.addWidget(self.slider_mtu)
        self.mtu_container.hide()
        layout.addWidget(self.mtu_container)

        layout.addSpacing(4)

        obf_lbl = QLabel("obfuscation")
        obf_lbl.setFont(QFont(family, 10, QFont.Bold))
        obf_lbl.setStyleSheet("color: rgba(255,255,255,255); font-size: 15px; font-weight: 700; letter-spacing: 1.5px;")
        layout.addWidget(obf_lbl)

        self.check_padding = QCheckBox("traffic padding")
        self.check_padding.setFont(QFont(family, 10, QFont.Bold))
        self.check_cbr = QCheckBox("constant bitrate")
        self.check_cbr.setFont(QFont(family, 10, QFont.Bold))

        CHECK_STYLE = """
            QCheckBox { color: white; }
            QCheckBox::indicator {
                width: 16px;
                height: 16px;
            }
            QCheckBox::indicator:unchecked {
                border: 2px solid rgba(255,255,255,140);
                border-radius: 3px;
            }
            QCheckBox::indicator:checked {
                border: 2px solid white;
                background: white;
                border-radius: 3px;
            }
        """
        for cb in (self.check_padding, self.check_cbr):
            cb.setStyleSheet(CHECK_STYLE)
            layout.addWidget(cb)

        layout.addSpacing(8)

        # ── Bandwidth ──
        bw_lbl = QLabel("bandwidth limit")
        bw_lbl.setFont(QFont(family, 10, QFont.Bold))
        bw_lbl.setStyleSheet("color: rgba(255,255,255,255); font-size: 15px; font-weight: 700; letter-spacing: 1.5px;")
        layout.addWidget(bw_lbl)

        self.mbps_label = QLabel("Limit: 5 Mbps")
        self.mbps_label.setFont(QFont(family, 10, QFont.Bold))
        self.mbps_label.setStyleSheet("color: white; font-size: 12px;")

        self.slider_mbps = QSlider(Qt.Orientation.Horizontal)
        self.slider_mbps.setRange(1, 15)
        self.slider_mbps.setValue(5)
        self.slider_mbps.setStyleSheet("""
            QSlider::groove:horizontal {
                background: #888888;
                height: 6px;
                border-radius: 3px;
            }
            QSlider::handle:horizontal {
                background: white;
                border: 2px solid #cccccc;
                width: 14px;
                height: 14px;
                margin: -5px 0;
                border-radius: 7px;
            }
            QSlider::sub-page:horizontal {
                background: white;
                border-radius: 3px;
            }
            QSlider::add-page:horizontal {
                background: #888888;
                border-radius: 3px;
            }
        """)
        self.slider_mbps.valueChanged.connect(lambda v: self.mbps_label.setText(f"Limit: {v} Mbps"))
        layout.addWidget(self.mbps_label)
        layout.addWidget(self.slider_mbps)

        self.rehandshake_label = QLabel("rehandshake timing")
        self.rehandshake_label.setFont(QFont(family, 10, QFont.Bold))
        self.rehandshake_label.setStyleSheet("color: rgba(255,255,255,255); font-size: 15px; font-weight: 700; letter-spacing: 1.5px;")
        layout.addWidget(self.rehandshake_label)

        self.rehandshake_value = 60
        self.rehandshake_display = QLabel(f"{self.rehandshake_value} s")
        self.rehandshake_display.setFont(QFont(family, 11, QFont.Bold))
        self.rehandshake_display.setStyleSheet("color: white; font-size: 14px; padding: 8px 12px; background-color: rgba(255,255,255,20); border: 1px solid rgba(255,255,255,40); border-radius: 6px;")

        self.rehandshake_decrease = QPushButton("-")
        self.rehandshake_decrease.setFixedSize(32, 32)
        self.rehandshake_decrease.setFont(QFont(family, 14, QFont.Bold))
        self.rehandshake_decrease.setStyleSheet("""
            QPushButton {
                background-color: rgba(255,255,255,20);
                color: white;
                border: 1px solid rgba(255,255,255,40);
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: rgba(255,255,255,40);
            }
        """)
        self.rehandshake_decrease.clicked.connect(self._decrease_rehandshake)

        self.rehandshake_button = QPushButton("+")
        self.rehandshake_button.setFixedSize(32, 32)
        self.rehandshake_button.setFont(QFont(family, 14, QFont.Bold))
        self.rehandshake_button.setStyleSheet("""
            QPushButton {
                background-color: rgba(255,255,255,20);
                color: white;
                border: 1px solid rgba(255,255,255,40);
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: rgba(255,255,255,40);
            }
        """)
        self.rehandshake_button.clicked.connect(self._increase_rehandshake)

        rehandshake_row = QHBoxLayout()
        rehandshake_row.setSpacing(8)
        rehandshake_row.addWidget(self.rehandshake_display)
        rehandshake_row.addWidget(self.rehandshake_decrease)
        rehandshake_row.addWidget(self.rehandshake_button)
        rehandshake_row.addStretch()
        layout.addLayout(rehandshake_row)

        key_label = QLabel("public key (hex)")
        key_label.setFont(QFont(family, 10, QFont.Bold))
        key_label.setStyleSheet("color: rgba(255,255,255,255); font-size: 15px; font-weight: 700; letter-spacing: 1.5px;")
        layout.addWidget(key_label)

        self.public_key_input = QLineEdit()
        self.public_key_input.setPlaceholderText("Enter your hex public key")
        self.public_key_input.setFont(QFont(family, 11, QFont.Bold))
        self.public_key_input.setStyleSheet("""
            QLineEdit {
                background-color: rgba(255,255,255,20);
                color: white;
                border: 1px solid rgba(255,255,255,40);
                border-radius: 6px;
                padding: 8px 12px;
                font-size: 13px;
            }
            QLineEdit:focus {
                border: 1px solid rgba(255,255,255,120);
                background-color: rgba(255,255,255,30);
            }
        """)
        layout.addWidget(self.public_key_input)

        self._connect_custom_check()


        tun_lbl = QLabel("tun interface name")
        tun_lbl.setFont(QFont(family, 10, QFont.Bold))
        tun_lbl.setStyleSheet("color: rgba(255,255,255,255); font-size: 15px; font-weight: 700; letter-spacing: 1.5px;")
        layout.addWidget(tun_lbl)

        self.tun_input = QLineEdit()
        self.tun_input.setPlaceholderText("e.g. tun_client")
        self.tun_input.setText("tun0")
        self.tun_input.setFont(QFont(family, 11, QFont.Bold))
        self.tun_input.setStyleSheet("""
            QLineEdit {
                background-color: rgba(255,255,255,20);
                color: white;
                border: 1px solid rgba(255,255,255,40);
                border-radius: 6px;
                padding: 8px 12px;
                font-size: 13px;
            }
            QLineEdit:focus {
                border: 1px solid rgba(255,255,255,120);
                background-color: rgba(255,255,255,30);
            }
        """)
        layout.addWidget(self.tun_input)

    def _on_preset_clicked(self, btn):
        if btn == self.btn_custom:
            self.preset_group.blockSignals(True)
            btn.setChecked(False)
            self._check_custom()
            self.preset_group.blockSignals(False)
            return
        self._apply_preset("best" if btn == self.btn_best else "basic")

    def _apply_preset(self, mode):
        self._disconnect_custom_check()
        if mode == "best":
            self.btn_frag_mtu.setChecked(True)
            self.mtu_container.setVisible(True)
            self.slider_mtu.setValue(1024)
            self.check_padding.setChecked(True)
            self.check_cbr.setChecked(True)
            self.btn_best.setChecked(True)
        else:
            self.btn_frag_off.setChecked(True)
            self.mtu_container.setVisible(False)
            self.check_padding.setChecked(False)
            self.check_cbr.setChecked(False)
            self.btn_basic.setChecked(True)
        self._connect_custom_check()

    def _disconnect_custom_check(self):
        for sig in (self.btn_frag_off.clicked, self.btn_frag_mtu.clicked,
                    self.slider_mtu.valueChanged,
                    self.check_padding.clicked, self.check_cbr.clicked,
                    self.slider_mbps.valueChanged):
            try: sig.disconnect(self._check_custom)
            except: pass

    def _connect_custom_check(self):
        for sig in (self.btn_frag_off.clicked, self.btn_frag_mtu.clicked,
                    self.slider_mtu.valueChanged,
                    self.check_padding.clicked, self.check_cbr.clicked,
                    self.slider_mbps.valueChanged):
            sig.connect(self._check_custom)

    def _check_custom(self, *args):
        is_best = (
            self.btn_frag_mtu.isChecked()
            and self.slider_mtu.value() == 1024
            and self.check_padding.isChecked()
            and self.check_cbr.isChecked()
        )
        is_basic = (
            self.btn_frag_off.isChecked()
            and not self.check_padding.isChecked()
            and not self.check_cbr.isChecked()
        )
        if is_best:
            self.btn_best.setChecked(True)
        elif is_basic:
            self.btn_basic.setChecked(True)
        else:
            self.btn_custom.setChecked(True)

    def _increase_rehandshake(self):
        self.rehandshake_value = min(self.rehandshake_value + 10, 9999)
        self.rehandshake_display.setText(f"{self.rehandshake_value} s")

    def _decrease_rehandshake(self):
        self.rehandshake_value = max(self.rehandshake_value - 10, 10)
        self.rehandshake_display.setText(f"{self.rehandshake_value} s")

class MetricsPage(QWidget):
    def __init__(self):
        import pyqtgraph as pg
        super().__init__()
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setStyleSheet("background: transparent;")

        self.data_x          = list(range(-100 + 1, 1))
        self.data_y          = [0] * 100
        self.data_packets    = [0] * 100
        self.data_keepalives = [0] * 100
        self.data_real       = [0] * 100
        self.data_dummy      = [0] * 100

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(10)

        LABEL_STYLE = (
            "color: rgba(255,255,255,255); font-size: 13px;"
            "font-weight: 700; letter-spacing: 1.5px;"
        )
        PERCENT_STYLE = (
            "color: white; font-size: 12px; font-weight: 600;"
            "letter-spacing: 0.5px;"
        )

        # ── Throughput ──
        lbl_tp = QLabel("throughput (mbps)")
        lbl_tp.setFont(QFont(family, 10, QFont.Bold))
        lbl_tp.setStyleSheet(LABEL_STYLE)
        layout.addWidget(lbl_tp)

        self.throughput_widget = self._graph(130, (0, 100))
        self.throughput_line   = self.throughput_widget.plot(
            self.data_x, self.data_y, fillLevel=0
        )
        layout.addWidget(self.throughput_widget)

        row = QHBoxLayout()
        row.setSpacing(10)

        pkt_col = QVBoxLayout()
        lbl_pkt = QLabel("packets/s")
        lbl_pkt.setFont(QFont(family, 10, QFont.Bold))
        lbl_pkt.setStyleSheet(LABEL_STYLE)
        self.packets_widget = self._graph(100, (0, 1000))
        self.packets_line   = self.packets_widget.plot(
            self.data_x, self.data_packets, fillLevel=0
        )
        pkt_col.addWidget(lbl_pkt)
        pkt_col.addWidget(self.packets_widget)
        row.addLayout(pkt_col)

        ka_col = QVBoxLayout()
        lbl_ka = QLabel("keepalives/s")
        lbl_ka.setFont(QFont(family, 10, QFont.Bold))
        lbl_ka.setStyleSheet(LABEL_STYLE)
        self.keepalive_widget = self._graph(100, (0, 1))
        self.keepalive_widget.getAxis("left").setTickSpacing(1, 1)
        self.keepalive_line   = self.keepalive_widget.plot(
            self.data_x, self.data_keepalives, fillLevel=0
        )
        ka_col.addWidget(lbl_ka)
        ka_col.addWidget(self.keepalive_widget)
        row.addLayout(ka_col)

        layout.addLayout(row)

        # ── Real vs Dummy ──
        lbl_mix = QLabel("real vs dummy packets")
        lbl_mix.setFont(QFont(family, 10, QFont.Bold))
        lbl_mix.setStyleSheet(LABEL_STYLE)
        layout.addWidget(lbl_mix)

        self.mix_widget  = self._graph(100, (0, 500))
        self.real_line   = self.mix_widget.plot(
            self.data_x, self.data_real,  name="Real"
        )
        self.dummy_line  = self.mix_widget.plot(
            self.data_x, self.data_dummy, name="Dummy"
        )
        layout.addWidget(self.mix_widget)

        self.percent_label = QLabel("Real: 0.00%  │  Dummy: 0.00%")
        self.percent_label.setAlignment(Qt.AlignCenter)
        self.percent_label.setFont(QFont(family, 10, QFont.Bold))
        self.percent_label.setStyleSheet(PERCENT_STYLE)
        layout.addWidget(self.percent_label)

        self._apply_graph_style()

    def _graph(self, min_h, y_range):
        import pyqtgraph as pg
        w = pg.PlotWidget()
        w.setMinimumHeight(min_h)
        w.showGrid(x=True, y=True, alpha=0.15)
        w.setXRange(-100 + 1, 0, padding=0)
        w.setYRange(*y_range)
        w.setStyleSheet("background: transparent;")
        return w

    def _apply_graph_style(self):
        import pyqtgraph as pg
        BG        = (0, 0, 0, 0)
        FG        = (255, 255, 255, 255)
        SECONDARY = (255, 255, 255, 140)
        axis_style = {"color": "#888888", "font-size": "9pt"}

        for widget, line, color in [
            (self.throughput_widget, self.throughput_line, FG),
            (self.packets_widget,    self.packets_line,    FG),
            (self.keepalive_widget,  self.keepalive_line,  SECONDARY),
        ]:
            widget.setBackground(BG)
            widget.setLabel("left",   "", **axis_style)
            widget.setLabel("bottom", "", **axis_style)
            pen = pg.mkPen(color=color, width=2)
            line.setPen(pen)
            c = QColor(*color)
            c.setAlpha(30)
            line.setBrush(c)

        self.mix_widget.setBackground(BG)
        self.mix_widget.setLabel("left",   "", **axis_style)
        self.mix_widget.setLabel("bottom", "", **axis_style)
        self.real_line.setPen(pg.mkPen(color=FG,        width=2))
        self.dummy_line.setPen(pg.mkPen(color=SECONDARY, width=2,
                                        style=Qt.PenStyle.DashLine))

    def push_data(self, vy, vpkt, vka, vrl, vdm):
        def _push(buf, val):
            buf.append(val)
            del buf[0]

        _push(self.data_y,          vy)
        _push(self.data_packets,    vpkt)
        _push(self.data_keepalives, vka)
        _push(self.data_real,       vrl)
        _push(self.data_dummy,      vdm)

        self.throughput_line.setData(self.data_x, self.data_y)
        self.packets_line.setData(self.data_x, self.data_packets)
        self.keepalive_line.setData(self.data_x, self.data_keepalives)
        self.real_line.setData(self.data_x, self.data_real)
        self.dummy_line.setData(self.data_x, self.data_dummy)

        total = vrl + vdm
        if total > 0:
            self.percent_label.setText(
                f"Real: {vrl/total*100:.1f}%   │   Dummy: {vdm/total*100:.1f}%"
            )

class NavBar(QWidget):
    def __init__(self, stacked_widget):
        super().__init__()
        self.stacked_widget = stacked_widget
        self.setStyleSheet("background-color: rgba(43, 43, 60, 180);")

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.btn_connect = ScrambleButton("Home")
        self.btn_options = ScrambleButton("Settings")
        self.btn_metrics = ScrambleButton("Metrics")

        self.buttons = [self.btn_options, self.btn_connect, self.btn_metrics]

        for i, btn in enumerate(self.buttons):
            btn.setFont(QFont(family, 22, QFont.Bold))

            def navigate(idx):
                current = stacked_widget.currentIndex()
                direction = "left" if idx > current else "right"
                stacked_widget.slide_to_index(idx, direction)
                self.set_active(idx)

            btn.clicked.connect(lambda checked, idx=i: navigate(idx))
            layout.addWidget(btn)

        self.set_active(stacked_widget.currentIndex())

    def set_active(self, active_idx):
        for i, btn in enumerate(self.buttons):
            if i == active_idx:
                btn.setStyleSheet("""
                    QPushButton {
                        background-color: transparent;
                        color: rgb(255, 255, 255);
                        border: none;
                        border-top: 2px solid white;
                        padding: 12px;
                        font-size: 14px;
                        font-weight: 900;
                    }
                    QPushButton:hover {
                        background-color: rgba(255, 255, 255, 30);
                    }
                """)
            else:
                btn.setStyleSheet("""
                    QPushButton {
                        background-color: transparent;
                        color: rgba(255, 255, 255, 100);
                        border: none;
                        border-top: 2px solid transparent;
                        padding: 12px;
                        font-size: 14px;
                        font-weight: 400;
                    }
                    QPushButton:hover {
                        background-color: rgba(255, 255, 255, 30);
                        color: rgba(255, 255, 255, 180);
                    }
                """)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.setFixedSize(WIDTH, HEIGHT)

        self.central = QWidget()
        self.setCentralWidget(self.central)
        self.central.setStyleSheet("background: transparent;")

        bg_path = "chamlon_utilities/background.mp4"
        if os.path.exists(bg_path):
            self.bg_widget = FrameVideoBackground(bg_path, self.central)
            self.bg_widget.setGeometry(0, 0, WIDTH, HEIGHT)
        else:
            self.bg_widget = None
            self.central.setStyleSheet("background-color: #1e1e2e;")

        self.main_layout = QVBoxLayout(self.central)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)

        self.title_bar = CustomTitleBar(self)
        self.main_layout.addWidget(self.title_bar)

        self.root_stack = QStackedWidget()
        self.root_stack.setAttribute(Qt.WA_TranslucentBackground)
        self.root_stack.setStyleSheet("background: transparent;")
        self.main_layout.addWidget(self.root_stack)

        self.app_container = QWidget()
        self.app_container.setAttribute(Qt.WA_TranslucentBackground)
        self.app_container.setStyleSheet("background: transparent;")
        app_layout = QVBoxLayout(self.app_container)
        app_layout.setContentsMargins(0, 0, 0, 0)
        app_layout.setSpacing(0)

        self.pages = AnimatedStackedWidget()
        self.pages.setAttribute(Qt.WA_TranslucentBackground)
        self.pages.setStyleSheet("background: transparent;")
        self.pages.addWidget(OptionsPage())
        self.pages.addWidget(ConnectionPage())
        self.pages.addWidget(MetricsPage())
        self.pages.setCurrentIndex(1)

        self.nav_bar = NavBar(self.pages)

        app_layout.addWidget(self.pages)
        app_layout.addWidget(self.nav_bar)

        self.root_stack.addWidget(self.app_container)
        self.root_stack.setCurrentWidget(self.app_container)

        if self.bg_widget is not None:
            self.bg_widget.lower()
            self.bg_widget.setGeometry(0, 0, WIDTH, HEIGHT)
        self.root_stack.raise_()
        self._wire_connection()

    def resizeEvent(self, event):
        if self.bg_widget is not None:
            self.bg_widget.setGeometry(0, 0, self.width(), self.height())
        super().resizeEvent(event)

    VPN_BINARY = "chamlon_client/vpn_client"

    def _wire_connection(self):
        conn_page = self.pages.widget(1)
        options   = self.pages.widget(0)
        conn_page.connect_requested.connect(lambda ip, port: self._start_vpn(ip, port, options))
        conn_page.disconnect_requested.connect(self._stop_vpn)

    def _start_vpn(self, ip, port, options):
        conn_page = self.pages.widget(1)
        if not self._valid_ip(ip) or not self._valid_port(port):
            if not self._valid_ip(ip):
                conn_page.show_error("invalid ip")
            else:
                conn_page.show_error("invalid port")
            return

        public_key = options.public_key_input.text().strip()
        if not public_key:
            conn_page.show_error("pubkey not set")
            return
        if not re.fullmatch(r"[0-9a-fA-F]{64}", public_key):
            conn_page.show_error("invalid key")
            return

        mbps = f"MBPS:{options.slider_mbps.value()}"
        frag = "FRAG:N"
        if options.btn_frag_mtu.isChecked():
            frag = f"FRAG:Y:{options.slider_mtu.value()}"
        cbr = "CBR:Y" if options.check_cbr.isChecked() else "CBR:N"
        pad = "PAD:Y" if options.check_padding.isChecked() else "PAD:N"
        rehandshake = f"REHANDSHAKE:{options.rehandshake_value}"
        tun_name = f"TUN:{options.tun_input.text().strip() or 'tun_vpnC'}"

        conn_page._start_connecting()

        if hasattr(self, "process"):
            try:
                self.process.readyReadStandardOutput.disconnect()
            except TypeError:
                pass
            self.process.kill()
            self.process.waitForFinished(1000)
            del self.process

        self.process = QProcess(self)
        self.process.readyReadStandardOutput.connect(self._on_vpn_output)
        args = [
            "-n", self.VPN_BINARY,
            ip, port, public_key,
            mbps, frag, cbr, pad,
            rehandshake, tun_name,
        ]
        self.process.start("sudo", args)

    def _stop_vpn(self):
        if not hasattr(self, "process") or self.process.state() != QProcess.Running:
            self._set_status("x", "err")
            return

        try:
            self.process.readyReadStandardOutput.disconnect()
        except TypeError:
            pass

        pkexec_pid = self.process.processId()
        child_pids = self._get_child_pids(pkexec_pid)

        for pid in child_pids:
            try:
                os.kill(pid, signal.SIGTERM)
            except PermissionError:
                os.system(f"sudo -n kill -TERM {pid}")
            except ProcessLookupError:
                pass

        if not self.process.waitForFinished(3000):
            for pid in child_pids:
                try:
                    os.kill(pid, signal.SIGKILL)
                except PermissionError:
                    os.system(f"sudo -n kill -KILL {pid}")
                except ProcessLookupError:
                    pass
            self.process.waitForFinished(2000)
            if self.process.state() == QProcess.Running:
                self.process.kill()

        self._set_status("x", "err")

    @staticmethod
    def _get_child_pids(parent_pid: int) -> list[int]:
        """Return all descendant PIDs of parent_pid using /proc (Linux only)."""
        result = []
        try:
            for entry in os.listdir("/proc"):
                if not entry.isdigit():
                    continue
                try:
                    status_path = f"/proc/{entry}/status"
                    with open(status_path) as f:
                        ppid = None
                        for line in f:
                            if line.startswith("PPid:"):
                                ppid = int(line.split()[1])
                                break
                        if ppid == parent_pid:
                            pid = int(entry)
                            result.append(pid)
                            result.extend(MainWindow._get_child_pids(pid))
                except (FileNotFoundError, PermissionError, ValueError):
                    continue
        except Exception:
            pass
        return result

    def _on_vpn_output(self):
        data = self.process.readAllStandardOutput().data().decode()

        metrics = self.pages.widget(2)
        vy   = metrics.data_y[-1]
        vpkt = metrics.data_packets[-1]
        vrl  = metrics.data_real[-1]
        vdm  = metrics.data_dummy[-1]
        vka  = 0
        found = False
        total_count = None
        packets_seen = False

        for raw in data.splitlines():
            line = raw.strip()
            if not line:
                continue

            if line == "TIMEOUT":
                self._set_status("● TIMEOUT", "err")
                self.process.readyReadStandardOutput.disconnect()
                self.process.terminate()
                self.process.waitForFinished(1000)
                return
            if line == "CONNECTED":
                self._set_status("● CONNECTED", "ok")
                continue
            if line == "DISCONNECTED":
                self._set_status("● DISCONNECTED", "err")
                continue
            if line == "ERROR":
                self._set_status("● ERROR", "err")
                continue

            low = line.lower()
            if "received keepalive from server" in low:
                vka = 1
                found = True
                continue

            tokens = re.findall(r"[A-Za-z]+|[-+]?\d*\.\d+|\d+", line)
            for i in range(0, len(tokens) - 1, 2):
                label = tokens[i].upper()
                value = tokens[i + 1]
                try:
                    num = float(value)
                except ValueError:
                    continue

                found = True
                if label == "MBPS":
                    vy = num
                elif label in ("KEEPALIVE", "KEEPALIVES"):
                    vka = num
                elif label == "REAL":
                    vrl = num
                elif label == "DUMMY":
                    vdm = num
                elif label == "TOTAL":
                    total_count = num

        if total_count is not None and not packets_seen:
            vpkt = total_count

        if found:
            metrics.push_data(vy, vpkt, vka, vrl, vdm)

    def _set_status(self, text, kind):
        conn_page = self.pages.widget(1)
        conn_page.set_connected(kind == "ok")

    @staticmethod
    def _valid_ip(ip):
        pat = (r"^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\."
               r"(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\."
               r"(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\."
               r"(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$")
        return re.match(pat, ip) is not None

    @staticmethod
    def _valid_port(port):
        return port.isdigit() and 1 <= int(port) <= 65535

    def closeEvent(self, event):
        if hasattr(self, "process") and self.process.state() == QProcess.Running:
            pkexec_pid = self.process.processId()
            for pid in self._get_child_pids(pkexec_pid):
                try:
                    os.kill(pid, signal.SIGTERM)
                except (ProcessLookupError, PermissionError):
                    pass
            self.process.waitForFinished(3000)
            if self.process.state() == QProcess.Running:
                self.process.kill()
        event.accept()

family = "Arial"
if __name__ == "__main__":
    app = QApplication(sys.argv)
    font_id = QFontDatabase.addApplicationFont("chamlon_utilities/geist-sans-latin-200-normal.ttf")
    if font_id < 0:
        print("Failed to load font, using default")
    else:
        family = QFontDatabase.applicationFontFamilies(font_id)[0]
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
