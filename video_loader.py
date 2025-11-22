import os
import vlc
import sys
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QStackedWidget, QSizePolicy, QGridLayout
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from texts import guide_gym

class ExerciseWidget(QWidget):
    def __init__(self, video_path, exercise_name, instructions=None):
        super().__init__()
        layout = QVBoxLayout(self)
        self.stacked = QStackedWidget()
        self.stacked.setStyleSheet("background-color: white; color: black;")

        # PAGE GUIDE
        self.page_guide = QWidget()
        guide_layout = QVBoxLayout(self.page_guide)
        guide_text = instructions if instructions else f"No guide available for {exercise_name}"
        guide_label = QLabel(guide_text)
        guide_label.setWordWrap(True)
        switch_btn = QPushButton("Watch Video")
        switch_btn.setStyleSheet("background-color:white;")
        switch_btn.clicked.connect(self.switchtovideo)
        guide_layout.addWidget(guide_label)
        guide_layout.addWidget(switch_btn)

        # PAGE VIDEO
        self.page_video = QWidget()
        video_layout = QVBoxLayout(self.page_video)
        self.video_frame = QWidget()
        self.video_frame.setMinimumHeight(300)
        self.video_frame.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.video_frame.setStyleSheet("background-color: black;")
        label = QLabel(exercise_name)
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        back_btn = QPushButton("Back to Guide")
        back_btn.setStyleSheet("background-color:white;")
        back_btn.clicked.connect(self.stop_and_back)
        video_layout.addWidget(self.video_frame)
        video_layout.addWidget(label)
        video_layout.addWidget(back_btn)

        # VLC setup
        self.instance = vlc.Instance()
        self.mediaplayer = self.instance.media_player_new()
        abs_path = os.path.abspath(video_path)
        self.media = self.instance.media_new(f"file:///{abs_path}")
        self.mediaplayer.set_media(self.media)

        if sys.platform.startswith("linux"):
            self.mediaplayer.set_xwindow(self.video_frame.winId())
        elif sys.platform == "win32":
            self.mediaplayer.set_hwnd(self.video_frame.winId())
        elif sys.platform == "darwin":
            self.mediaplayer.set_nsobject(int(self.video_frame.winId()))

        self.stacked.addWidget(self.page_guide)
        self.stacked.addWidget(self.page_video)
        layout.addWidget(self.stacked)

    def switchtovideo(self):
        self.stacked.setCurrentIndex(1)
        self.mediaplayer.play()

    def stop_and_back(self):
        self.mediaplayer.stop()
        self.stacked.setCurrentIndex(0)


class VideoLoader:
    def __init__(self, base_folder_path, target_layout):
        self.folder = base_folder_path
        self.layout = target_layout

    def load_exercises(self):
        row = 0
        col = 0
        max_cols = 2  # số cột mỗi hàng

        for muscle_group in sorted(os.listdir(self.folder)):
            group_path = os.path.join(self.folder, muscle_group)
            if not os.path.isdir(group_path):
                continue

            for file in sorted(os.listdir(group_path)):
                if not file.lower().endswith(".mp4"):
                    continue

                video_path = os.path.join(group_path, file)
                exercise_name = os.path.splitext(file)[0]
                exercise_key = exercise_name.lower().replace(" ", "")

                # Lấy hướng dẫn từ guide_gym nếu có
                instructions = f"No guide available for {exercise_name}"
                try:
                    if exercise_name in guide_gym:
                        instructions = f"{guide_gym[exercise_name].get('description', '')} (Tier {guide_gym[exercise_name].get('tier', '?')})"
                except Exception as e:
                    print(f"⚠️ Error fetching guide for {exercise_name}: {e}")

                # Tạo widget
                widget = ExerciseWidget(video_path, exercise_name, instructions)
                self.layout.addWidget(widget, row, col)

                col += 1
                if col >= max_cols:
                    col = 0
                    row += 1
