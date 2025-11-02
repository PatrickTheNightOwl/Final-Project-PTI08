import os
import vlc
import sys
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QStackedWidget, QSizePolicy
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from texts import guide_gym

# ExerciseWidget (dùng VLC thay cho QMediaPlayer)
class ExerciseWidget(QWidget):
    def __init__(self, video_path, exercise_name, instructions):
        super().__init__()
        layout = QVBoxLayout(self)
        # Tạo stacked widget để chuyển đổi giữa 2 trang (guide & video)
        self.stacked = QStackedWidget()
        self.stacked.setStyleSheet("background-color: white; color: black;")

        # PAGE 1 - Hướng dẫn
        self.page_guide = QWidget()
        guide_layout = QVBoxLayout(self.page_guide)
        guide_label = QLabel(instructions)
        guide_label.setWordWrap(True)
        switch_btn = QPushButton("Watch Video")
        switch_btn.setStyleSheet("background-color:white;")
        switch_btn.clicked.connect(self.switchtovideo)

        guide_layout.addWidget(guide_label)
        guide_layout.addWidget(switch_btn)

        # PAGE 2 - Video
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

        # VLC Setup
        self.instance = vlc.Instance()
        self.mediaplayer = self.instance.media_player_new()
        self.abs_path = os.path.abspath(video_path)
        self.media = self.instance.media_new(f"file:///{self.abs_path}")
        self.mediaplayer.set_media(self.media)

        self.video_frame.winId()
        self.video_frame.show()
        self.video_frame.setAttribute(Qt.WidgetAttribute.WA_OpaquePaintEvent)
        self.video_frame.setAttribute(Qt.WidgetAttribute.WA_NoSystemBackground, True)
        self.video_frame.setUpdatesEnabled(True)
        self.video_frame.setVisible(True)
        self.video_frame.show()

        if sys.platform.startswith("linux"):
            self.mediaplayer.set_xwindow(self.video_frame.winId())
        elif sys.platform == "win32":
            self.video_frame.show()
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


# VideoLoader - Load toàn bộ video từ folder
class VideoLoader:
    def __init__(self, base_folder_path, target_layout):
        self.folder = base_folder_path
        self.layout = target_layout

    def load_exercises(self):
        row = 0
        col = 0
        for muscle_group in os.listdir(self.folder):
            group_path = os.path.join(self.folder, muscle_group)

            if os.path.isdir(group_path):
                for file in os.listdir(group_path):
                    if file.endswith(".mp4"):
                        video_path = os.path.join(group_path, file)
                        exercise_name = os.path.splitext(file)[0]
                        exercise_name_check = exercise_name.lower().replace(" ", "")

                        # Debug phân nhánh
                        if self.folder == "C:/Users/LENOVO/Downloads/code/Python/PTA08/Final_Project/GymVideos":
                            exercise_name_exist = f"{exercise_name} - for {muscle_group}"
                            try:
                                instructions = f"How to do {exercise_name_exist} (Tier {guide_gym[exercise_name]['tier']})"
                            except KeyError as e:
                                print(f"⚠️ KeyError in guide_gym: {exercise_name} not found")
                                instructions = exercise_name_exist
                        elif self.folder == "C:/Users/LENOVO/Downloads/code/Python/PTA08/Final_Project/Calis Videos":
                            instructions = exercise_name

                        if "anatomy" in exercise_name_check:
                            instructions = exercise_name
                        widget = ExerciseWidget(video_path, exercise_name, instructions)
                        self.layout.addWidget(widget, row, col)

                        col += 1
                        if col == 2:
                            col = 0
                            row += 1