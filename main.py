# main_fixed.py
import os
import sys
import string
import bcrypt
from PyQt6 import uic
from PyQt6.QtWidgets import (
    QMainWindow, QApplication, QMessageBox, QWidget, QLineEdit, QDialog, QGridLayout
)
from PyQt6.QtGui import QIcon, QCursor
from PyQt6.QtCore import Qt, QTimer

# your modules (unchanged)
from texts import quotes
from userdata_iO import load_data, save_data
from quotes_random import randomquotes
from video_loader import VideoLoader
from smtp import generate_otp, send_otp


class LoginPage(QMainWindow):
    def __init__(self):
        super().__init__()
        base_dir = os.path.dirname(__file__)
        ui_path = os.path.join(base_dir, "gui", "Final_Project_PTI08_LoginPage.ui")
        uic.loadUi(ui_path, self)

        # UI connections
        self.loginbutton.clicked.connect(self.Login)
        self.loginbutton.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.movetoregister.clicked.connect(self.OpenRegister)
        self.movetoregister.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.showhidepwbutton.clicked.connect(self.ShowPassword)
        self.showhidepwbutton.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.showhidepwbutton.setIcon(QIcon("gui/showpassword.png"))

        self.statusBar().hide()
        self.setWindowTitle("TrainAnywhere")
        self.setWindowIcon(QIcon("gui/decor3.ico"))

        # Lockout/attempt tracking (persist for this running instance)
        # structure: {'username': {'pw_attempts': int, 'otp_attempts': int, 'lock_until_ms': int}}
        self.attempts = {}

    def _ensure_user_entry(self, username):
        if username not in self.attempts:
            self.attempts[username] = {'pw_attempts': 0, 'otp_attempts': 0, 'pw_locked_until': 0}

    def Login(self):
        msg = QMessageBox()
        username = self.username_input.text().strip()
        password = self.password_input.text()

        if username == "":
            msg.setWindowTitle("Invalid Information")
            msg.setIcon(QMessageBox.Icon.Warning)
            msg.setText("Please enter username.")
            msg.exec()
            return

        self._ensure_user_entry(username)
        data = load_data()
        if username not in data:
            msg.setWindowTitle("Invalid Information")
            msg.setIcon(QMessageBox.Icon.Warning)
            msg.setText("Wrong username!")
            msg.exec()
            return

        # pw lock check: here we use simple timer using QTimer; check if pw_input is disabled or lock timestamp
        # (for more robust cross-run lockouts you'd persist to disk)
        stored_hash = data[username]["password"]
        # check password
        if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
            # reset attempts on success
            self.attempts[username]['pw_attempts'] = 0

            gmail = data[username].get("gmail")
            if gmail:
                self.otp = generate_otp()
                try:
                    send_otp(gmail, username, self.otp)
                except Exception as e:
                    msg.setWindowTitle("OTP Error")
                    msg.setIcon(QMessageBox.Icon.Critical)
                    msg.setText(f"Failed to send OTP: {e}")
                    msg.exec()
                    return

                msg.setWindowTitle("Your OTP code")
                msg.setIcon(QMessageBox.Icon.Information)
                msg.setText("Your OTP code has been sent to your gmail!")
                msg.exec()
                # show verify dialog modally
                verify = VerifyOTP(self.otp, username, password, gmail, parent=self)
                verify.exec()
                # VerifyOTP will open MainPage on success
            else:
                msg.setWindowTitle("Login successfully!")
                msg.setIcon(QMessageBox.Icon.Information)
                msg.setText("Login successfully! Enjoy your training time!")
                msg.exec()
                main = MainPage(username, password, None)
                self.close()
                main.show()
        else:
            # wrong password -> increment attempt count and handle lock
            self.attempts[username]['pw_attempts'] += 1
            failed = self.attempts[username]['pw_attempts']
            # every 3 wrong attempts -> disable for 3 minutes * multiplier
            if failed % 3 == 0:
                multiplier = failed // 3
                pw_delay_ms = 180000 * multiplier  # 3 minutes * multiplier
                minutes = 3 * multiplier
                msg.setWindowTitle("Please Try Again Later")
                msg.setIcon(QMessageBox.Icon.Warning)
                msg.setText(
                    f"You’ve entered the wrong password {failed} times.\n"
                    f"Please wait {minutes} minutes before trying again."
                )
                msg.exec()
                self.password_input.setEnabled(False)
                QTimer.singleShot(pw_delay_ms, lambda: self.password_input.setEnabled(True))
            else:
                msg.setWindowTitle("Invalid Password")
                msg.setIcon(QMessageBox.Icon.Warning)
                msg.setText(f"You’ve entered the wrong password {failed} times.")
                msg.exec()

    def ShowPassword(self):
        if self.password_input.echoMode() == QLineEdit.EchoMode.Password:
            self.showhidepwbutton.setIcon(QIcon("gui/hidepassword.png"))
            self.password_input.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.showhidepwbutton.setIcon(QIcon("gui/showpassword.png"))
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)

    def OpenRegister(self):
        self.close()
        register.show()


class VerifyOTP(QDialog):
    def __init__(self, otpcode, username, password, gmail, parent=None):
        super().__init__(parent)
        base_dir = os.path.dirname(__file__)
        ui_path = os.path.join(base_dir, "gui", "Final_Project_PTI08_VerifyOTP.ui")
        uic.loadUi(ui_path, self)
        self.otp = otpcode
        self.verifybutton.clicked.connect(self.Verify)
        self.username = username
        self.password = password
        self.gmail = gmail
        # per-dialog attempt counter
        self.failed_attempt_otp = 0

    def Verify(self):
        msg = QMessageBox()
        user_input = self.otp_input.text().strip()
        if user_input == self.otp:
            msg.setWindowTitle("Login successfully!")
            msg.setText("Correct OTP code! Login Successfully! Enjoy your training time!")
            msg.setIcon(QMessageBox.Icon.Information)
            msg.exec()
            self.accept()  # close dialog with success
            main = MainPage(self.username, self.password, self.gmail)
            main.show()
        else:
            self.failed_attempt_otp += 1
            failed = self.failed_attempt_otp
            if failed % 3 == 0:
                multiplier = failed // 3
                otp_delay_ms = 180000 * multiplier
                minutes = 3 * multiplier
                msg.setWindowTitle("Please Try Again Later")
                msg.setText(
                    f"You’ve entered the wrong OTP {failed} times.\n"
                    f"Please wait {minutes} minutes before trying again."
                )
                msg.exec()
                self.otp_input.setEnabled(False)
                QTimer.singleShot(otp_delay_ms, lambda: self.otp_input.setEnabled(True))
            else:
                msg.setWindowTitle("Invalid OTP")
                msg.setText(f"You’ve entered the wrong OTP {failed} times.")
                msg.exec()


class RegisterPage(QMainWindow):
    def __init__(self):
        super().__init__()
        base_dir = os.path.dirname(__file__)
        ui_path = os.path.join(base_dir, "gui", "Final_Project_PTI08_RegisterPage.ui")
        uic.loadUi(ui_path, self)
        self.registerbutton.clicked.connect(self.SaveNewUser)
        self.registerbutton.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.movetologin.clicked.connect(self.OpenLogin)
        self.movetologin.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.showhidepwbutton.clicked.connect(self.ShowPassword)
        self.showhidepwbutton.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.showhidepwbutton.setIcon(QIcon("gui/showpassword.png"))
        self.setWindowTitle("TrainAnywhere")
        self.setWindowIcon(QIcon("gui/decor3.ico"))
        self.statusBar().hide()

    def OpenLogin(self):
        self.close()
        login.show()

    def SaveNewUser(self):
        msg = QMessageBox()
        username = self.usernameinput.text().strip()
        password = self.password_input.text()
        gmail = str(self.gmail_input.text()).strip().lower()
        data = load_data()

        if username == "":
            msg.setWindowTitle("Registration failed")
            msg.setIcon(QMessageBox.Icon.Warning)
            msg.setText("Please enter username!")
            msg.exec()
            return

        if username in data:
            msg.setWindowTitle("Registration Failed")
            msg.setIcon(QMessageBox.Icon.Warning)
            msg.setText("Username already exists!")
            msg.exec()
            return

        if not (8 <= len(password) <= 25):
            msg.setWindowTitle("Invalid Password")
            msg.setIcon(QMessageBox.Icon.Warning)
            msg.setText("Password must be between 8 and 25 characters.")
            msg.exec()
            return

        special_chars = "!@#$%^&*()_+-={[}]|\\:;\"'<>,.?/~`"
        has_letter = any(c in string.ascii_letters for c in password)
        has_digit = any(c in string.digits for c in password)
        has_special = any(c in special_chars for c in password)
        if not (has_letter and has_digit and has_special):
            msg.setWindowTitle("Invalid Password")
            msg.setIcon(QMessageBox.Icon.Warning)
            msg.setText("Password must contain letters, numbers, and special characters.")
            msg.exec()
            return

        # gmail uniqueness check (only if non-empty)
        if gmail != "":
            for stored in data.values():
                if stored.get("gmail") == gmail:
                    msg.setWindowTitle("Invalid gmail")
                    msg.setIcon(QMessageBox.Icon.Warning)
                    msg.setText("Gmail already exists.")
                    msg.exec()
                    return

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        data[username] = {
            "password": hashed_password.decode('utf-8'),
            "gmail": gmail if gmail != "" else None
        }
        save_data(data)
        msg.setWindowTitle("Register Success")
        msg.setIcon(QMessageBox.Icon.Information)
        msg.setText("Account registered successfully!")
        msg.exec()
        self.OpenLogin()

    def ShowPassword(self):
        if self.password_input.echoMode() == QLineEdit.EchoMode.Password:
            self.showhidepwbutton.setIcon(QIcon("gui/hidepassword.png"))
            self.password_input.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.showhidepwbutton.setIcon(QIcon("gui/showpassword.png"))
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)


class MainPage(QMainWindow):
    def __init__(self, username, password, gmail):
        super().__init__()
        base_dir = os.path.dirname(__file__)
        ui_path = os.path.join(base_dir, "gui", "Final_Project_PTI08_MainPage.ui")
        uic.loadUi(ui_path, self)
        self.username = username
        self.password = password
        self.gmail = gmail
        self.stackedWidget.setCurrentIndex(1)
        self.SwitchToNutritions.clicked.connect(self.NutritionsPage)
        self.SwitchToNutritions.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.SwitchToWorkout.clicked.connect(self.WorkoutPage)
        self.SwitchToWorkout.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.SwitchToHome.clicked.connect(self.HomePage)
        self.SwitchToHome.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.settingsbutton.clicked.connect(self.Settings)
        self.gymmodebutton.clicked.connect(self.GymMode)
        self.gymmodebutton.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.calisthenicsmodebutton.clicked.connect(self.CalisthenicsMode)
        self.calisthenicsmodebutton.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        # show username and a quote
        self.username_show.setText(username)
        self.quotes.setText(f"'{randomquotes(quotes)}'")
        self.setWindowTitle("TrainAnywhere")
        self.setWindowIcon(QIcon("gui/decor3.ico"))
        self.statusBar().hide()

    def GymMode(self):
        self.stackedWidget.setCurrentIndex(3)
        # create grid layout in the scroll area contents
        self.grid_layout = QGridLayout(self.scrollAreaWidgetContents)
        video_folder = os.path.join(os.path.dirname(__file__), "GymVideos")
        loader = VideoLoader(video_folder, self.grid_layout)
        loader.load_exercises()

    def CalisthenicsMode(self):
        self.stackedWidget.setCurrentIndex(4)
        old_layout = self.scrollAreaWidgetContents_2.layout()
        if old_layout is not None:
            while old_layout.count():
                child = old_layout.takeAt(0)
                if child.widget():
                    child.widget().deleteLater()
            QWidget().setLayout(old_layout)
        self.grid_layout = QGridLayout()
        self.scrollAreaWidgetContents_2.setLayout(self.grid_layout)
        video_folder = os.path.join(os.path.dirname(__file__), "Calis Videos")
        loader = VideoLoader(video_folder, self.grid_layout)
        loader.load_exercises()

    def NutritionsPage(self):
        self.stackedWidget.setCurrentIndex(2)

    def WorkoutPage(self):
        self.stackedWidget.setCurrentIndex(0)

    def HomePage(self):
        self.stackedWidget.setCurrentIndex(1)

    def Settings(self):
        # pass three args (username, password, gmail)
        self.settingspage = Settings(self.username, self.password, self.gmail)
        self.settingspage.show()
        self.close()


class Settings(QDialog):
    def __init__(self, username, password, gmail):
        super().__init__()
        uic.loadUi("gui/Final_Project_PTI08_SettingsPage.ui", self)
        self.username = username
        self.password = password
        self.gmail = gmail
        self.editbutton.clicked.connect(self.EditUsername)
        self.editbutton.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.editbutton_2.clicked.connect(self.EditPassword)
        self.editbutton_2.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.editbutton_3.clicked.connect(self.EditGmail)
        self.editbutton_3.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.username_exist.setText(username)
        # DO NOT show plaintext password in UI; show masked
        self.password_exist.setText("•" * 8)
        self.gmail_exist.setText(gmail if gmail else "Not set")
        self.gobackbutton.clicked.connect(self.GoBackHome)
        self.gobackbutton.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.logoutbutton.clicked.connect(self.LogOut)
        self.logoutbutton.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.setWindowTitle("TrainAnywhere")
        self.setWindowIcon(QIcon("gui/decor3.ico"))

    def LogOut(self):
        self.movetologin = LoginPage()
        self.movetologin.show()
        self.close()

    def GoBackHome(self):
        self.close()
        self.mainpage = MainPage(self.username, self.password, self.gmail)
        self.mainpage.show()

    def EditUsername(self):
        self.editusername = EditUsername(self.username, self.password, self.gmail)
        self.close()
        self.editusername.show()

    def EditPassword(self):
        self.editpassword = EditPassword(self.password, self.username, self.gmail)
        self.close()
        self.editpassword.show()

    def EditGmail(self):
        self.editgmail = EditGmail(self.password, self.username, self.gmail)
        self.close()
        self.editgmail.show()


class EditUsername(QDialog):
    def __init__(self, username, password, gmail):
        super().__init__()
        uic.loadUi("gui/Final_Project_PTI08_EditUsernamePage.ui", self)
        self.username = username
        self.password = password
        self.gmail = gmail
        self.username_exist.setText(username)
        # update save button state when user types
        self.username_input.textChanged.connect(self._update_save_state)
        self.savebutton_username.clicked.connect(self.SaveDataCheck)
        self.savebutton_username.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.cancelbutton_username.clicked.connect(self.GoBackToSettings)
        self.cancelbutton_username.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.setWindowTitle("TrainAnywhere")
        self.setWindowIcon(QIcon("gui/decor3.ico"))
        self._update_save_state()

    def _update_save_state(self):
        if self.username_input.text().strip() == "":
            self.savebutton_username.setStyleSheet("color:#D3D3D3;font:20pt;")
            self.savebutton_username.setEnabled(False)
        else:
            self.savebutton_username.setStyleSheet("color:white;font:20pt")
            self.savebutton_username.setEnabled(True)

    def GoBackToSettings(self):
        self.gobacksettings = Settings(self.username, self.password, self.gmail)
        self.gobacksettings.show()
        self.close()

    def SaveDataCheck(self):
        msg = QMessageBox()
        data = load_data()
        newusername = self.username_input.text().strip()
        if newusername == "":
            msg.setWindowTitle("Invalid New Username")
            msg.setIcon(QMessageBox.Icon.Warning)
            msg.setText("New username can't be blank")
            msg.exec()
            return
        if newusername == self.username:
            msg.setWindowTitle("Invalid New Username")
            msg.setIcon(QMessageBox.Icon.Warning)
            msg.setText("New username can't be same as current username!")
            msg.exec()
            return
        if newusername in data:
            msg.setWindowTitle("Invalid New Username")
            msg.setIcon(QMessageBox.Icon.Warning)
            msg.setText("New username is already taken, please choose another name")
            msg.exec()
            return
        # perform rename
        data[newusername] = data[self.username]
        del data[self.username]
        save_data(data)
        msg.setWindowTitle("Username Changed")
        msg.setIcon(QMessageBox.Icon.Information)
        msg.setText(f"Username changed to '{newusername}' successfully.")
        msg.exec()
        self.mainpage = MainPage(newusername, self.password, self.gmail)
        self.mainpage.show()
        self.close()


class EditPassword(QDialog):
    def __init__(self, password, username, gmail):
        super().__init__()
        uic.loadUi("gui/Final_Project_PTI08_EditPasswordPage.ui", self)
        self.username = username
        self.password = password
        self.gmail = gmail
        self.password_exist.setText("•" * 8)
        self.password_input.textChanged.connect(self._update_save_state)
        self.savebutton_password.clicked.connect(self.SaveDataCheck)
        self.savebutton_password.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.cancelbutton_password.clicked.connect(self.GoBackSettings)
        self.cancelbutton_password.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.setWindowTitle("TrainAnywhere")
        self.setWindowIcon(QIcon("gui/decor3.ico"))
        self._update_save_state()

    def _update_save_state(self):
        if self.password_input.text().strip() == "":
            self.savebutton_password.setStyleSheet("color:#D3D3D3;font:20pt;")
            self.savebutton_password.setEnabled(False)
        else:
            self.savebutton_password.setStyleSheet("color:white;font:20pt")
            self.savebutton_password.setEnabled(True)

    def GoBackSettings(self):
        self.gobacksettings = Settings(self.username, self.password, self.gmail)
        self.gobacksettings.show()
        self.close()

    def SaveDataCheck(self):
        msg = QMessageBox()
        data = load_data()
        newpassword = self.password_input.text()
        if newpassword == "":
            msg.setWindowTitle("Invalid New Password")
            msg.setIcon(QMessageBox.Icon.Warning)
            msg.setText("New password can't be blank")
            msg.exec()
            return
        if newpassword == self.password:
            msg.setWindowTitle("Invalid New Password")
            msg.setIcon(QMessageBox.Icon.Warning)
            msg.setText("New password can't be same as current password!")
            msg.exec()
            return
        # hash and save
        hashed_password = bcrypt.hashpw(newpassword.encode('utf-8'), bcrypt.gensalt())
        data[self.username]["password"] = hashed_password.decode('utf-8')
        save_data(data)
        msg.setWindowTitle("Password Changed")
        msg.setIcon(QMessageBox.Icon.Information)
        msg.setText("Password changed successfully.")
        msg.exec()
        # show settings/main with new password masked
        self.settings = MainPage(self.username, newpassword, self.gmail)
        self.settings.show()
        self.close()


def validate_gmail_domain(address: str):
    """Return True if address looks like a gmail address."""
    address = address.strip().lower()
    if "@" not in address:
        return False
    local, domain = address.rsplit("@", 1)
    return domain in ("gmail.com", "gmail.com.vn")


class EditGmail(QDialog):
    # signature: (password, username, gmail)
    def __init__(self, password, username, gmail):
        super().__init__()
        uic.loadUi("gui/Final_Project_PTI08_EditGmailPage.ui", self)
        self.username = username
        self.password = password
        self.gmail = gmail
        self.gmail_exist.setText(gmail if gmail else "Not set")
        self.gmail_input.textChanged.connect(self._update_save_state)
        self.savebutton_gmail.clicked.connect(self.SaveDataCheck)
        self.savebutton_gmail.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.cancelbutton_gmail.clicked.connect(self.GoBackSettings)
        self.cancelbutton_gmail.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.removebutton_gmail.clicked.connect(self.RemoveGmail)
        self.removebutton_gmail.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.setWindowTitle("TrainAnywhere")
        self.setWindowIcon(QIcon("gui/decor3.ico"))
        self._update_save_state()

    def _update_save_state(self):
        if self.gmail_input.text().strip() == "":
            self.savebutton_gmail.setStyleSheet("color:#D3D3D3;font:20pt;")
            self.savebutton_gmail.setEnabled(False)
        else:
            self.savebutton_gmail.setStyleSheet("color:white;font:20pt")
            self.savebutton_gmail.setEnabled(True)

    def GoBackSettings(self):
        self.gobacksettings = Settings(self.username, self.password, self.gmail)
        self.gobacksettings.show()
        self.close()

    def SaveDataCheck(self):
        msg = QMessageBox()
        data = load_data()
        newgmail = self.gmail_input.text().strip().lower()
        if newgmail == "":
            msg.setWindowTitle("Invalid New Gmail")
            msg.setIcon(QMessageBox.Icon.Warning)
            msg.setText("New gmail can't be blank")
            msg.exec()
            return
        if newgmail == (data[self.username].get("gmail") or "").lower():
            msg.setWindowTitle("Invalid New Gmail")
            msg.setIcon(QMessageBox.Icon.Warning)
            msg.setText("New gmail can't be same as current gmail!")
            msg.exec()
            return
        if not validate_gmail_domain(newgmail):
            msg.setWindowTitle("Invalid new gmail")
            msg.setIcon(QMessageBox.Icon.Warning)
            msg.setText("New Gmail must be a valid gmail address (e.g. user@gmail.com).")
            msg.exec()
            return
        # check uniqueness
        for u, record in data.items():
            if u != self.username and record.get("gmail") and record.get("gmail").lower() == newgmail:
                msg.setWindowTitle("Invalid Gmail")
                msg.setIcon(QMessageBox.Icon.Warning)
                msg.setText("This gmail is already used by another account.")
                msg.exec()
                return
        data[self.username]["gmail"] = newgmail
        save_data(data)
        msg.setWindowTitle("Gmail Changed")
        msg.setIcon(QMessageBox.Icon.Information)
        msg.setText(f"Gmail changed to '{newgmail}' successfully.")
        msg.exec()
        self.settings = MainPage(self.username, self.password, newgmail)
        self.settings.show()
        self.close()

    def RemoveGmail(self):
        msg = QMessageBox()
        data = load_data()
        if self.username in data:
            data[self.username]["gmail"] = None
            save_data(data)
            msg.setWindowTitle("Gmail Removed")
            msg.setIcon(QMessageBox.Icon.Information)
            msg.setText("Gmail has been removed successfully!")
            msg.exec()
            self.settings = MainPage(self.username, self.password, gmail=None)
            self.settings.show()
            self.close()
        else:
            msg.setWindowTitle("Error")
            msg.setIcon(QMessageBox.Icon.Warning)
            msg.setText("User not found.")
            msg.exec()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    register = RegisterPage()
    login = LoginPage()
    login.show()
    sys.exit(app.exec())
