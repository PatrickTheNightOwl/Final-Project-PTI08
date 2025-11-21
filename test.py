# main_fixed_clean2.py
import os
import sys
import string
import traceback
import bcrypt
import subprocess
from PyQt6 import uic
from PyQt6.QtWidgets import (
    QMainWindow, QApplication, QMessageBox, QWidget, QLineEdit, QDialog, QGridLayout
)
from PyQt6.QtGui import QIcon, QCursor
from PyQt6.QtCore import Qt, QTimer

# custom modules (unchanged)
from texts import quotes
from userdata_iO import load_data, save_data
from quotes_random import randomquotes
from video_loader import VideoLoader
from smtp import generate_otp, send_otp


# ------------------ Helpers ------------------
def keep_main_ref(window):
    """Store window on QApplication to prevent GC."""
    app = QApplication.instance()
    if app is not None:
        app.main_window = window


def validate_gmail_domain(address: str):
    address = address.strip().lower()
    if "@" not in address:
        return False
    _, domain = address.rsplit("@", 1)
    return domain in ("gmail.com", "gmail.com.vn")


# ------------------ Login Page ------------------
class LoginPage(QMainWindow):
    def __init__(self):
        super().__init__()
        base_dir = os.path.dirname(__file__)
        ui_path = os.path.join(base_dir, "gui", "Final_Project_PTI08_LoginPage.ui")
        uic.loadUi(ui_path, self)

        # UI wiring
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

        # per-run attempt tracking
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

        stored_hash = data[username]["password"]
        # verify password
        if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
            # reset attempts
            self.attempts[username]['pw_attempts'] = 0

            gmail = data[username].get("gmail")
            if gmail:
                # generate and send OTP
                self.otp = generate_otp()
                try:
                    send_otp(gmail, username, self.otp)
                except Exception as e:
                    msg.setWindowTitle("OTP Error")
                    msg.setIcon(QMessageBox.Icon.Critical)
                    msg.setText(f"Failed to send OTP: {e}")
                    msg.exec()
                    return

                msg.setWindowTitle("Your OTP Code")
                msg.setIcon(QMessageBox.Icon.Information)
                msg.setText("OTP sent to your Gmail!")
                msg.exec()

                # open verify dialog modally and handle result
                verify = VerifyOTP(self.otp, username, password, gmail, parent=self)
                result = verify.exec()
                # if accepted, VerifyOTP already created and showed main; hide login
                if result == QDialog.DialogCode.Accepted:
                    # hide login (do not close to avoid destroying UI parents accidentally)
                    self.hide()
                else:
                    # stay on login; nothing to do
                    pass

            else:
                msg.setWindowTitle("Login Successful")
                msg.setIcon(QMessageBox.Icon.Information)
                msg.setText("Login successfully! Enjoy your training time!")
                msg.exec()

                # create MainPage, keep reference, show it, then hide login
                main = MainPage(username, password, None)
                keep_main_ref(main)
                main.show()
                self.hide()

        else:
            # wrong password handling
            self.attempts[username]['pw_attempts'] += 1
            failed = self.attempts[username]['pw_attempts']

            if failed % 3 == 0:
                multiplier = failed // 3
                pw_delay_ms = 180000 * multiplier
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
        # open the register window created in main block (kept in module-scope)
        try:
            register.show()
            self.hide()
        except Exception:
            # fallback: create new
            r = RegisterPage()
            r.show()
            self.hide()


# ------------------ Verify OTP ------------------
class VerifyOTP(QDialog):
    def __init__(self, otpcode, username, password, gmail, parent=None):
        super().__init__(parent)
        base_dir = os.path.dirname(__file__)
        ui_path = os.path.join(base_dir, "gui", "Final_Project_PTI08_VerifyOTP.ui")
        uic.loadUi(ui_path, self)

        self.otp = otpcode
        self.username = username
        self.password = password
        self.gmail = gmail
        self.verifybutton.clicked.connect(self.Verify)
        self.failed_attempt_otp = 0

    def Verify(self):
        msg = QMessageBox()
        user_input = self.otp_input.text().strip()

        if user_input == self.otp:
            msg.setWindowTitle("Login Successful")
            msg.setIcon(QMessageBox.Icon.Information)
            msg.setText("Correct OTP! Login successfully!")
            msg.exec()

            # show MainPage BEFORE closing this dialog and keep reference
            main = MainPage(self.username, self.password, self.gmail)
            keep_main_ref(main)
            main.show()

            # accept/close dialog after main shown
            self.accept()
        else:
            self.failed_attempt_otp += 1
            failed = self.failed_attempt_otp

            if failed % 3 == 0:
                multiplier = failed // 3
                delay_ms = 180000 * multiplier
                minutes = 3 * multiplier

                msg.setWindowTitle("Try Again Later")
                msg.setText(
                    f"You’ve entered the wrong OTP {failed} times.\n"
                    f"Please wait {minutes} minutes before retry."
                )
                msg.exec()
                self.otp_input.setEnabled(False)
                QTimer.singleShot(delay_ms, lambda: self.otp_input.setEnabled(True))
            else:
                msg.setWindowTitle("Invalid OTP")
                msg.setText(f"You’ve entered the wrong OTP {failed} times.")
                msg.exec()


# ------------------ Register Page ------------------
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

        self.statusBar().hide()
        self.setWindowTitle("TrainAnywhere")
        self.setWindowIcon(QIcon("gui/decor3.ico"))

    def OpenLogin(self):
        try:
            login.show()
            self.hide()
        except Exception:
            l = LoginPage()
            l.show()
            self.hide()

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

        # after registration go back to login
        try:
            login.show()
            self.hide()
        except Exception:
            l = LoginPage()
            l.show()
            self.hide()

    def ShowPassword(self):
        if self.password_input.echoMode() == QLineEdit.EchoMode.Password:
            self.showhidepwbutton.setIcon(QIcon("gui/hidepassword.png"))
            self.password_input.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.showhidepwbutton.setIcon(QIcon("gui/showpassword.png"))
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)


# ------------------ Main Page ------------------
class MainPage(QMainWindow):
    def __init__(self, username, password, gmail):
        # defensive init: capture exceptions and print them (PyQt sometimes swallows them)
        try:
            super().__init__()
            print("MainPage init start")  # debug marker

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

            self.movetochatbot.clicked.connect(self.OpenChatbot)

            self.username_show.setText(username)
            self.quotes.setText(f"'{randomquotes(quotes)}'")

            self.setWindowTitle("TrainAnywhere")
            self.setWindowIcon(QIcon("gui/decor3.ico"))
            self.statusBar().hide()

            print("MainPage init OK")  # debug marker
        except Exception as e:
            print("Exception in MainPage.__init__:", e)
            traceback.print_exc()
            raise  # re-raise so dev can see it if desired

    def GymMode(self):
        self.stackedWidget.setCurrentIndex(3)
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

    def OpenChatbot(self):
        subprocess.Popen([sys.executable, "chatbot.py"])

    def WorkoutPage(self):
        self.stackedWidget.setCurrentIndex(0)

    def HomePage(self):
        self.stackedWidget.setCurrentIndex(1)

    def Settings(self):
        settingspage = Settings(self.username, self.password, self.gmail)
        # keep reference to avoid GC while settings is open
        keep_main_ref(settingspage)
        settingspage.show()
        self.close()


# ------------------ Settings & Edits ------------------
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
        self.password_exist.setText("•" * 8)
        self.gmail_exist.setText(gmail if gmail else "Not set")

        self.gobackbutton.clicked.connect(self.GoBackHome)
        self.gobackbutton.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.logoutbutton.clicked.connect(self.LogOut)
        self.logoutbutton.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))

        self.setWindowTitle("TrainAnywhere")
        self.setWindowIcon(QIcon("gui/decor3.ico"))

    def LogOut(self):
        # show login and close settings
        try:
            login.show()
        except Exception:
            new_login = LoginPage()
            new_login.show()
        self.close()

    def GoBackHome(self):
        main = MainPage(self.username, self.password, self.gmail)
        keep_main_ref(main)
        main.show()
        self.close()

    def EditUsername(self):
        edit = EditUsername(self.username, self.password, self.gmail)
        edit.show()
        self.close()

    def EditPassword(self):
        edit = EditPassword(self.password, self.username, self.gmail)
        edit.show()
        self.close()

    def EditGmail(self):
        edit = EditGmail(self.password, self.username, self.gmail)
        edit.show()
        self.close()


class EditUsername(QDialog):
    def __init__(self, username, password, gmail):
        super().__init__()
        uic.loadUi("gui/Final_Project_PTI08_EditUsernamePage.ui", self)

        self.username = username
        self.password = password
        self.gmail = gmail
        self.username_exist.setText(username)

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
        s = Settings(self.username, self.password, self.gmail)
        s.show()
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
        main = MainPage(newusername, self.password, self.gmail)
        keep_main_ref(main)
        main.show()
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
        s = Settings(self.username, self.password, self.gmail)
        s.show()
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
        main = MainPage(self.username, newpassword, self.gmail)
        keep_main_ref(main)
        main.show()
        self.close()


class EditGmail(QDialog):
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
        s = Settings(self.username, self.password, self.gmail)
        s.show()
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
        main = MainPage(self.username, self.password, newgmail)
        keep_main_ref(main)
        main.show()
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
            main = MainPage(self.username, self.password, gmail=None)
            keep_main_ref(main)
            main.show()
            self.close()
        else:
            msg.setWindowTitle("Error")
            msg.setIcon(QMessageBox.Icon.Warning)
            msg.setText("User not found.")
            msg.exec()


# ------------------ Entrypoint ------------------
if __name__ == "__main__":
    app = QApplication(sys.argv)

    # create module-scope windows so we can easily show/hide them later
    register = RegisterPage()
    login = LoginPage()

    # show login
    login.show()
    # keep reference to top windows so GC won't collect anything important
    keep_main_ref(login)
    keep_main_ref(register)

    sys.exit(app.exec())
