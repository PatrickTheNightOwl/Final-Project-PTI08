#load các thư viện cần thiết
from PyQt6.QtWidgets import QMainWindow, QApplication, QMessageBox, QWidget, QLineEdit, QDialog, QGridLayout
from PyQt6.QtGui import QIcon, QCursor
from PyQt6.QtCore import Qt, QTimer
from PyQt6 import uic  
import string
import sys 
import bcrypt
import os
#load module xử lí biến, thông tin, hiển thị
from texts import quotes
from userdata_iO import load_data, save_data  
from quotes_random import randomquotes
from video_loader import VideoLoader
from smtp import generate_otp, send_otp
#tạo hằng số file json
class LoginPage(QMainWindow) :
    def __init__(self,):
        super().__init__()
        base_dir = os.path.dirname(__file__)
        ui_path = os.path.join(base_dir, "gui", "Final_Project_PTI08_LoginPage.ui")
        uic.loadUi(ui_path,self)
        self.loginbutton.clicked.connect(self.Login) # signal and slots
        self.loginbutton.setCursor(QCursor(Qt.CursorShape.PointingHandCursor)) #chỉnh con trỏ chuột khi chạm nút
        self.movetoregister.clicked.connect(self.OpenRegister)
        self.movetoregister.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.showhidepwbutton.clicked.connect(self.ShowPassword)
        self.showhidepwbutton.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.showhidepwbutton.setIcon(QIcon("gui/showpassword.png"))
        self.statusBar().hide() # ẩn status bar
        self.setWindowTitle("TrainAnywhere") # đặt title cho cửa sổ
        self.setWindowIcon(QIcon("gui/decor3.ico"))

                    
    def Login(self) :
        msg = QMessageBox()
        username = self.username_input.text()
        password = self.password_input.text()
        
        failed_attempt_pw = 0
        pw_delay = 180000
        pw_delay_in_minute = 3
        
        data = load_data() # load json file vào biến data
        if username in data :
            stored_hash = data[username]["password"] #lấy mật khẩu đã hash từ data
            if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')): #so sánh 
                if data[username]["gmail"] != None :
                    self.otp = generate_otp()
                    send_otp(data[username]["gmail"],username,self.otp)
                    msg.setWindowTitle("Your OTP code")
                    msg.setIcon(QMessageBox.Icon.Information)
                    msg.setText("Your OTP code has been sent to your gmail! ")
                    msg.exec()
                    verify = VerifyOTP(self.otp,username,password,data[username]["gmail"])
                else : 
                    msg.setWindowTitle("Login successfully!")
                    msg.setIcon(QMessageBox.Icon.Information)
                    msg.setText("Login successfully! Enjoy your training time!")
                    msg.exec()
                    main = MainPage(username,password,None)
                    self.close()
                    main.show()
            else :
                failed_attempt_pw += 1
                if (failed_attempt_pw // 3) > 1 :
                    self.password_input.setEnabled(False)
                    pw_delay *= (failed_attempt_pw // 3)
                    pw_delay_in_minute *= (failed_attempt_pw // 3)
                    msg.setWindowTitle("Please Try Again Later")
                    msg.setText(
                        f"""
                        You’ve entered the wrong password {failed_attempt_pw} times.
                        Please wait {pw_delay_in_minute} minutes before trying again.

                        """
                    )
                    msg.exec()
                    QTimer.singleShot(pw_delay,lambda : self.password_input.setEnabled(True))
                elif (failed_attempt_pw // 3) == 1 :
                    self.otp_input.setEnabled(False)
                    msg.setWindowTitle("Please Try Again Later")
                    msg.setText(
                        f"""
                        You’ve entered the wrong password {failed_attempt_pw} times.
                        Please wait {pw_delay_in_minute} minutes before trying again.

                        """
                    )
                    msg.exec()
                    QTimer.singleShot(pw_delay,lambda : self.password_input.setEnabled(True))
                else : 
                    msg.setWindowTitle("Please Try Again Later")
                    msg.setText(
                        f"""
                        You’ve entered the wrong password {failed_attempt_pw} times.
                        """
                    )
                    msg.exec()
        else :
            msg.setWindowTitle("Invalid Information")
            msg.setIcon(QMessageBox.Icon.Warning)
            msg.setText("Wrong username!")
            msg.exec()
    def ShowPassword(self) :
        if self.password_input.echoMode() == QLineEdit.EchoMode.Password :
            self.showhidepwbutton.setIcon(QIcon("gui/hidepassword.png")) # thay đổi icon của nút hiện password
            self.password_input.setEchoMode(QLineEdit.EchoMode.Normal) # thay đổi echo của dòng nhập mật khẩu để hiển thị 
        else :
            self.showhidepwbutton.setIcon(QIcon("gui/showpassword.png"))
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
    def OpenRegister(self) :
        self.close() # đóng login
        register.show() # mở register
class VerifyOTP(QDialog) :
    def __init__(self,otpcode,username,password,gmail):
        super().__init__()
        base_dir = os.path.dirname(__file__)
        ui_path = os.path.join(base_dir, "gui", "Final_Project_PTI08_VerifyOTP.ui")
        uic.loadUi(ui_path,self)
        self.otp = otpcode
        self.verifybutton.clicked.connect(self.Verify)
        self.username = username
        self.password = password
        self.gmail = gmail
    def Verify(self) :
        msg = QMessageBox()
        failed_attempt_otp = 0
        otp_delay = 180000
        otp_delay_in_minute = 3
        if self.otp_input.text() == self.otp :
            msg = QMessageBox()
            msg.setWindowTitle("Login successfully!")
            msg.setText("Correct OTP code! Login Successfully! Enjoy your training time!")
            msg.setIcon(QMessageBox.Icon.Information)
            msg.exec()
            self.close()
            main = MainPage(self.username,self.password,self.gmail)
            main.show()
        else :
            failed_attempt_otp += 1
            if (failed_attempt_otp // 3) > 1 :
                self.otp_input.setEnabled(False)
                otp_delay *= (failed_attempt_otp // 3)
                otp_delay_in_minute *= (failed_attempt_otp // 3)
                msg.setWindowTitle("Please Try Again Later")
                msg.setText(
                    f"""
                    You’ve entered the wrong OTP {failed_attempt_otp} times.
                    Please wait {otp_delay_in_minute} minutes before trying again.

                    """
                )
                msg.exec()
                QTimer.singleShot(otp_delay,lambda : self.otp_input.setEnabled(True))
            elif (failed_attempt_otp // 3) == 1 :
                self.otp_input.setEnabled(False)
                msg.setWindowTitle("Please Try Again Later")
                msg.setText(
                    f"""
                    You’ve entered the wrong OTP {failed_attempt_otp} times.
                    Please wait {otp_delay_in_minute} minutes before trying again.

                    """
                )
                msg.exec()
                QTimer.singleShot(otp_delay,lambda : self.otp_input.setEnabled(True))
            else : 
                msg.setWindowTitle("Please Try Again Later")
                msg.setText(
                    f"""
                    You’ve entered the wrong OTP {failed_attempt_otp} times.
                    """
                )
                msg.exec()
class RegisterPage(QMainWindow) :
    def __init__(self): 
        super().__init__()
        base_dir = os.path.dirname(__file__)
        ui_path = os.path.join(base_dir, "gui", "Final_Project_PTI08_RegisterPage.ui")
        uic.loadUi(ui_path,self)
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
    def OpenLogin(self) :
        self.close() # đóng register 
        login.show() # mở login
    def SaveNewUser(self):
        msg = QMessageBox()
        username = self.usernameinput.text()
        password = self.password_input.text()
        gmail = str(self.gmail_input.text())
        data = load_data()

        special_chars = "!@#$%^&*()_+-={[}]|\\:;\"'<>,.?/~`"
        if username == "" :
            msg.setWindowTitle("Registration failed")
            msg.setIcon(QMessageBox.Icon.Warning)
            msg.setText("Please enter username!")
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

        has_letter = any(c in string.ascii_letters for c in password)
        has_digit = any(c in string.digits for c in password)
        has_special = any(c in special_chars for c in password)

        if not (has_letter and has_digit and has_special):
            msg.setWindowTitle("Invalid Password")
            msg.setIcon(QMessageBox.Icon.Warning)
            msg.setText("Password must contain letters, numbers, and special characters.")
            msg.exec()
            return
        
        for stored_username in data.values() :
            if stored_username["gmail"] == gmail :
                msg.setWindowTitle("Invalid gmail")
                msg.setIcon(QMessageBox.Icon.Warning)
                msg.setText("Gmail already exists.")
                msg.exec()
                return
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        data[username] = {
            "password": hashed_password.decode('utf-8'),
            "gmail" : gmail.lower()
        }
        save_data(data)
        msg.setWindowTitle("Register Success")
        msg.setIcon(QMessageBox.Icon.Information)
        msg.setText("Account registered successfully!")
        msg.exec()
        self.OpenLogin()

    def ShowPassword(self) :
        if self.password_input.echoMode() == QLineEdit.EchoMode.Password :
            self.showhidepwbutton.setIcon(QIcon("gui/hidepassword.png"))
            self.password_input.setEchoMode(QLineEdit.EchoMode.Normal)
        else :
            self.showhidepwbutton.setIcon(QIcon("gui/showpassword.png"))
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
class MainPage(QMainWindow) :
    def __init__(self,username,password,gmail):
        super().__init__()
        uic.loadUi("gui/Final_Project_PTI08_MainPage.ui",self)
        self.username = username
        self.password = password
        self.gmail = gmail
        self.stackedWidget.setCurrentIndex(1) # đặt page của stackedWidget = 1 ( page giữa )
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
        self.username_show.setText(username) # đặt văn bản cho label username_show bằng biến username ( được truyền vào ở login )
        self.quotes.setText(f"'{randomquotes(quotes)}'")
        self.setWindowTitle("TrainAnywhere")
        self.setWindowIcon(QIcon("gui/decor3.ico"))
        self.statusBar().hide()
    def GymMode(self) :
        self.stackedWidget.setCurrentIndex(3)
       # Tạo Grid layout để bỏ vào GridWidget
        self.grid_layout = QGridLayout(self.scrollAreaWidgetContents)
        # Load tất cả bài tập
        video_folder = "C:/Users/LENOVO/Downloads/code/Python/PTI08/Final_Project/GymVideos"  # Thư mục chứa bài tập phân nhóm
        loader = VideoLoader(video_folder, self.grid_layout)
        loader.load_exercises()
        # loader.load_exercises()

    def CalisthenicsMode(self):
        self.stackedWidget.setCurrentIndex(4)  # Đảm bảo chuyển đến đúng trang Calis

        # Xóa layout cũ nếu có
        old_layout = self.scrollAreaWidgetContents_2.layout()
        if old_layout is not None:
            while old_layout.count():
                child = old_layout.takeAt(0)
                if child.widget():
                    child.widget().deleteLater()
        # Xóa layout khỏi widget
            QWidget().setLayout(old_layout)

    # Gán layout mới
        self.grid_layout = QGridLayout()
        self.scrollAreaWidgetContents_2.setLayout(self.grid_layout)

    # Load video
        video_folder = "C:/Users/LENOVO/Downloads/code/Python/PTI08/Final_Project/Calis Videos"
        loader = VideoLoader(video_folder, self.grid_layout)
        loader.load_exercises()

    def NutritionsPage(self) :
        self.stackedWidget.setCurrentIndex(2) # chuyển page khi ấn nút
    def WorkoutPage(self) :
        self.stackedWidget.setCurrentIndex(0)
    def HomePage(self) :
        self.stackedWidget.setCurrentIndex(1)
    def Settings(self) :
        self.settingspage = Settings(self.username,self.password,)
        self.settingspage.show()
        self.close()
class Settings(QDialog) :
    def __init__(self,username,password,gmail):
        super().__init__()
        uic.loadUi("gui/Final_Project_PTI08_SettingsPage.ui",self)
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
        self.password_exist.setText(password)
        self.gmail_exist.setText(gmail)
        self.gobackbutton.clicked.connect(self.GoBackHome)
        self.gobackbutton.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.logoutbutton.clicked.connect(self.LogOut)
        self.logoutbutton.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.setWindowTitle("TrainAnywhere")
        self.setWindowIcon(QIcon("gui/decor3.ico"))
    def LogOut(self) :
        self.movetologin = LoginPage()
        self.movetologin.show()
        self.close()
    def GoBackHome(self) :
        self.close()
        self.mainpage = MainPage(self.username,self.password)
        self.mainpage.show()
    def EditUsername(self) :
        self.editusername = EditUsername(self.username,self.password,self.gmail)
        self.close()
        self.editusername.show()
    def EditPassword(self) :
        self.editpassword = EditPassword(self.password,self.username,self.gmail)
        self.close()
        self.editpassword.show()
    def EditGmail(self) :
        self.editgmail = EditGmail(self.username,self.password,self.gmail)
        self.close()
        self.editgmail.show()
class EditUsername(QDialog) :
    def __init__(self,username,password,gmail):
        super().__init__()
        uic.loadUi("gui/Final_Project_PTI08_EditUsernamePage.ui",self)
        self.username = username
        self.password = password
        self.gmail = gmail
        self.username_exist.setText(username)
        if self.username_input.text() == "" :
            self.savebutton_username.setStyleSheet("color:#D3D3D3;font:20pt;")
        else :
            self.savebutton_username.setStyleSheet("color:white;font:20pt")
        self.savebutton_username.clicked.connect(self.SaveDataCheck)
        self.savebutton_username.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.cancelbutton_username.clicked.connect(self.GoBackToSettings)
        self.cancelbutton_username.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.setWindowTitle("TrainAnywhere")
        self.setWindowIcon(QIcon("gui/decor3.ico"))
    def GoBackToSettings(self) :
        self.gobacksettings = Settings(self.username,self.password,self.gmail)
        self.gobacksettings.show()
        self.close()
    def SaveDataCheck(self) :
        msg = QMessageBox()
        data = load_data()
        newusername = self.username_input.text()
        if newusername == "" :
            msg.setWindowTitle("Invalid New Username")
            msg.setIcon(QMessageBox.Icon.Warning)
            msg.setText("New username can't be blank")
            msg.exec()
        elif newusername == self.username :
            msg.setWindowTitle("Invalid New Username")
            msg.setIcon(QMessageBox.Icon.Warning)
            msg.setText("New username can't be same as current username!")
            msg.exec()
        elif newusername in data :
            msg.setWindowTitle("Invalid New Username")
            msg.setIcon(QMessageBox.Icon.Warning)
            msg.setText("New username is already taken, please choose another name")
            msg.exec()
        else :
            for stored_username in data :
                if stored_username == self.username :
                    data[newusername] = data[self.username]
                    del data[self.username]
                    break
            save_data(data)
            msg.setWindowTitle("Username Changed")
            msg.setIcon(QMessageBox.Icon.Information)
            msg.setText(f"Username changed to '{newusername}' successfully.")
            msg.exec()
            self.mainpage = MainPage(newusername,self.password,self.gmail)
            self.mainpage.show()
            self.close()
class EditPassword(QDialog) :
    def __init__(self,password,username,gmail):
        super().__init__()
        uic.loadUi("gui/Final_Project_PTI08_EditPasswordPage.ui",self)
        self.password_exist.setText(password)
        self.username = username
        self.password = password
        self.gmail = gmail
        if self.password_input.text() == "" :
            self.savebutton_password.setStyleSheet("color:#D3D3D3;font:20pt;")
        else :
            self.savebutton_password.setStyleSheet("color:white;font:20pt")
        self.savebutton_password.clicked.connect(self.SaveDataCheck)
        self.savebutton_password.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.cancelbutton_password.clicked.connect(self.GoBackSettings)
        self.cancelbutton_password.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.setWindowTitle("TrainAnywhere")
        self.setWindowIcon(QIcon("gui/decor3.ico"))
    def GoBackSettings(self) :
        self.gobacksettings = Settings(self.username,self.password,self.gmail)
        self.gobacksettings.show()
        self.close()
    def SaveDataCheck(self) :
        msg = QMessageBox()
        data = load_data()
        newpassword = self.password_input.text()
        if newpassword == "" :
            msg.setWindowTitle("Invalid New Password")
            msg.setIcon(QMessageBox.Icon.Warning)
            msg.setText("New password can't be blank")
            msg.exec()
        elif newpassword == self.password :
            msg.setWindowTitle("Invalid New Password")
            msg.setIcon(QMessageBox.Icon.Warning)
            msg.setText("New password can't be same as current password!")
            msg.exec()
        else :
            for stored_username in data :
                if stored_username == self.username :
                    hashed_password = bcrypt.hashpw(newpassword.encode('utf-8'), bcrypt.gensalt())
                    data[self.username]["password"] = hashed_password.decode('utf-8')
                    break
            save_data(data)
            msg.setWindowTitle("Password Changed")
            msg.setIcon(QMessageBox.Icon.Information)
            msg.setText(f"Password changed to '{newpassword}' successfully.")
            msg.exec()
            self.settings = MainPage(self.username, newpassword, self.gmail)
            self.settings.show()
            self.close()
class EditGmail(QDialog) :
    def __init__(self,password,username,gmail):
        super().__init__()
        uic.loadUi("gui/Final_Project_PTI08_EditGmailPage.ui",self)
        data = load_data()
        self.gmail_exist.setText(self.gmail)
        self.username = username
        self.password = password
        self.gmail = gmail
        if self.gmail_input.text() == "" :
            self.savebutton_gmail.setStyleSheet("color:#D3D3D3;font:20pt;")
        else :
            self.savebutton_gmail.setStyleSheet("color:white;font:20pt")
        self.savebutton_gmail.clicked.connect(self.SaveDataCheck)
        self.savebutton_gmail.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.cancelbutton_gmail.clicked.connect(self.GoBackSettings)
        self.cancelbutton_gmail.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.removebutton_gmail.clicked.connect(self.RemoveGmail)
        self.removebutton_gmail.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.setWindowTitle("TrainAnywhere")
        self.setWindowIcon(QIcon("gui/decor3.ico"))
    def GoBackSettings(self) :
        self.gobacksettings = Settings(self.username,self.password,self.gmail)
        self.gobacksettings.show()
        self.close()
    def SaveDataCheck(self) :
        msg = QMessageBox()
        data = load_data()
        newgmail = self.gmail_input.text()
        common_domain = [
        "gmail.com","gmail.com.vn"
        ]
        has_domain = any(c in common_domain for c in newgmail)
        has_atsign = any(c == "@" for c in newgmail)
        if newgmail == "" :
            msg.setWindowTitle("Invalid New Gmail")
            msg.setIcon(QMessageBox.Icon.Warning)
            msg.setText("New gmail can't be blank")
            msg.exec()
        elif newgmail == data[self.username]["gmail"] :
            msg.setWindowTitle("Invalid New Gmail")
            msg.setIcon(QMessageBox.Icon.Warning)
            msg.setText("New gmail can't be same as current password!")
            msg.exec()
        elif not(has_domain and has_atsign) :
            msg.setWindowTitle("Invalid new gmail")
            msg.setIcon(QMessageBox.Icon.Warning)
            msg.setText("New Gmail must contain '@', and 'gmail.com'.")
            msg.exec()
        else :
            for stored_username in data :
                if stored_username == self.username :
                    data[self.username]["gmail"] = newgmail
                    break
            save_data(data)
            msg.setWindowTitle("Gmail Changed")
            msg.setIcon(QMessageBox.Icon.Information)
            msg.setText(f"Gmail changed to '{newgmail}' successfully.")
            msg.exec()
            self.settings = MainPage(self.username, self.password, newgmail)
            self.settings.show()
            self.close()
    def RemoveGmail(self) :
        msg = QMessageBox()
        data = load_data()
        for stored_username in data :
            if stored_username == self.username :
                stored_username["gmail"] = None
        save_data(data)
        msg.setWindowTitle("Gmail Removed")
        msg.setIcon(QMessageBox.Icon.Information)
        msg.setText("Gmail has been removed successfully!")
        msg.exec()
        self.settings = MainPage(self.username, self.password, gmail=None)
        self.settings.show()
        self.close()
if __name__ == "__main__" :
    app = QApplication(sys.argv)
    register = RegisterPage()
    login = LoginPage()
    login.show()
    app.exec()