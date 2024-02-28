import os.path

from Crypto.Cipher import DES3
from Crypto.PublicKey import RSA
from PyQt5 import QtWidgets, uic
import vhdmount.diskpart as vdisk
from encrypt import aes, createkey, tripledes

sizes = {
    "3DES": 24,
    "AES-128": 16,
    "AES-196": 24,
    "AES-256": 32
}


class MyApplication(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        uic.loadUi('pymycrypt.ui', self)
        self.publicKeyFilePath = ""
        self.privateKeyFilePath = ""
        self.pempath = ""
        self.last_volumn_index = ""
        self.currentkey = ""
        self.currentmode = ""
        self.currentalgorithm = ""
        self.currentVHDfilepath = ""
        self.currentpempath = ""
        # 创建加密磁盘页
        self.comboBoxInit.currentTextChanged.connect(self.OnComboboxChanged)
        self.pushButtonCreateRSA.clicked.connect(self.CreateRSA)
        self.pushButtonCreate.clicked.connect(self.CreateVHD)
        self.pushButtonChoosePublicKey.clicked.connect(self.ChoosePublicKey)
        self.pushButtonLoadVHD.clicked.connect(self.LoadVHD)
        self.pushButtonUnmountVHD.clicked.connect(self.UnmountVHD)
        self.pushButtonChoosePrivateKey.clicked.connect(self.ChoosePrivateKey)
        # 创建加密文件页
        self.comboBoxInit2.currentTextChanged.connect(self.OnComboboxChanged2)
        self.pushButtonChooseNeedEncryptFile.clicked.connect(self.ChooseNeedEncryptFile)
        self.pushButtonCreate2.clicked.connect(self.CreateEncryptfile)
        self.pushButtonChoosePublicKey2.clicked.connect(self.ChoosePublicKey)
        self.pushButtonDecryptFile.clicked.connect(self.DecryptFile)
        self.pushButtonChoosePrivateKey2.clicked.connect(self.ChoosePrivateKey)

    def OnComboboxChanged(self, text):
        # 根据 ComboBox 的选项来启用或禁用 Label 和 LineEdit
        if text == "使用口令":
            self.labelPass.setEnabled(True)
            self.lineEditPass.setEnabled(True)
            self.pushButtonChoosePublicKey.setEnabled(False)
        elif text == "使用RSA公钥":
            self.labelPass.setEnabled(False)
            self.lineEditPass.setEnabled(False)
            self.pushButtonChoosePublicKey.setEnabled(True)
        else:
            self.labelPass.setEnabled(False)
            self.lineEditPass.setEnabled(False)
            self.pushButtonChoosePublicKey.setEnabled(False)

    def OnComboboxChanged2(self, text):
        # 根据 ComboBox 的选项来启用或禁用 Label 和 LineEdit
        if text == "使用口令":
            self.labelPass2.setEnabled(True)
            self.lineEditPass2.setEnabled(True)
            self.pushButtonChoosePublicKey2.setEnabled(False)
        elif text == "使用RSA公钥":
            self.labelPass2.setEnabled(False)
            self.lineEditPass2.setEnabled(False)
            self.pushButtonChoosePublicKey2.setEnabled(True)
        else:
            self.labelPass2.setEnabled(False)
            self.lineEditPass2.setEnabled(False)
            self.pushButtonChoosePublicKey2.setEnabled(False)

    def CreateRSA(self):
        # 获取当前激活的 tab
        currentTab = self.tabWidget.currentWidget()
        # 在当前 tab 中查找 QTextBrowser
        textBrowser = currentTab.findChild(QtWidgets.QTextBrowser)
        options = QtWidgets.QFileDialog.Options()
        filePath, _ = QtWidgets.QFileDialog.getSaveFileName(self, "创建文件", "", "RSA公钥私钥(*.pem)", options=options)
        if not filePath:
            return
        public_key, private_key = createkey.generate_rsa()
        filePath, suffix = os.path.splitext(filePath)
        with open(filePath + "_public" + suffix, "wb") as file_out:
            file_out.write(public_key)
        with open(filePath + "_private" + suffix, "wb") as file_out:
            file_out.write(private_key)
        textBrowser.setText("RSA公钥私钥创建成功")

    def CreatePem(self, filePath, size):
        filePath, _ = os.path.splitext(filePath)
        init = self.comboBoxInit.currentText()
        sauce = createkey.generate_key(size)
        # 获取当前激活的 tab
        currentTab = self.tabWidget.currentWidget()
        # 在当前 tab 中查找 QTextBrowser
        textBrowser = currentTab.findChild(QtWidgets.QTextBrowser)
        if init == "系统随机":
            with open(filePath + ".pem", "wb") as file_out:
                file_out.write(sauce)
            return sauce
        elif init == "使用口令":
            password = self.lineEditPass.text()
            key = createkey.generate_key_from_password(password, sauce, size)
            with open(filePath + ".passpem", "wb") as file_out:
                file_out.write(sauce)
            return key
        elif init == "使用RSA公钥":
            encrypted_key = createkey.secure_key_with_rsa(RSA.import_key(open(self.publicKeyFilePath).read()), sauce)
            with open(filePath + ".rsapem", "wb") as file_out:
                file_out.write(encrypted_key)
            return sauce

        textBrowser.setText("密钥创建成功")

    def CreatePem2(self, filePath, size):
        filePath, _ = os.path.splitext(filePath)
        init = self.comboBoxInit2.currentText()
        sauce = createkey.generate_key(size)
        # 获取当前激活的 tab
        currentTab = self.tabWidget.currentWidget()
        # 在当前 tab 中查找 QTextBrowser
        textBrowser = currentTab.findChild(QtWidgets.QTextBrowser)
        if init == "系统随机":
            with open(filePath + ".pem", "wb") as file_out:
                file_out.write(sauce)
            return sauce
        elif init == "使用口令":
            password = self.lineEditPass2.text()
            key = createkey.generate_key_from_password(password, sauce, size)
            with open(filePath + ".passpem", "wb") as file_out:
                file_out.write(sauce)
            return key
        elif init == "使用RSA公钥":
            encrypted_key = createkey.secure_key_with_rsa(RSA.import_key(open(self.publicKeyFilePath).read()), sauce)
            with open(filePath + ".rsapem", "wb") as file_out:
                file_out.write(encrypted_key)
            return sauce

        textBrowser.setText("密钥创建成功")

    def DecryptPem(self, pempath, size):
        init = self.comboBoxInit.currentText()
        # 获取当前激活的 tab
        currentTab = self.tabWidget.currentWidget()
        # 在当前 tab 中查找 QTextBrowser
        textBrowser = currentTab.findChild(QtWidgets.QTextBrowser)
        key = ""
        if init == "系统随机":
            with open(pempath, "rb") as file_in:
                key = file_in.read()
            return key
        elif init == "使用口令":
            password = self.lineEditPass.text()
            with open(pempath, "rb") as file_in:
                salt = file_in.read()
            key = createkey.generate_key_from_password(password, salt, size)
            return key
        elif init == "使用RSA公钥":
            with open(pempath, "rb") as file_in:
                encrypt_key = file_in.read()
            decrypted_key = createkey.decrypt_key_with_rsa(RSA.import_key(
                open(self.privateKeyFilePath).read()), encrypt_key)
            return decrypted_key

        textBrowser.setText("密钥解密成功")

    def DecryptPem2(self, pempath, size):
        init = self.comboBoxInit2.currentText()
        # 获取当前激活的 tab
        currentTab = self.tabWidget.currentWidget()
        # 在当前 tab 中查找 QTextBrowser
        textBrowser = currentTab.findChild(QtWidgets.QTextBrowser)
        key = ""
        if init == "系统随机":
            with open(pempath, "rb") as file_in:
                key = file_in.read()
            return key
        elif init == "使用口令":
            password = self.lineEditPass2.text()
            with open(pempath, "rb") as file_in:
                salt = file_in.read()
            key = createkey.generate_key_from_password(password, salt, size)
            return key
        elif init == "使用RSA公钥":
            with open(pempath, "rb") as file_in:
                encrypt_key = file_in.read()
            decrypted_key = createkey.decrypt_key_with_rsa(RSA.import_key(
                open(self.privateKeyFilePath).read()), encrypt_key)
            return decrypted_key

        textBrowser.setText("密钥解密成功")

    def ChoosePublicKey(self):
        options = QtWidgets.QFileDialog.Options()
        filePath, _ = QtWidgets.QFileDialog.getOpenFileName(self, "选择公钥文件", "", "公钥文件(*.pem)",
                                                            options=options)
        if not filePath:
            return
        abs_path = os.path.abspath(filePath)
        self.publicKeyFilePath = abs_path

    def ChoosePrivateKey(self):
        options = QtWidgets.QFileDialog.Options()
        filePath, _ = QtWidgets.QFileDialog.getOpenFileName(self, "选择私钥文件", "", "私钥文件(*.pem)",
                                                            options=options)
        if not filePath:
            return
        abs_path = os.path.abspath(filePath)
        self.privateKeyFilePath = abs_path

    def ChooseNeedEncryptFile(self):
        options = QtWidgets.QFileDialog.Options()
        filePath, _ = QtWidgets.QFileDialog.getOpenFileName(self, "选择文件", "", "任意文件(*.*)", options=options)
        if not filePath:
            return
        abs_path = os.path.abspath(filePath)
        self.lineEditNeedEncryptFilePath.setText(abs_path)

    def CreateVHD(self):
        # 读取VHD创建参数
        algorithm = self.comboBoxAlgorithm.currentText()
        mode = self.comboBoxMode.currentText()
        filesize = self.lineEditSize.text()
        format = self.comboBoxFormat.currentText()
        # 获取当前激活的 tab
        currentTab = self.tabWidget.currentWidget()
        # 在当前 tab 中查找 QTextBrowser
        textBrowser = currentTab.findChild(QtWidgets.QTextBrowser)

        # 选择保存路径
        options = QtWidgets.QFileDialog.Options()
        filePath, _ = QtWidgets.QFileDialog.getSaveFileName(self, "创建文件", "", "加密虚拟硬盘(*.vhd)",
                                                            options=options)
        if not filePath:
            return
        abs_path = os.path.abspath(filePath)

        # 创建VHD文件
        last_volumn_index = vdisk.diskpart_create_vdisk(abs_path, filesize, format)
        vdisk.diskpart_unmount(abs_path, last_volumn_index)

        # 加密VHD文件
        key = self.CreatePem(abs_path, sizes[algorithm])
        if algorithm == "3DES":
            key = DES3.adjust_key_parity(key)
            tripledes.encrypt_file(abs_path, key, mode)
        elif algorithm in ("AES-128", "AES-196", "AES-256"):
            aes.encrypt_file(abs_path, key, mode)

        textBrowser.setText("虚拟硬盘创建成功")

    def CreateEncryptfile(self):
        # 读取参数
        algorithm = self.comboBoxAlgorithm2.currentText()
        mode = self.comboBoxMode2.currentText()
        abs_path = self.lineEditNeedEncryptFilePath.text()
        # 获取当前激活的 tab
        currentTab = self.tabWidget.currentWidget()
        # 在当前 tab 中查找 QTextBrowser
        textBrowser = currentTab.findChild(QtWidgets.QTextBrowser)

        # 选择保存路径
        options = QtWidgets.QFileDialog.Options()
        saveas_path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "选择保存位置", "", "任意文件(*.*)",
                                                               options=options)
        if not saveas_path:
            return

        # 加密文件
        key = self.CreatePem2(saveas_path, sizes[algorithm])
        if algorithm == "3DES":
            key = DES3.adjust_key_parity(key)
            tripledes.encrypt_file_saveas(abs_path, key, mode, saveas_path)
        elif algorithm in ("AES-128", "AES-196", "AES-256"):
            aes.encrypt_file_saveas(abs_path, key, mode, saveas_path)

        textBrowser.setText("文件加密成功")

    def LoadVHD(self):
        # 读取VHD参数
        algorithm = self.comboBoxAlgorithm.currentText()
        self.currentalgorithm = algorithm
        mode = self.comboBoxMode.currentText()
        self.currentmode = mode
        # 获取当前激活的 tab
        currentTab = self.tabWidget.currentWidget()
        # 在当前 tab 中查找 QTextBrowser
        textBrowser = currentTab.findChild(QtWidgets.QTextBrowser)

        # 选择加载路径
        options = QtWidgets.QFileDialog.Options()
        filePath, _ = QtWidgets.QFileDialog.getOpenFileName(self, "选择加密磁盘文件", "", "加密虚拟硬盘(*.vhd)",
                                                            options=options)
        if not filePath:
            return
        abs_path = os.path.abspath(filePath)
        self.currentVHDfilepath = abs_path

        # 选择密钥文件
        pempath, _ = QtWidgets.QFileDialog.getOpenFileName(self, "选择密钥文件", "",
                                                           "密钥文件(*.pem);;密码保护文件(*.passpem);;RSA密钥文件(*.rsapem)",
                                                           options=options)
        if not pempath:
            return
        pempath = os.path.abspath(pempath)
        self.currentpempath = pempath

        # 解密密钥文件
        key = self.DecryptPem(pempath,sizes[algorithm])
        self.currentkey = key

        # 解密文件
        if algorithm == "3DES":
            key = DES3.adjust_key_parity(key)
            tripledes.decrypt_file(abs_path, key, mode)
        elif algorithm in ("AES-128", "AES-196", "AES-256"):
            aes.decrypt_file(abs_path, key, mode)

        # 加载虚拟硬盘
        self.last_volumn_index = vdisk.diskpart_attach_vdisk(abs_path)
        textBrowser.setText("虚拟硬盘加载成功")

    def UnmountVHD(self):
        if not self.last_volumn_index:
            print("请先卸载当前硬盘")

        # 卸载虚拟硬盘
        vdisk.diskpart_unmount(self.currentVHDfilepath, self.last_volumn_index)
        # 重新加密硬盘
        if self.currentalgorithm == "3DES":
            key = DES3.adjust_key_parity(self.currentkey)
            tripledes.encrypt_file(self.currentVHDfilepath, key, self.currentmode)
        elif self.currentalgorithm in ("AES-128", "AES-196", "AES-256"):
            aes.encrypt_file(self.currentVHDfilepath, self.currentkey, self.currentmode)
        # 重置临时参数
        self.last_volumn_index = ""
        self.currentkey = ""
        self.currentmode = ""
        self.currentalgorithm = ""
        self.currentVHDfilepath = ""
        self.currentpempath = ""

    def DecryptFile(self):
        # 读取参数
        algorithm = self.comboBoxAlgorithm2.currentText()
        mode = self.comboBoxMode2.currentText()
        abs_path = self.lineEditNeedEncryptFilePath.text()
        # 获取当前激活的 tab
        currentTab = self.tabWidget.currentWidget()
        # 在当前 tab 中查找 QTextBrowser
        textBrowser = currentTab.findChild(QtWidgets.QTextBrowser)

        # 选择保存路径
        options = QtWidgets.QFileDialog.Options()
        saveas_path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "选择保存位置", "", "任意文件(*.*)", options=options)
        if not saveas_path:
            return
        saveas_path = os.path.abspath(saveas_path)
        self.currentVHDfilepath = abs_path

        # 选择密钥文件
        pempath, _ = QtWidgets.QFileDialog.getOpenFileName(self, "选择密钥文件", "",
                                                           "密钥文件(*.pem);;密码保护文件(*.passpem);;RSA密钥文件(*.rsapem)",
                                                           options=options)
        if not pempath:
            return
        pempath = os.path.abspath(pempath)
        self.currentpempath = pempath

        # 解密密钥文件
        key = self.DecryptPem2(pempath,sizes[algorithm])

        # 解密文件
        if algorithm == "3DES":
            key = DES3.adjust_key_parity(key)
            tripledes.decrypt_file_saveas(abs_path, key, mode, saveas_path)
        elif algorithm in ("AES-128", "AES-196", "AES-256"):
            aes.decrypt_file_saveas(abs_path, key, mode, saveas_path)

        textBrowser.setText("文件解密成功")


if __name__ == "__main__":
    import sys

    app = QtWidgets.QApplication(sys.argv)
    mainWindow = MyApplication()
    mainWindow.show()
    sys.exit(app.exec_())
