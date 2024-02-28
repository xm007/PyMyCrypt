import ast
import os.path
import time

from Crypto.Random import get_random_bytes
from PyQt5 import QtWidgets, uic
from PyQt5.QtWidgets import QMessageBox, QTableWidgetItem

import encrypt
import vhdmount.diskpart as vdisk
from encrypt import aes, tripledes, filehash,createkey

sizes = {
    "3DES": 24,
    "AES-128": 16,
    "AES-196": 24,
    "AES-256": 32
}

class MyApplication(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        uic.loadUi('pymycrypt2.ui', self)
        self.last_volumn_index = ""
        self.currentVHDfilepath = ""
        # 算法耗时测试
        self.tableWidgetSpeedTest.setHorizontalHeaderLabels(["算法", "模式", "耗时 (毫秒)"])
        self.pushButtonSpeedTest.clicked.connect(self.CalcFunctionTime)
        # 创建虚拟硬盘页
        self.pushButtonCreateVHD.clicked.connect(self.CreateVHD)
        # 加密虚拟磁盘页
        self.pushButtonEncryptVHD.clicked.connect(self.EncryptVHD)
        # 管理虚拟磁盘页
        self.pushButtonLoadVHD.clicked.connect(self.LoadVHD)
        self.pushButtonUnmountVHD.clicked.connect(self.UnmountVHD)
        # 加密文件页
        self.pushButtonEncryptFile.clicked.connect(self.EncryptFile)
        # 解密文件
        self.pushButtonDecryptFile.clicked.connect(self.DecryptFile)
        # 加解密文本
        self.pushButtonEncryptText.clicked.connect(self.EncryptText)
        self.pushButtonDecryptText.clicked.connect(self.DecryptText)
        # 文件HASH
        self.pushButtonCalcHash.clicked.connect(self.CalcHash)
        self.pushButtonVerifyHash.clicked.connect(self.VerifyHash)
        # 生成RSA
        self.pushButtonRSAGen.clicked.connect(self.RSAGenerate)
        # 数字签名
        self.pushButtonSignGen.clicked.connect(self.SignGenerate)
        self.pushButtonSignVerify.clicked.connect(self.SignVerify)

    def CreateVHD(self):
        # 读取VHD创建参数
        filesize = self.lineEditSize.text()
        format = self.comboBoxFormat.currentText()

        # 选择保存路径
        options = QtWidgets.QFileDialog.Options()
        filepath, _ = QtWidgets.QFileDialog.getSaveFileName(self, "创建文件", "", "加密虚拟硬盘(*.vhd)",
                                                            options=options)
        if not filepath:
            return
        abs_path = os.path.abspath(filepath)

        # 创建VHD文件
        last_volumn_index = vdisk.diskpart_create_vdisk(abs_path, filesize, format)
        vdisk.diskpart_unmount(abs_path, last_volumn_index)

    def EncryptVHD(self):
        # 读取VHD加密参数
        algorithm = self.comboBoxAlgorithmEncryptVHD.currentText()
        mode = self.comboBoxModeEncryptVHD.currentText()
        password = self.lineEditPassEncryptVHD.text()

        # 选择文件
        options = QtWidgets.QFileDialog.Options()
        filePath, _ = QtWidgets.QFileDialog.getOpenFileName(self, "选择文件", "", "虚拟磁盘文件(*.vhd)", options=options)
        if not filePath:
            return
        abs_path = os.path.abspath(filePath)
        # # 添加加密文件名后缀
        # saveas_path = os.path.splitext(abs_path)+ ".enc"
        # 选择保存路径
        default_file_name = os.path.basename(abs_path)
        default_dir = os.path.dirname(abs_path)
        options = QtWidgets.QFileDialog.Options()
        options |= QtWidgets.QFileDialog.DontUseNativeDialog
        saveas_path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "选择保存路径", os.path.join(default_dir, default_file_name), "加密虚拟硬盘(*.*)",
                                                            options=options)
        if not saveas_path:
            return
        saveas_path = os.path.abspath(saveas_path)

        # 加密VHD文件
        if algorithm == "3DES":
            tripledes.encrypt_file_saveas_withpassword(abs_path,password,mode,saveas_path,sizes[algorithm])
        elif algorithm in ("AES-128", "AES-196", "AES-256"):
            aes.encrypt_file_saveas_withpassword(abs_path,password,mode,saveas_path,sizes[algorithm])

    def LoadVHD(self):
        # 读取VHD加密参数
        algorithm = self.comboBoxAlgorithmManageVHD.currentText()
        mode = self.comboBoxModeManageVHD.currentText()
        password = self.lineEditPassManageVHD.text()

        # 选择加载路径
        options = QtWidgets.QFileDialog.Options()
        filePath, _ = QtWidgets.QFileDialog.getOpenFileName(self, "选择磁盘文件", "", "加密虚拟硬盘(*.*)",
                                                            options=options)
        if not filePath:
            return
        abs_path = os.path.abspath(filePath)

        # 选择保存路径
        default_file_name = os.path.basename(abs_path)
        default_dir = os.path.dirname(abs_path)
        options = QtWidgets.QFileDialog.Options()
        options |= QtWidgets.QFileDialog.DontUseNativeDialog
        saveas_path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "选择解密后保存路径", os.path.join(default_dir, default_file_name), "加密虚拟硬盘(*.*)",
                                                            options=options)
        if not saveas_path:
            return
        saveas_path = os.path.abspath(saveas_path)

        self.currentVHDfilepath = saveas_path

        # # 检查文件是否包含加密后缀.enc
        # if filePath.endswith('.enc'):
        #     saveas_path = filePath[:-4] # 移除最后四个字符
        #     self.currentVHDfilepath = saveas_path
            # 解密VHD文件
        if algorithm == "3DES":
            tripledes.decrypt_file_saveas_withpassword(abs_path, password, mode, saveas_path,sizes[algorithm])
        elif algorithm in ("AES-128", "AES-196", "AES-256"):
            aes.decrypt_file_saveas_withpassword(abs_path, password, mode, saveas_path,sizes[algorithm])
        self.last_volumn_index = vdisk.diskpart_attach_vdisk(saveas_path)
        # else:
        #     self.last_volumn_index = vdisk.diskpart_attach_vdisk(abs_path)

    def UnmountVHD(self):
        # 卸载虚拟硬盘
        vdisk.diskpart_unmount(self.currentVHDfilepath, self.last_volumn_index)

        # 重置参数
        self.currentVHDfilepath = ""
        self.last_volumn_index = ""

    def EncryptFile(self):
        # 读取加密参数
        algorithm = self.comboBoxAlgorithmEncryptFile.currentText()
        mode = self.comboBoxModeEncryptFile.currentText()
        password = self.lineEditPassCryptVHDEncryptFile.text()

        # 选择文件
        options = QtWidgets.QFileDialog.Options()
        filePath, _ = QtWidgets.QFileDialog.getOpenFileName(self, "选择文件", "", "任意文件(*.*)", options=options)
        if not filePath:
            return
        abs_path = os.path.abspath(filePath)
        # # 添加加密文件名后缀
        # saveas_path = os.path.splitext(abs_path)+ ".enc"
        # 选择保存路径
        default_file_name = os.path.basename(abs_path)
        default_dir = os.path.dirname(abs_path)
        options = QtWidgets.QFileDialog.Options()
        options |= QtWidgets.QFileDialog.DontUseNativeDialog
        saveas_path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "选择保存路径", os.path.join(default_dir, default_file_name), "加密文件(*.*)",
                                                            options=options)
        if not saveas_path:
            return
        saveas_path = os.path.abspath(saveas_path)

        # 加密VHD文件
        if algorithm == "3DES":
            tripledes.encrypt_file_saveas_withpassword(abs_path,password,mode,saveas_path,sizes[algorithm])
        elif algorithm in ("AES-128", "AES-196", "AES-256"):
            aes.encrypt_file_saveas_withpassword(abs_path,password,mode,saveas_path,sizes[algorithm])

    def DecryptFile(self):
        # 读取解密参数
        algorithm = self.comboBoxAlgorithmDecryptFile.currentText()
        mode = self.comboBoxModeDecryptFile.currentText()
        password = self.lineEditPassDecryptFile.text()

        # 选择加载路径
        options = QtWidgets.QFileDialog.Options()
        filePath, _ = QtWidgets.QFileDialog.getOpenFileName(self, "选择磁盘文件", "", "任意文件(*.*)",
                                                            options=options)
        if not filePath:
            return
        abs_path = os.path.abspath(filePath)
        # 选择保存路径
        default_file_name = os.path.basename(abs_path)
        default_dir = os.path.dirname(abs_path)
        options = QtWidgets.QFileDialog.Options()
        options |= QtWidgets.QFileDialog.DontUseNativeDialog
        saveas_path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "选择保存路径", os.path.join(default_dir, default_file_name), "加密文件(*.*)",
                                                            options=options)
        if not saveas_path:
            return
        saveas_path = os.path.abspath(saveas_path)

        # 检查文件是否包含加密后缀.enc
        # if filePath.endswith('.enc'):
        #     saveas_path = filePath[:-4]  # 移除最后四个字符
        # 解密VHD文件
        if algorithm == "3DES":
            tripledes.decrypt_file_saveas_withpassword(abs_path, password, mode, saveas_path,sizes[algorithm])
        elif algorithm in ("AES-128", "AES-196", "AES-256"):
            aes.decrypt_file_saveas_withpassword(abs_path, password, mode, saveas_path,sizes[algorithm])
        # else:
        #     return

    def EncryptText(self):
        # 读取参数
        algorithm = self.comboBoxAlgorithmText.currentText()
        mode = self.comboBoxModeText.currentText()
        password = self.lineEditPassText.text()
        plaintext = self.textEditPlainText.toPlainText().encode('utf-8')


        # 加密明文
        if algorithm == "3DES":
            encrypttext = tripledes.encryptwithpassword(password,plaintext,mode,sizes[algorithm])
        elif algorithm in ("AES-128", "AES-196", "AES-256"):
            encrypttext = aes.encryptwithpassword(password,plaintext,mode,sizes[algorithm])

        # 设置文本框
        self.textEditEncryptText.setPlainText(repr(encrypttext))

    def DecryptText(self):
        # 读取参数
        algorithm = self.comboBoxAlgorithmText.currentText()
        mode = self.comboBoxModeText.currentText()
        password = self.lineEditPassText.text()
        encrypttext = self.textEditEncryptText.toPlainText()
        encrypttext = ast.literal_eval(encrypttext)

        # 解密明文
        if algorithm == "3DES":
            decrypttext = tripledes.decryptwithpassword(password,encrypttext,mode,sizes[algorithm])
        elif algorithm in ("AES-128", "AES-196", "AES-256"):
            decrypttext = aes.decryptwithpassword(password,encrypttext,mode,sizes[algorithm])

        # 设置文本框
        self.textEditPlainText.setPlainText(decrypttext.decode('utf-8'))

    def CalcHash(self):
        # 读取参数
        mode = self.comboBoxHashMode.currentText()

        # 选择加载路径
        options = QtWidgets.QFileDialog.Options()
        filePath, _ = QtWidgets.QFileDialog.getOpenFileName(self, "选择文件", "", "任意文件(*.*)",
                                                            options=options)
        if not filePath:
            return
        abs_path = os.path.abspath(filePath)

        # 计算hash
        hash = filehash.calculate_hash(abs_path,mode)
        self.textEditHash.setPlainText(hash)

    def VerifyHash(self):
        # 读取参数
        mode = self.comboBoxHashMode.currentText()
        hash = self.textEditHash.toPlainText()

        # 选择加载路径
        options = QtWidgets.QFileDialog.Options()
        filePath, _ = QtWidgets.QFileDialog.getOpenFileName(self, "选择文件", "", "任意文件(*.*)",
                                                            options=options)
        if not filePath:
            return
        abs_path = os.path.abspath(filePath)

        # 验证HASH
        if filehash.verify_file_hash(abs_path, hash, mode):
            QMessageBox.information(self, "验证结果", "文件验证成功！", QMessageBox.Ok)
        else:
            QMessageBox.warning(self, "验证结果", "文件验证失败！", QMessageBox.Ok)

    def RSAGenerate(self):
        # 读取参数
        algorithm = self.comboBoxAlgorithmRSAGen.currentText()
        # 选择保存位置
        options = QtWidgets.QFileDialog.Options()
        options |= QtWidgets.QFileDialog.DontUseNativeDialog
        publicpem_path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "选择公钥保存路径", '', "公钥文件(*.pem)",
                                                            options=options)
        if not publicpem_path:
            return
        publicpem_path = os.path.abspath(publicpem_path)


        options = QtWidgets.QFileDialog.Options()
        options |= QtWidgets.QFileDialog.DontUseNativeDialog
        privatepem_path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "选择私钥保存路径", '', "私钥文件(*.pem)",
                                                            options=options)
        if not privatepem_path:
            return
        privatepem_path = os.path.abspath(privatepem_path)

        # 生成公钥私钥
        if algorithm == "RSA":
            publickey,privatekey = createkey.generate_rsa()
        else:
            publickey, privatekey = createkey.generate_ecc()

        with open(publicpem_path+'.pem','w') as publicpem:
            publicpem.write(publickey)
        with open(privatepem_path+'.pem', 'w') as privatepem:
            privatepem.write(privatekey)

    def SignGenerate(self):
        # 读取参数
        algorithm = self.comboBoxAlgorithmSign.currentText()
        mode = self.comboBoxHashModeSign.currentText()

        # 选择加载路径
        options = QtWidgets.QFileDialog.Options()
        filePath, _ = QtWidgets.QFileDialog.getOpenFileName(self, "选择文件", "", "任意文件(*.*)",
                                                            options=options)
        if not filePath:
            return
        abs_path = os.path.abspath(filePath)
        # 选择私钥
        options = QtWidgets.QFileDialog.Options()
        privatepem_path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "选择私钥文件", "", "私钥文件(*.pem)",
                                                            options=options)
        if not privatepem_path:
            return
        privatepem_path = os.path.abspath(privatepem_path)

        # # 选择保存路径
        # default_file_name = os.path.basename(abs_path)
        # default_dir = os.path.dirname(abs_path)
        # options = QtWidgets.QFileDialog.Options()
        # options |= QtWidgets.QFileDialog.DontUseNativeDialog
        # saveas_path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "选择签名保存路径", os.path.join(default_dir, default_file_name+'.sign'), "签名文件(*.*)",
        #                                                     options=options)
        # if not saveas_path:
        #     return
        # saveas_path = os.path.abspath(saveas_path)

        # 保存签名
        if algorithm == 'ECC':
            createkey.sign_file(abs_path, privatepem_path, abs_path + '.sign', mode='SHA256', algorithm='ECC')
        else:
            createkey.sign_file(abs_path, privatepem_path, abs_path + '.sign', mode, algorithm)

    def SignVerify(self):
        # 读取参数
        algorithm = self.comboBoxAlgorithmSign.currentText()
        mode = self.comboBoxHashModeSign.currentText()

        # 选择加载路径
        options = QtWidgets.QFileDialog.Options()
        filePath, _ = QtWidgets.QFileDialog.getOpenFileName(self, "选择文件", "", "任意文件(*.*)",
                                                            options=options)
        if not filePath:
            return
        abs_path = os.path.abspath(filePath)

        # 选择公钥
        options = QtWidgets.QFileDialog.Options()
        publicpem_path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "选择公钥文件", "", "公钥文件(*.pem)",
                                                            options=options)
        if not publicpem_path:
            return
        publicpem_path = os.path.abspath(publicpem_path)

        # 选择文件签名路径
        options = QtWidgets.QFileDialog.Options()
        signPath, _ = QtWidgets.QFileDialog.getOpenFileName(self, "选择文件签名", "", "签名文件(*.sign)",
                                                            options=options)
        if not signPath:
            return
        signPath = os.path.abspath(signPath)

        # 验证HASH
        if algorithm == "ECC":
            isVerified = createkey.verify_signature(abs_path,signPath,publicpem_path,mode='SHA256',algorithm='ECC')
        else:
            isVerified = createkey.verify_signature(abs_path, signPath, publicpem_path, mode, algorithm)
        if isVerified:
            QMessageBox.information(self, "验证结果", "文件验证成功！", QMessageBox.Ok)
        else:
            QMessageBox.warning(self, "验证结果", "文件验证失败！", QMessageBox.Ok)

    def CalcFunctionTime(self):
        size = self.lineEditSizeSpeedTest.text()
        paraments = []
        times = []
        plaintext = get_random_bytes(int(size)*1024*1024)
        for index in range(self.comboBoxAlgorithmEncryptVHD.count()):
            algorithm = self.comboBoxAlgorithmEncryptVHD.itemText(index)
            for index2 in range(self.comboBoxModeEncryptVHD.count()):
                mode = self.comboBoxModeEncryptVHD.itemText(index2)
                paraments.append([algorithm,mode])
        for items in paraments:
            if items[0] == "3DES":
                start_time = time.time()
                key = createkey.generate_key(sizes[items[0]])
                tripledes.encrypt(key,plaintext,items[1])
                end_time = time.time()
                times.append(int((end_time - start_time) * 1000))
            if items[0] in ("AES-128", "AES-196", "AES-256"):
                start_time = time.time()
                key = createkey.generate_key(sizes[items[0]])
                aes.encrypt(key,plaintext,items[1])
                end_time = time.time()
                times.append(int((end_time - start_time) * 1000))
        self.tableWidgetSpeedTest.setRowCount(len(paraments))
        for row, ((algorithm, mode), item) in enumerate(zip(paraments, times)):
            self.tableWidgetSpeedTest.setItem(row, 0, QTableWidgetItem(algorithm))
            self.tableWidgetSpeedTest.setItem(row, 1, QTableWidgetItem(mode))
            self.tableWidgetSpeedTest.setItem(row, 2, QTableWidgetItem(f"{item}"))

if __name__ == "__main__":
    import sys

    app = QtWidgets.QApplication(sys.argv)
    mainWindow = MyApplication()
    mainWindow.show()
    sys.exit(app.exec_())
