from PyQt5 import QtWidgets, uic
import vhdmount.diskpart as vdisk
class MyApplication(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        uic.loadUi('pymycrypt.ui', self)

        self.pushButtonCreate.clicked.connect(self.CreateVHD)

    def CreateVHD(self):
        # 读取VHD创建参数
        algorithm = self.comboBoxAlgorithm.currentText()
        mode = self.comboBoxMode.currentText()
        size = self.lineEditSize.text()
        format = self.comboBoxFormat.currentText()
        # 选择保存路径
        options = QtWidgets.QFileDialog.Options()
        filePath,_ = QtWidgets.QFileDialog.getSaveFileName(self,"创建文件","","加密虚拟硬盘(*.vhd)",options=options)
        #创建VHD文件
        last_volumn_index = vdisk.diskpart_create_vdisk(filePath,size,format)
        vdisk.diskpart_unmount(filePath, last_volumn_index)
        #加密VHD文件




if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    mainWindow = MyApplication()
    mainWindow.show()
    sys.exit(app.exec_())
