import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QWidget, QTableWidget, QTableWidgetItem, QVBoxLayout


class PerformanceWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("加密算法性能展示")
        self.setGeometry(100, 100, 600, 400)
        self.tableWidget = QTableWidget()
        self.setCentralWidget(self.tableWidget)

        self.tableWidget.setColumnCount(3)
        self.tableWidget.setHorizontalHeaderLabels(["算法", "模式", "速度 (MB/s)"])

        algorithms = [
            ['3DES', 'ECB'], ['3DES', 'CBC'], ['3DES', 'CTR'], ['3DES', 'CFB'], ['3DES', 'OFB'],
            ['AES-128', 'ECB'], ['AES-128', 'CBC'], ['AES-128', 'CTR'], ['AES-128', 'CFB'], ['AES-128', 'OFB'],
            ['AES-196', 'ECB'], ['AES-196', 'CBC'], ['AES-196', 'CTR'], ['AES-196', 'CFB'], ['AES-196', 'OFB'],
            ['AES-256', 'ECB'], ['AES-256', 'CBC'], ['AES-256', 'CTR'], ['AES-256', 'CFB'], ['AES-256', 'OFB']
        ]
        speeds = [
            1.5739316940307617, 1.7540876865386963, 1.5700364112854004, 12.988267660140991, 1.6931896209716797,
            0.04346156120300293, 0.10667228698730469, 0.03499031066894531, 0.9633231163024902, 0.11893486976623535,
            0.05996870994567871, 0.13137078285217285, 0.04579472541809082, 1.1208350658416748, 0.13944005966186523,
            0.059059858322143555, 0.1422579288482666, 0.04595661163330078, 1.2476253509521484, 0.13929271697998047
        ]

        self.tableWidget.setRowCount(len(algorithms))
        for row, (algorithm, speed) in enumerate(zip(algorithms, speeds)):
            self.tableWidget.setItem(row, 0, QTableWidgetItem(algorithm[0]))
            self.tableWidget.setItem(row, 1, QTableWidgetItem(algorithm[1]))
            self.tableWidget.setItem(row, 2, QTableWidgetItem(f"{speed:.3f}"))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("主窗口")
        self.setGeometry(100, 100, 200, 100)

        self.button = QPushButton("显示加密算法性能", self)
        self.button.clicked.connect(self.showPerformanceWindow)
        self.button.resize(180, 30)
        self.button.move(10, 30)

        self.performanceWindow = PerformanceWindow()  # 创建加密算法性能展示窗口但不立即显示

    def showPerformanceWindow(self):
        self.performanceWindow.show()  # 显示加密算法性能窗口


if __name__ == "__main__":
    app = QApplication(sys.argv)
    mainWindow = MainWindow()
    mainWindow.show()
    sys.exit(app.exec_())
