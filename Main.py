"""#########################################################################
Title: QuantuMessage Main systems                   Version: 1.0

Author: James Norman                                Development stage: 2

Start Date: 23/04/2019                              Language: Python v3.6.4

Description: Display and NetworkInterface classes for
             QuantuMessage messaging system

Modules: logging, socket, threading, diffiehellman

Disclaimer:
Any form of encryption used within this software is experimental and has
NO PROOF OF SECURITY WHATSOEVER. Therefore it is highly recommended that
NO ONE USE THE ENCRYPTION WITHIN THIS CODE UNDER ANY CIRCUMSTANCES.

Anyone using this encryption system does so at their own risk.
The developer accepts NO RESPONSIBILITY for any loss or theft of
data as a result of using the encryption algorithms in this software.

Copyright (C) 2019 James Norman

License:
This file is part of QuantuMessage.

QuantuMessage is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

QuantuMessage is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with QuantuMessage.  If not, see <https://www.gnu.org/licenses/>.
#########################################################################"""
import logging
import pickle
import socket
import sys
import threading
import time
import traceback
import winsound
from _thread import start_new_thread

from PyQt5 import QtWidgets
from diffiehellman.diffiehellman import DiffieHellman

import Encryption

# Lock setup
displayLock = threading.Lock()

# Dictionary used for classes to communicate
classReferences = dict()

# Logging/logfile setup
formatter = logging.Formatter(fmt="%(asctime)s %(levelname)-8s %(message)s", datefmt="%d/%m/%Y %H:%M:%S")
fileWriter = logging.FileHandler("./Log/Main.log", mode="w")
fileWriter.setFormatter(formatter)
screenWriter = logging.StreamHandler(stream=sys.stdout)
screenWriter.setFormatter(formatter)
logger = logging.getLogger("Main")
logger.setLevel(logging.DEBUG)
logger.addHandler(fileWriter)
logger.addHandler(screenWriter)

# Disclaimer/license setup
with open("./COPYING.txt", "r") as f:
    programLicense = f.read()
print(programLicense)
disclaimer = """Disclaimer:
Any form of encryption used within this software is experimental and has
NO PROOF OF SECURITY WHATSOEVER. Therefore it is highly recommended that
NO ONE USE THE ENCRYPTION WITHIN THIS CODE UNDER ANY CIRCUMSTANCES.

Anyone using this encryption system does so at their own risk.
The developer accepts NO RESPONSIBILITY for any loss or theft of
data as a result of using the encryption algorithms in this software.
"""


class ReceiveMessagesThread(object):
    """Class to hold listener socket for receiving incoming messages"""
    running = True
    keyExchanger = DiffieHellman()  # DH key exchange used for messages
    
    signer = Encryption.SignatureAlgorithm()
    host = socket.gethostname()
    port = 23419

    def __init__(self, graph, keys):
        self.encrypter = Encryption.SymmetricKeyAlgorithm(graph, keys)
        classReferences["ReceiveMessagesThread"] = self
        t = threading.Thread(target=self.receiveConnections)  # Receiver kept in a separate thread to promote real-time updates
        t.daemon = True
        t.start()

    def receiveConnections(self):
        """Listens for connection requests and passes them on to a thread"""
        listener = self.initialiseListener()
        listener.listen(5)
        logger.info("Receiver Listening")
        while self.running:
            connection, address = listener.accept()
            logger.info("Connection %s at %s"%(connection, address))
            start_new_thread(self.receiveData, (connection,))

    def receiveData(self, connection):
        """Receives incoming messages within a separate thread"""
        received = False
        message = []
        while not received:
            start, end = self.generateSecureConnection(connection, "receiver")
            connection.sendall(str.encode(self.encrypter.encryptMessage("Ready", start, end)))  # Confirms connection
            logger.info("Confirmation sent")
            start, end = self.generateSecureConnection(connection, "sender")
            data = connection.recv(2**30)                 
            if not data:
                break
            else:
                if len(data) > 0:
                    connection.sendall(str.encode("1"))  # Confirmation of message receipt
                    received = True
                else:
                    connection.sendall(str.encode("0"))
        connection.close()
        encrypted_message = pickle.loads(data)
        for section in encrypted_message:
            message.append(self.encrypter.decryptMessage(section, start, end))
        with displayLock:
            winsound.PlaySound("Alert.wav", winsound.SND_FILENAME)
            
            classReferences["Display"].displayReceivedMessage(message)

    def initialiseListener(self):
        """Sets up socket to listen on port 23419"""
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2**30)  # Increases the send buffer
        # Send buffer does not currently need to be this large, but may be useful later.
        listener.bind((self.host, self.port))
        listener.listen(5)  # Starts up listener with timeout 5 seconds
        return listener
    
    def generateSecureConnection(self, connection, state):
        """Intended to generate two shared secrets for use in the cryptosystem.
        Python does not allow such large volumes of data to be sent via sockets
        and so it simply returns two example keys.
        """
        return 5, 138


class NetworkInterface(object):
    """Class to handle networking and data transfer to another client"""
    host = socket.gethostname()
    port = 23419
    verifier = Encryption.SignatureAlgorithm()  # Used to verify signatures

    def __init__(self, graph, keys):
        self.keyExchanger = DiffieHellman()  # DH key exchange
        self.encrypter = Encryption.SymmetricKeyAlgorithm(graph, keys)
        classReferences["NetworkInterface"] = self  # References itself for other classes

    def connectToReceiver(self, receiverName):
        """Creates a socket and uses it to connect to the specified receiver"""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2**30)  # Increases the send buffer
        # Send buffer does not currently need to be this large, but may be useful later. 
        s.connect((receiverName, self.port))
        return s

    def sendMessage(self, message, receiver):
        """Creates a connection with the specified receiver, sets up an info
        package and sends it to the receiver
        """
        received = False  # Flag for message reception
        attempts = 0
        connected = False  # Flag for connection to receiver
        while not connected and attempts < 2:
            try:
                sender = self.connectToReceiver(receiver)
                connected = True
            except Exception as e:
                logger.error(traceback.format_exc())
                attempts += 1
                continue
        if connected:
            try:
                start, end = self.generateSecureConnection(sender, "sender")
                confirmation = sender.recv(2048)
                logger.info(self.encrypter.decryptMessage(confirmation.decode("utf-8"), start, end))  # Logs confirmation of connection
                start, end = self.generateSecureConnection(sender, "receiver")
                unix = time.time()
                package = [self.encrypter.encryptMessage(str(unix), start, end),
                           self.encrypter.encryptMessage(str(self.host), start, end),
                           self.encrypter.encryptMessage(message, start, end)]
                while not received:
                    sender.sendall(pickle.dumps(package))
                    confirmation = sender.recv(2048).decode("utf-8")  # Checks message has been received and resends if not
                    if confirmation == "1":
                        received = True
                with displayLock:
                    classReferences["Display"].displaySentMessage([unix, receiver, message])
            except Exception as e:
                logger.error(traceback.format_exc())
            return received
        else:
            classReferences["Display"].showError("Connection Error", "Unable to connect to receiver.")

    def  generateSecureConnection(self, connection, state):
        """Mock generator for secure connections"""
        return 5, 138


class Display(QtWidgets.QMainWindow):
    """Class for GUI"""
    def __init__(self, License, disclaimer):
        super(Display, self).__init__()
        self.license = License
        self.disclaimer = disclaimer
        classReferences["Display"] = self
        self.messages = self.readMessages()
        self.initialiseGUI()
        for line in self.messages:
            self.chatThreadDisplay.append(line)
        logger.info("UI Initialised")
        logger.info(self.license)

    def displaySentMessage(self, package):
        """Writes a message to the GUI sent to a receiver"""
        if len(package[2]) > 0:
            line = "[You -> %s]: %s"%(str(package[1]).upper(), package[2])
            logger.info("Line set")
            self.messages.append(line)
            logger.info("Line appended")
            self.chatThreadDisplay.append(line)
            logger.info("Got line")
            self.writeMessages()

    def displayReceivedMessage(self, package):
        """Writes a message received to the GUI"""
        if len(package[2]) > 0:
            line = "[%s]: %s"%(package[1], package[2])
            logger.info("Line set")
            self.messages.append(line)
            logger.info("Line appended")
            self.chatThreadDisplay.append(line)
            logger.info("Got line")
            self.writeMessages()
            
    def initialiseGUI(self):
        """Sets up widgets within the interface"""
        self.setGeometry(50, 50, 500, 500)
        self.setWindowTitle("QuantuMessage P2P")
        self.display = QtWidgets.QWidget()
        self.layout = QtWidgets.QVBoxLayout()
        self.addressBox = QtWidgets.QLineEdit()
        self.addressBox.setPlaceholderText("Receiver address")  # Box for machine name
        self.chatThreadDisplay = QtWidgets.QTextEdit()
        self.chatThreadDisplay.setReadOnly(True)  # Large box to hold conversation
        self.messageBox = QtWidgets.QLineEdit()
        self.messageBox.setPlaceholderText("Enter message")  # Box to type messages
        self.sendButton = QtWidgets.QPushButton("Send")
        self.sendButton.clicked.connect(self.sendMessage)  # Button to send message
        self.licenseButton = QtWidgets.QPushButton("License")
        self.licenseButton.clicked.connect(self.displayLicense)  # Button for license display
        self.disclaimerLabel = QtWidgets.QLabel()
        self.disclaimerLabel.setText(self.disclaimer)
        self.layout.addWidget(self.addressBox)
        self.layout.addWidget(self.chatThreadDisplay)
        self.layout.addWidget(self.messageBox)
        self.layout.addWidget(self.sendButton)
        self.layout.addWidget(self.licenseButton)
        self.layout.addWidget(self.disclaimerLabel)
        self.display.setLayout(self.layout)
        self.setCentralWidget(self.display)
        self.show()

    def readMessages(self):
        with open("messages.pickle", "rb") as f:
            messages = pickle.load(f)
        return messages

    def sendMessage(self):
        """Reads a message and address from the GUI and passes it to the NetworkInterface"""
        address = self.addressBox.text()
        message = self.messageBox.text()
        successful = classReferences["NetworkInterface"].sendMessage(message, address)
        if successful:
            self.messageBox.clear()

    def displayLicense(self):
        self.message = ScrollMessageBox(self.license)
        self.message.setWindowTitle("License")
        self.message.exec_()

    def showError(self, title, message):
        """Displays an error message to the user"""
        self.message = QtWidgets.QMessageBox(self)
        self.message.setIcon(QtWidgets.QMessageBox.Information)
        self.message.setWindowTitle(title)
        self.message.setText(message)
        self.message.exec_()

    def writeMessages(self):
        """Writes list of messages to a file for use between executions"""
        with open("messages.pickle", "wb") as f:
            pickle.dump(self.messages, f)

class ScrollMessageBox(QtWidgets.QMessageBox):
    """Scrolled message box to display a license.
    This code was adapted from a response by StackOverflow user "eyllanesc"
    - see https://stackoverflow.com/questions/47345776/pyqt5-how-to-add-a-scrollbar-to-a-qmessagebox for original
    response.
    """
    def __init__(self, l, *args, **kwargs):
        QtWidgets.QMessageBox.__init__(self, *args, **kwargs)
        scroll = QtWidgets.QScrollArea(self)
        scroll.setWidgetResizable(True)
        self.content = QtWidgets.QWidget()
        scroll.setWidget(self.content)
        lay = QtWidgets.QVBoxLayout(self.content)
        for item in l.split("\n"):

            lay.addWidget(QtWidgets.QLabel(item, self))
        self.layout().addWidget(scroll, 0, 0, 1, self.layout().columnCount())
        self.setStyleSheet("QScrollArea{min-width:500 px; min-height: 400px}\nQLabel{text-align: center;}")






if __name__ == "__main__":
    with open("graph.pickle", "rb") as f:
        graph = pickle.load(f)
    with open("keys.pickle", "rb") as f:
        keys = pickle.load(f)

    app = QtWidgets.QApplication(sys.argv)
    app.setStyle("Fusion")
    Gui = Display(programLicense, disclaimer)
    ConnectionMonitor = NetworkInterface(graph, keys)
    Listener = ReceiveMessagesThread(graph, keys)
    sys.exit(app.exec())
