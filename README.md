# QuantuMessage
Experimental messaging program with possible quantum-secure encryption

# Disclaimer
**Any form of encryption used within this software is experimental and has NO PROOF OF SECURITY WHATSOEVER. Therefore it is highly recommended that NO ONE USE THE ENCRYPTION WITHIN THIS CODE UNDER ANY CIRCUMSTANCES.**

**Anyone using this encryption system does so at their own risk. The developer accepts NO RESPONSIBILITY for any loss or theft of data as a result of using the encryption algorithms in this software.**

# License
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


# Instructions for Use
1. Extract the zip file to the chosen directory
2. Run the file "Main.exe"


# Notes
1. "Receiver address" refers to the device name of the destination machine. This can be found through Python, via the "socket" library's "gethostname" function.
2. The program will save messages automatically. To erase message content, a copy of Python 3.6 must be installed on your machine. To do so, visit <https://www.python.org/downloads/> to download and install a copy then run "resetMessages.py".
3. This program has been built and tested on Windows only, and performance on other operating systems may vary.