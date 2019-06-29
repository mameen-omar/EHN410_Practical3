#!/usr/bin/env python3

import subprocess
subprocess.call(["make","rc4"])

#./rc4 -fi inputfile -fo outputfile -kf keyfile -hex


print("************ Start Testing Rc4 *******************\n")
inputfileName = "temp"
outputFileName = "temp2" 
keyFile = "" 

temp = subprocess.call(["./rc4","-fi", inputfileName, "-fo", outputFileName])

print("\n************ End Testing Rc4 *******************")