#!/usr/bin/env python3

import subprocess
subprocess.call(["make","rsakeygen"])

# ./rsakeygen -b bits -ku publickeyfile -kr privatekeyfile -key key -kf keyfile -ascii (to specify if the key is ascii)
bits = "55"
publickeyfile = "temp"
privatekeyfile = "temp2" 
keyFile = ""
key = ""  
# subprocess.call(["./rsakeygen", "-b", bits, "-ku", publickeyfile, "-kr" , privatekeyfile , "-key"  , key , "-kf" , keyFile])
subprocess.call(["make", "rsakeygen"])
print("************ Start Testing rsakeygen *******************\n")
print("Test 1 begin:")
temp = subprocess.call(["./rsakeygen", "-b", bits, "-KU", publickeyfile, "-KR" , privatekeyfile , "-key"  , key , "-kf" , keyFile])
print("Return code: " + str(temp))
print("Test 1 End.")
print("************ End Testing rsakeygen *******************\n")