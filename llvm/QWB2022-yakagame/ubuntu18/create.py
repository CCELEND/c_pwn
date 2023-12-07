for i in range(256):
	s = str(i)
	s = "0"*(3-len(s)) + s
	print("void ccelend" + s + "(int x);")

print("")

for i in range(256):
	s = str(i)
	s = "0"*(3-len(s)) + s
	print("cclend" + s + "(0);")
