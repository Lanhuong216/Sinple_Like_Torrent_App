def spiltfile(filename):
    listfile=[]
    fileR = open(filename, "rb")
    chunk = 0
    byte = fileR.read(524288)
    while byte:
        # Open a temporary file and write a chunk of bytes
        fileN = "chunk" + filename + str(chunk) + ".txt"
        fileT = open(fileN, "wb")
        listfile.append(fileN)
        fileT.write(byte)
        fileT.close()
        # Read next 1024 bytes
        byte = fileR.read(524288)
        chunk += 1
    return listfile
