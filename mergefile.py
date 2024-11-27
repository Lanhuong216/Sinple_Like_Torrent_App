# Open original file for reconstruction
fileM = open("5_SQLfinal.pdf", "wb")
 
# Manually enter total amount of "chunks"
chunk = 0
chunks = 4
# Piece the file together using all chunks
while chunk <= chunks:
    fileName = "chunk" + str(chunk) + ".txt"
    try: 
        
        fileTemp = open(fileName, "rb")
        byte = fileTemp.read(524288)
        fileM.write(byte)
        chunk += 1
    except:
        break
    print(" - Chunk #" + str(chunk-1) + " done.")
 
fileM.close()