# Open original file for reconstruction
def mergefile(filename, numberofchunks, piecesize):
    fileM = open(f"received_{filename}", "wb")
    # Manually enter total amount of "chunks"
    chunk = 0
    # Piece the file together using all chunks
    while chunk <= numberofchunks:
        fileName = "received_chunk" +filename + str(chunk) + ".txt"
        try: 
            
            fileTemp = open(fileName, "rb")
            byte = fileTemp.read(piecesize)
            fileM.write(byte)
            chunk += 1
        except:
            break
        
    print(f"[MERGE FILE] {filename} successfully!")
    fileM.close()

#mergefile("5_SQL.pdf", 4, 524288)