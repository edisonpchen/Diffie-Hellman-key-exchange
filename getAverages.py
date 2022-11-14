import sys

def clientdata(filename):
  with open(filename) as file:
    sigVerif_sum = 0
    gyComp_sum = 0
    enc_sum = 0
    macVerif_sum = 0
    sigVerif_n = 0
    gyComp_n = 0
    enc_n = 0
    macVerif_n = 0
    line = file.readline()
    while(line != ""):
      task = line[10]
      val = int(line[37:])
      if(task == '0'):
        sigVerif_sum += val
        sigVerif_n += 1
      elif(task == '1'):
        gyComp_sum += val
        gyComp_n += 1
      elif(task == '2'):
        enc_sum += val
        enc_n += 1
      elif(task == '3'):
        macVerif_sum += val
        macVerif_n += 1
      line = file.readline()
    print("sig verif : "+str(round(sigVerif_sum / sigVerif_n)))
    print("G^y comp  : "+str(round(gyComp_sum / gyComp_n)))
    print("encryption: "+str(round(enc_sum / enc_n)))
    print("mac verif : "+str(round(macVerif_sum / macVerif_n)))
    file.close()

print()
for i in range(1,len(sys.argv)):
  print(sys.argv[i]+": ")
  clientdata(sys.argv[i])
  print()
