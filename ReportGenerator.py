__author__ = 'ben'

import os
import io


def handshake_was_made(p_line):
    readbytes = p_line.split(" ")[4]
    sentbytes = p_line.split(" ")[8]

    if int(readbytes) > 7 and int(sentbytes) > 0:
        return True
    else:
        return False


workingDirectory = "/Users/ben/Documents/Thesis/shane/poodle/out/"
files = os.listdir(workingDirectory)
count = 0
fullData = []

for fileName in files:
    count += 1
    if count % 100:
        print("Files Process:" + str(count) + ":" + fileName)

    f = io.open(workingDirectory + fileName, mode="rt", encoding='cp1252')
    reachedEndOfSection = False
    line = f.readline()
    site = line[21:]
    rank = fileName.split('-')[0]

    # Test for SSL3
    ssl3 = False

    if not f.readline().startswith("#SSLv3"):
        # file format not correct, go to next file
        continue

    while not reachedEndOfSection:
        line = f.readline()

        if line.startswith("SSL handshake has read"):
            ssl3 = handshake_was_made(line)

        if line.startswith("#"):
            reachedEndOfSection = True

        if line == "":
            #file is missing data, continue
            break

    if line == "":
            #file is missing data, continue
            continue

    # Test for SSL3 + SCSV
    reachedEndOfSection = False
    ssl3_SCSV = False

    if not line.startswith("#SSLv3+SVSC"):
        # file format not correct, go to next file
        continue

    while not reachedEndOfSection:
        line = f.readline()

        if line.startswith("SSL handshake has read"):
            ssl3_SCSV = handshake_was_made(line)

        if line.startswith("#"):
            reachedEndOfSection = True

        if line == "":
            #file is missing data, continue
            break

    if line == "":
            #file is missing data, continue
            continue

    # Test for SSL2

    reachedEndOfSection = False
    ssl2 = False

    if not line.startswith("#SSLv2"):
        # file format not correct, go to next file
        continue

    while not reachedEndOfSection:
        line = f.readline()

        if line.startswith("SSL handshake has read"):
            ssl2 = handshake_was_made(line)

        if line.startswith("#"):
            reachedEndOfSection = True

        if line == "":
            #file is missing data, continue
            break

    # Test for TLS1

    reachedEndOfSection = False
    tls1 = False

    if not line.startswith("#TLS1"):
        # file format not correct, go to next file
        continue

    while not reachedEndOfSection:
        line = f.readline()

        if line.startswith("SSL handshake has read"):
            tls1 = handshake_was_made(line)

        if line.startswith("#"):
            reachedEndOfSection = True

        if line == "":
            #file is missing data, continue
            break

    # Test for TLS1.1

    reachedEndOfSection = False
    tls1_1 = False

    if not line.startswith("#TLS1.1"):
        # file format not correct, go to next file
        continue

    while not reachedEndOfSection:
        line = f.readline()

        if line.startswith("SSL handshake has read"):
            tls1_1 = handshake_was_made(line)

        if line.startswith("#"):
            reachedEndOfSection = True

        if line == "":
            #file is missing data, continue
            break

    # Test for TSL1.2

    reachedEndOfSection = False
    tls1_2 = False

    if not line.startswith("#TLS1.2"):
        # file format not correct, go to next file
        continue

    while not reachedEndOfSection:
        line = f.readline()
        if line.startswith("SSL handshake has read"):
            tls1_2 = handshake_was_made(line)

        if line.startswith("#"):
            reachedEndOfSection = True

        if line == "":
            #file is missing data, continue
            break

    if line == "":
            #file is missing data, continue
            continue

    # TODO: cipherscan

    data = [rank, site.replace("\n", ""), ssl3, ssl3_SCSV, ssl2, tls1, tls1_1, tls1_2]

    fullData.append(data)
    f.close()

with open('/Users/ben/Documents/Thesis/shane/poodle/report.csv', 'w') as csvfile:
    for row in fullData:
        csvfile.write(
            str(row[0]) + ',' + str(row[1]) + ',' + str(row[2]) + ',' + str(row[3]) + ',' +
            str(row[4]) + ',' + str(row[5]) + ',' + str(row[6]) + ',' + str(row[7]) + '\n')

    csvfile.close()