import csv
import logging
import numpy as np
import pyshark

PCAPFILE = 'c:/xfer/test.pcapng'
logging.basicConfig(level=logging.ERROR)
firstRequest = 0
prefix = '192.168.0.'
lastOctets = list(range(51, 53))
pktCounter = 0
cF = []
deltas = []
coilDeltas = []


def findnextrequest(captureFile, start):
    logging.debug('findnextrequest called with start of %s', start)

    for pktCount in range(start, len(captureFile)):
        packet = captureFile[pktCount]
        if captureFile[pktCount].highest_layer == 'MODBUS':
            try:
                test = packet.modbus.response_time
            except AttributeError as e:
                # probaby need a way to CONFIRM its a request
                # logging.debug("Modbus packet without response time - probably request")
                return pktCount


def findnextresponse(captureFile, start, id):
    logging.debug('findnextresponse called with start of %s and id:%s', start, id)
    for pktCount in range(start, len(captureFile)):
        packet = captureFile[pktCount]
        if packet.highest_layer == 'MODBUS':
            try:
                test = packet.modbus.response_time
            except AttributeError as e:
                # logging.debug("Found Exception when looking for response time - not a response")
                continue
            else:
                if packet.mbtcp.trans_id == id:
                    return pktCount


logging.info('Starting PCAP Analysis for modbus response times on file %s', PCAPFILE)

for lastOctet in lastOctets:
    print('Processing packets for RTU:  {}{}'.format(prefix, lastOctet))

    cF = pyshark.FileCapture(PCAPFILE, display_filter='tcp.port == 502 && ip.addr == ' + prefix + str(lastOctet))
    cF.load_packets()
    logging.debug('IP Address {}{} has {} packets'.format(prefix, lastOctet, len(cF)))
    numPackets = len(cF)
    if numPackets == 0:
        logging.debug('no packets found - skipping...')
        continue

    with open('192.168.0.' + str(lastOctet) + '.csv', 'w', newline='') as oF:

        writer = csv.writer(oF, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        writer.writerow(
            ['Trans ID', 'Req-time', 'modbus Function', 'Resp-Time', 'Delta Time'])
        pktCounter = 0
        lastCoilTime = None
        while pktCounter < numPackets + 1:
            pktCounter = findnextrequest(cF, pktCounter)
            if pktCounter == None:
                break
            if lastCoilTime is not None:
                coilDelta = cF[pktCounter].sniff_time - lastCoilTime
                coilDeltas.append(coilDelta.total_seconds())

            if cF[pktCounter].modbus.func_code == '1':
                logging.info("Setting lastCoilTime to something other than none")
                lastCoilTime = cF[pktCounter].sniff_time

            logging.debug('findnextrequest returned packet# {}'.format(pktCounter))
            requestTime = cF[pktCounter].sniff_time
            csvLine = [
                cF[pktCounter].mbtcp.trans_id,
                cF[pktCounter].sniff_time.strftime('%H:%M:%S.%f'),
                cF[pktCounter].modbus.func_code
            ]

            responseCounter = findnextresponse(cF, pktCounter, cF[pktCounter].mbtcp.trans_id)
            if responseCounter == None:
                logging.info('Did not find match for packet# %s with tran_id:%s', pktCounter, cF[pktCounter.mbtcp.trans_id])
                break
            responseTime = cF[responseCounter].sniff_time
            deltaTime = responseTime - requestTime
            deltas.append(deltaTime.total_seconds())
            csvLine.append(cF[responseCounter].sniff_time.strftime('%H:%M:%S.%f'))
            csvLine.append(deltaTime.total_seconds())

            writer.writerow(csvLine)
            pktCounter += 1

        print('')
        # noinspection PyTypeChecker
        print('Standard deviation of deltaTimes: {}'.format(round(np.std(deltas), 6)))
        # noinspection PyTypeChecker
        print('Mean of Delta Times: {}'.format(round(np.mean(deltas), 6)))
        print('')
        # noinspection PyTypeChecker
        print('Std Deviation of time between coil requests: {}'.format(round(np.std(coilDeltas), 6)))
        # noinspection PyTypeChecker
        print('Mean of time between coil requests: {}'.format(round(np.mean(coilDeltas), 6)))
        print('----------------------------------------------------')
        print('')

