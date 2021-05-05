import socket
import struct as st
import pandas as pd
import pickle as pk


class HARDCODES:
    ID = bytes(b'\xaa\xaa')
    RECURSIVE_FLAGS = bytes(b'\x01\x00')
    ITERATIVE_FLAGS = bytes(b'\x00\x00')
    QDCOUNT = bytes(b'\x00\x01')
    ANQOUNT = bytes(b'\x00\x00')
    NSQOUNT = bytes(b'\x00\x00')
    ARQOUNT = bytes(b'\x00\x00')
    QCLASS = bytes(b'\x00\x01')
    ATYPE = bytes(b'\x00\x01')


class Cache:
    def __init__(self):
        self.__buffer = None
        self.load_buffer()

    def update(self, hostname_, res_ip):
        if self.__buffer.__contains__(hostname_):
            if self.get_counter(hostname_) >= 3:
                self.__buffer[hostname_][1] = res_ip

    def add(self, hostname_):
        if self.__buffer.__contains__(hostname_):
            self.__buffer[hostname_][0] = self.__buffer[hostname_][0] + 1
        else:
            self.__buffer[hostname_] = [1, None]

    def get_counter(self, hostname_):
        if self.__buffer.__contains__(hostname_):
            return self.__buffer[hostname_][0]
        else:
            return 0

    def get_result(self, hostname_):
        if self.__buffer.__contains__(hostname_):
            return self.__buffer[hostname_][1]
        else:
            return None

    def save_buffer(self):
        file = None
        try:
            file = open('buffer.obj', 'wb')
            pk.dump(self.__buffer, file)
        except IOError as msg:
            print(msg)
        finally:
            if file is not None:
                file.close()

    def load_buffer(self):
        file = None
        try:
            file = open('buffer.obj', 'rb')
            self.__buffer = pk.load(file)
        except IOError:
            self.__buffer = dict()
        finally:
            if file is not None:
                file.close()



def createQuery(hostName, TYPE, RECURSIVE):
    # Header

    # add ID
    bytesSequence = HARDCODES.ID
    # flags
    if RECURSIVE:
        bytesSequence += HARDCODES.RECURSIVE_FLAGS
    else:
        bytesSequence += HARDCODES.ITERATIVE_FLAGS
    # QDCOUNT
    bytesSequence += HARDCODES.QDCOUNT
    # ANQOUNT
    bytesSequence += HARDCODES.ANQOUNT
    # NSQOUNT
    bytesSequence += HARDCODES.NSQOUNT
    # ARQOUNT
    bytesSequence += HARDCODES.ARQOUNT

    # Question

    # QName
    parts = hostName.split('.')
    for part in parts:
        bytesSequence += st.pack('>B', len(part))
        bytesSequence += part.encode()
    bytesSequence += bytes(b'\x00')

    # Query Type
    if TYPE == 'A':
        bytesSequence += HARDCODES.ATYPE
    # Query Class
    bytesSequence += HARDCODES.QCLASS

    return bytesSequence


def connect(query, address):
    status = None
    result = None
    connection = None
    try:
        connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        connection.settimeout(4)

        connection.sendto(query, address)
        result = connection.recvfrom(4096)[0]
        status = True

    except ConnectionError as msg:
        result = str(msg)
        status = False
    except IOError as msg:
        result = str(msg)
        status = False
    finally:
        connection.close()
        return result, status


def check_response_flags(flagBytes):
    flag_status = bin(int(flagBytes.hex(), 16))[2:].zfill(8)
    QR = flag_status[0]
    # OPCODE = flag_status[1:5]
    # AA = flag_status[5]
    TC = flag_status[6]
    RD = flag_status[7]
    RA = flag_status[8]
    RCODE = int(flag_status[12:16], 2)

    if QR == '0':
        raise Exception('it\'s not a response')

    if RD == '1' and RA == '0':
        raise Exception('server does not support recursion.')

    if TC == '1':
        raise Exception('message is Truncated')

    if RCODE == 1:
        raise Exception('Format error : The name server was unable to interpret the query')
    elif RCODE == 2:
        raise Exception('Server failure : The name server was unable to process'
                        ' this query due to a problem with the name server')
    elif RCODE == 3:
        raise Exception('Name Error : the domain name referenced in the query does not exist')
    elif RCODE == 4:
        raise Exception('Not Implemented : The name server does not support the requested kind'
                        ' of query')
    elif RCODE == 5:
        raise Exception('Refused : The name server refuses to perform the '
                        'specified operation for policy reasons')


def findDataByOffset(copyBytes, offset, data_, codec='utf-8'):
    end = offset + 1 + copyBytes[offset]
    data_.append(copyBytes[offset + 1:end].decode(codec))

    if copyBytes[offset] == 0:
        return data_, end

    if end > len(copyBytes) or copyBytes[end] == 0:
        return data_, end
    else:
        return findDataByOffset(bytes(copyBytes), end, data_, codec)


def parseResult(result):
    try:
        index = 0

        # Header
        ID = result[index:index + 2]
        if ID != HARDCODES.ID:
            raise Exception('HEADER : ID mismatch')
        index += 2
        FLAGS = result[index:index + 2]
        check_response_flags(FLAGS)
        index += 2
        QDCOUNT = result[index:index + 2]
        index += 2
        ANQOUNT = result[index:index + 2]
        index += 2
        NSQOUNT = result[index:index + 2]
        index += 2
        ARQOUNT = result[index:index + 2]
        index += 2

        # Question
        Question, nIndex = findDataByOffset(bytes(result), index, [])
        QNAME = ''
        for i in range(len(Question)):
            if i == 0:
                QNAME += Question[i]
            else:
                QNAME += '.' + Question[i]

        index = nIndex + 1
        resQType = result[index:index + 2]
        index += 2
        resQClass = result[index:index + 2]
        if resQClass != HARDCODES.QCLASS:
            raise Exception('HEADER : QCLASS mismatch')
        index += 2

        # Answer
        ans = []
        for i in range(int.from_bytes(ANQOUNT, 'big')):
            data, index = parseAnswer(bytes(result), index)
            ans.append(data)

        # Authority
        aut = []
        for i in range(int.from_bytes(NSQOUNT, 'big')):
            data, index = parseAnswer(bytes(result), index)
            aut.append(data)

        # Additional
        add = []
        for i in range(int.from_bytes(ARQOUNT, 'big')):
            data, index = parseAnswer(bytes(result), index)
            add.append(data)

        return [ans, aut, add, True, None]
    except Exception as msg:
        ans = str(msg)
        return [None, None, None, False, ans]


def parseAnswer(copyBytes, offset):
    resNAME = copyBytes[offset:offset + 2]
    offset += 2
    resType = copyBytes[offset:offset + 2]
    offset += 2
    resClass = copyBytes[offset:offset + 2]
    if resClass != HARDCODES.QCLASS:
        raise Exception('ANSWER : QCLASS mismatch')
    offset += 2
    resTTL = copyBytes[offset:offset + 4]
    offset += 4
    resRDLENGTH = copyBytes[offset:offset + 2]
    offset += 2
    resRDATA = copyBytes[offset:offset + int.from_bytes(resRDLENGTH, 'big')]
    offset += int.from_bytes(resRDLENGTH, 'big')

    # A TYPE
    if int.from_bytes(resType, 'big') == int.from_bytes(HARDCODES.ATYPE, 'big'):
        IP = ''
        for i in range(int.from_bytes(resRDLENGTH, 'big')):
            if i > 0:
                IP += '.'
            IP += str(int.from_bytes(resRDATA[i:i + 1], 'big'))
        return ('IP', IP), offset

    else:
        return ('ELSE', resRDATA), offset


def read_from_csv():
    table = pd.read_csv('data.csv')
    data = []
    for i in range(table.shape[0]):
        data.append(list(table.loc[i]))
    return data


def write_to_csv(data):
    table = pd.DataFrame(data=data, columns=('HostName',
                                             'IP Address'))
    try:
        table.to_csv('data.csv', index=False, sep=',')
    except PermissionError:
        print('permission denied : data.csv is open')
        exit(-1)


def create_csv():
    table = pd.DataFrame(columns=('HostName',))
    try:
        table.to_csv('data.csv', index=False, sep=',')
    except PermissionError:
        print('permission denied : data.csv is open')
        exit(-1)


def converter(hostname, server_ip):
    res, aut, add, sts, error = DNS_LookUp(hostname,
                                           address=(server_ip, 53),
                                           RECURSIVE=False)

    if sts:
        if len(res) > 0:
            return [('ANSWER', res)]

        elif len(add) > 0:
            newRes = []
            for exp, r in add:
                if exp == 'IP':
                    newRes.extend(converter(hostname, r))

            return newRes
    else:
        return [('ERROR', error)]


def iterative_to_recursive_converter(hostname, server_ip):
    res = converter(hostname, server_ip)
    answers = []
    errors = ''
    counter = 1

    for status, message in res:
        if status == 'ANSWER':
            for _, ip in message:
                answers.append(ip)
        elif status == 'ERROR':
            if counter == 1:
                errors += str(counter) + ') ' + message
            else:
                errors += ' , ' + str(counter) + ') ' + message
            counter += 1

    if len(answers) > 0:
        answers = pd.unique(answers)
        IP_tag = ['IP' for _ in range(len(answers))]
        return list(zip(IP_tag, answers)), None, None, True, None

    return None, None, None, False, errors


def DNS_LookUp(inp, TYPE='A', address=("8.8.8.8", 53), RECURSIVE=True):
    Query = createQuery(inp, TYPE, RECURSIVE)
    result, status = connect(Query, address)

    if status:
        return parseResult(result)
    else:
        return None, None, None, False, result


def input_parser(data):
    data = data.split()

    hostname = ''
    recursive = True
    server_ip_address = ''

    for dt in data:
        if dt[0] == '-':
            if dt == '-r':
                recursive = True
            elif dt == '-i':
                recursive = False

        elif dt[0] == '@':
            server_ip_address = dt[1:]

        else:
            hostname = dt

    if len(hostname) == 0 or len(server_ip_address) == 0:
        return None, None, None
    else:
        return hostname, server_ip_address, recursive


def main():
    mode = input('1) Direct Input\n2) CSV File\n')

    if mode != '1' and mode != '2':
        print('wrong mode')
        exit(-1)

    if mode == '1':
        cache = Cache()
        hostname, server_ip, recursive = input_parser(input('> '))
        if hostname is None or server_ip is None or recursive is None:
            print('wrong input format')
            exit(-1)

        if cache.get_counter(hostname) >= 3:
            res, aut, add, sts, error = cache.get_result(hostname), None, None, True, None
        else:
            if not recursive:
                res, aut, add, sts, error = iterative_to_recursive_converter(hostname, server_ip)
            else:
                res, aut, add, sts, error = DNS_LookUp(hostname,
                                                       address=(server_ip, 53),
                                                       RECURSIVE=recursive)


        if sts:
            if (res is not None) and len(res) > 0:
                cache.add(hostname)
                cache.update(hostname, res)
                for exp, r in res:
                    if exp == 'IP':
                        print('IP :', r)

        else:
            print(error)

        cache.save_buffer()

    elif mode == '2':
        cache = Cache()
        create_csv()
        print('Enter your commands in data.csv and save file, then press any key')
        input()
        print('Wait.....')
        data_list = read_from_csv()
        new_data_list = []
        for data_l in data_list:
            hostname, server_ip, recursive = input_parser(data_l[0])
            if hostname is None or server_ip is None or recursive is None:
                new_data_list.append([*data_l, 'wrong input format'])
                continue

            if cache.get_counter(hostname) >= 3:
                res, aut, add, sts, error = cache.get_result(hostname), None, None, True, None
            else:
                if not recursive:
                    res, aut, add, sts, error = iterative_to_recursive_converter(hostname, server_ip)
                else:
                    res, aut, add, sts, error = DNS_LookUp(hostname,
                                                           address=(server_ip, 53),
                                                           RECURSIVE=recursive)
                    if error is not None:
                        error = '1) ' + error
            if sts:
                ndata = ''
                counter = 1
                if (res is not None) and len(res) > 0:
                    cache.add(hostname)
                    cache.update(hostname, res)
                    for exp, r in res:
                        if exp == 'IP':
                            if counter == 1:
                                ndata += str(counter) + ') ' + str(r)
                            else:
                                ndata += ' , ' + str(counter) + ') ' + str(r)
                            counter += 1
                    new_data_list.append([hostname, ndata])

            else:
                new_data_list.append([hostname, error])

        write_to_csv(new_data_list)
        cache.save_buffer()
        print('done')


if __name__ == '__main__':
    main()
