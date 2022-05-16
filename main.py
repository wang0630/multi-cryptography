import symmetric as sym
import datetime

if __name__ == '__main__':
    # modes_op = ['CTR']
    modes_op = ['CBC', 'CTR']
    for mode in modes_op:
        aes = sym.SymmetricAes(mode)
        print(f'Start {mode} for AES-128')
        start_time = datetime.datetime.now()
        plaintext = aes.run('./test.txt')
        time_delta = datetime.datetime.now() - start_time
        print(f'End {mode} for AES-128, total time: {time_delta.total_seconds()} seconds')

    for mode in modes_op:
        print(f'Start {mode} for 3DES')
        start_time = datetime.datetime.now()
        des = sym.Symmetric3Des(mode)
        plaintext = des.run('./test.txt')
        time_delta = datetime.datetime.now() - start_time
        print(f'End {mode} for 3DES, total time: {time_delta.total_seconds()} seconds')

    for mode in modes_op:
        print(f'Start {mode} for DES')
        start_time = datetime.datetime.now()
        des = sym.SymmetricDes(mode)
        plaintext = des.run('./test.txt')
        time_delta = datetime.datetime.now() - start_time
        print(f'End {mode} for DES, total time: {time_delta.total_seconds()} seconds')
