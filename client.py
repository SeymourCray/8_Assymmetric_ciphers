import socket
import pickle

HOST = '127.0.0.1'
PORT = 8081
PUBLIC_KEY = int()
PRIVATE_KEY = int()
a = int()
g = int()
p = int()



def vernam_enc_dec(k, m):
    k = str(k)*(len(m)//len(str(k))) + str(k)[-(len(m) % len(str(k))):]
    return ''.join(map(chr,   [i ^ int(x) for i, x in zip(map(ord, m), k)]))


def get_message(msg):
    return vernam_enc_dec(PRIVATE_KEY, str(msg))


def diffie_hellman(conn, server_key=False):
    global PRIVATE_KEY, PUBLIC_KEY, a, g, p
    if server_key:
        msg = conn.recv(1024)
        B = int(pickle.loads(msg))
        PRIVATE_KEY = B**a % p
        write_keys(PUBLIC_KEY, PRIVATE_KEY)
    else:
        from random import randint
        a = randint(1000, 10000)
        p = randint(1000, 10000)
        g = randint(1000, 10000)
        PUBLIC_KEY = (g ** a) % p
        conn.send(pickle.dumps((p, g, PUBLIC_KEY)))
        diffie_hellman(conn, server_key=True)


def write_keys(k1, k2):
    with open('keys_client.txt', 'a') as file:
        file.write('\n'.join([str(k1), str(k2)]))


def get_keys():
    global PRIVATE_KEY, PUBLIC_KEY
    try:
        with open('keys_client.txt', 'r') as file:
            keys = file.read()
            keys = keys.split('\n')
            PUBLIC_KEY = int(keys[0].strip())
            PRIVATE_KEY = int(keys[1].strip())
            return True
    except FileNotFoundError:
        return False


def get_port(conn):
    port = get_message(pickle.loads(conn.recv(1024)))
    print(f"Основное общение на порте {port}")
    conn.close()
    return int(port)


def communication(port):
    sock = socket.socket()
    print(port)
    from time import sleep
    sleep(3)
    sock.connect((HOST, port))
    while True:
        sock.send(pickle.dumps(get_message(input('>'))))
        print(get_message(pickle.loads(sock.recv(1024))))


sock = socket.socket()
sock.connect((HOST, PORT))
if not get_keys():
    diffie_hellman(sock)
communication(get_port(sock))


# 4. Клиент посылает сообщение серверу, шифруя его своим закрытым ключом и открытым ключом сервера.
# 5. Сервер принимает сообщение, расшифровывает его сначала своим закрытым ключом, а потом - открытым ключом клиента.
# 6. Обратное сообщение посылается аналогично.


# 4. Модифицируйте код клиента и сервера таким образом, чтобы установление режима шифрования
# происходило при подключении на один порт, а основное общение - на другом порту. Номер порта
# можно передавать как первое зашифрованное сообщение.
