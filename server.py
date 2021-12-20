import socket
import pickle
import threading

HOST = '127.0.0.1'
PUBLIC_KEY = int()
PRIVATE_KEY = int()
A_LIST = []
POOL = [i for i in range(8081, 8100)]
COUNT = 1


def vernam_enc_dec(k, m):
    k = str(k)*(len(m)//len(str(k))) + str(k)[-(len(m) % len(str(k))):]
    return ''.join(map(chr,   [i ^ int(x) for i, x in zip(map(ord, m), k)]))


def diffie_hellman(conn):
    global PRIVATE_KEY, PUBLIC_KEY, A
    msg = conn.recv(1024)
    p, g, A = pickle.loads(msg)
    if get_agreed_keys():
        if A in A_LIST:
            from random import randint
            b = randint(1000, 10000)
            PUBLIC_KEY = (g**b) % p
            PRIVATE_KEY = (A**b) % p
            write_keys(PUBLIC_KEY, PRIVATE_KEY)
            conn.send(pickle.dumps(PUBLIC_KEY))
            return True
        else:
            return False
    else:
        from random import randint
        b = randint(1000, 10000)
        PUBLIC_KEY = (g**b) % p
  
        PRIVATE_KEY = (A**b) % p
        write_keys(PUBLIC_KEY, PRIVATE_KEY)
        conn.send(pickle.dumps(PUBLIC_KEY))
        write_agreed_key(A)
        return True


def write_keys(k1, k2):
    with open('keys_server.txt', 'a') as file:
        file.write('\n'.join([str(k1), str(k2)]))


def get_message(msg):
    return vernam_enc_dec(PRIVATE_KEY, str(msg))


def get_keys():
    global PRIVATE_KEY, PUBLIC_KEY
    try:
        with open('keys_server.txt', 'r') as file:
            keys = file.read()
            keys = keys.split('\n')
            PUBLIC_KEY = int(keys[0].strip())
            PRIVATE_KEY = int(keys[1].strip())
            return True
    except FileNotFoundError:
        return False


def get_agreed_keys():
    global A_LIST
    try:
        with open('agreed_keys.txt', 'r') as file:
            keys = file.read()
            keys = keys.split('\n')
            A_LIST = [i.strip() for i in keys]
            return True
    except FileNotFoundError:
        return False


def write_agreed_key(key):
    with open('agreed_keys.txt', 'a') as file:
        file.write('\n'+str(key))


def connector(port):
    sock = socket.socket()
    sock.bind((HOST, port))
    sock.listen(1)
    conn, addr = sock.accept()
    while True:
        msg = get_message(pickle.loads(conn.recv(1024)))
        msg = list(msg)
        msg = ''.join([msg[i] for i in reversed(range(len(msg)))])
        conn.send(pickle.dumps(get_message(msg)))


def new_socket(port):
    sock = socket.socket()
    sock.bind((HOST, port))
    sock.listen(1)
    while True:
        conn, addr = sock.accept()
        if not get_keys():
            if not diffie_hellman(conn):
                conn.close()
                return False
        new_port = send_port(conn)
        thread = threading.Thread(target=connector, args=(new_port,))
        thread.start()


def send_port(conn):
    global COUNT
    from random import randint
    port = POOL[-1]+COUNT
    COUNT += 1
    conn.send(pickle.dumps(vernam_enc_dec(PRIVATE_KEY, str(port))))
    print(f"Основное общение на порте {port}")
    return port


def ports_pool(range_):
    for i in range_:
        thread = threading.Thread(target=new_socket, args=(i,))
        thread.start()


ports_pool(POOL)


# 4. Клиент посылает сообщение серверу, шифруя его своим закрытым ключом и открытым ключом сервера.
# 5. Сервер принимает сообщение, расшифровывает его сначала своим закрытым ключом, а потом - открытым ключом клиента.
# 6. Обратное сообщение посылается аналогично.

# 3. Реализуйте на сервере проверку входящих сертификатов. На сервере
# должен храниться список разрешенных ключей. Когда клиент посылает на сервер
# свой публичный ключ, сервер ищет его среди разрешенных и, если такого не находит,
# разрывает соединение. Проверьте правильность работы не нескольких разных клиентах.


# 6. Модифицируйте код FTP-сервера таким образом, чтобы он поддерживал шифрование.
