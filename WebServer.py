import socket
import sqlite3

def send_answer(conn, data=""):
    data = data.encode("utf-8")
    conn.send(data)


def parse(conn, addr):
    data = b""

    while not b"\r\n" in data:
        tmp = conn.recv(1024)
        if not tmp:
            break
        else:
            data += tmp

    if not data:
        return

    request_data = str(data).splitlines()
    print(request_data)
    biuld_id = request_data[0]
    key = request_data[1]
    login = request_data[2]
    sql_connect = sqlite3.connect(r'./Decoders.db')
    c = sql_connect.cursor()
    Licence = False
    for row in c.execute("SELECT * FROM `software_users` WHERE `software_users`.`login` LIKE '"+login+"' AND `software_users`.`hwid` LIKE '"+key+"'"):
        Licence = True
    if Licence:
        for row in c.execute("SELECT * FROM `builds` WHERE `builds`.`build_id` LIKE '"+biuld_id+"'"):
            send_answer(conn, data=row[2][::-1])
    else:
        send_answer(conn, data="BAKA-BAKA")
    sql_connect.commit()
    sql_connect.close()


sock = socket.socket()
sock.bind(("", 80))
sock.listen(5)

try:
    while 1:
        conn, addr = sock.accept()
        print("New connection from " + addr[0])
        #try:
        parse(conn, addr)
        #except:
        #send_answer(conn, data="Error BAKA")
        #finally:
        conn.close()
finally:
    sock.close()
