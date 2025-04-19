import socket
import threading
import logging
from datetime import datetime

ALLOWED_IPS = [
    '95.31.142.219',
    '127.0.0.1',
    '::1',
    'localhost'  # Если используется DNS-имя
]



def safe_close(sock):
    if sock is None:
        return
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except:
        pass
    try:
        sock.close()
    except:
        pass


logging.basicConfig(filename='intermediate_log.txt', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')


def log_message(message, connection_id=None):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} - {message}"
    if connection_id:
        log_entry = f"{log_entry} (Connection ID: {connection_id})"
    logging.info(log_entry)
    print(log_entry)


def forward(src, dst, direction, connection_id):
    try:
        while True:
            data = src.recv(4096)
            if not data:
                log_message(f"Соединение закрыто {direction}", connection_id)
                break
            dst.sendall(data)
            log_message(f"Переслано {len(data)} байт {direction}", connection_id)
    except Exception as e:
        log_message(f"Ошибка пересылки {direction}: {e}", connection_id)
    finally:
        safe_close(src)
        safe_close(dst)


def handle_connection(proxy_socket, connection_id):
    target_socket = None
    try:
        data = b''
        while True:
            chunk = proxy_socket.recv(1024)
            if not chunk:
                break
            data += chunk
            if b'\n\n' in data:
                break

        if b'\n\n' not in data:
            log_message("Неверный формат команды", connection_id)
            safe_close(proxy_socket)
            return

        header, body = data.split(b'\n\n', 1)
        header_str = header.decode('utf-8', 'ignore').strip()

        if not header_str.startswith('TARGET '):
            log_message(f"Неверная команда: {header_str}", connection_id)
            safe_close(proxy_socket)
            return

        target = header_str.split(' ', 1)[1]
        host, port = target.split(':', 1)
        port = int(port)

        log_message(f"Подключение к {host}:{port}", connection_id)

        target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target_socket.settimeout(10)
        try:
            target_socket.connect((host, port))
        except Exception as e:
            log_message(f"Ошибка подключения: {e}", connection_id)
            safe_close(proxy_socket)
            return

        if body:
            try:
                target_socket.sendall(body)
            except Exception as e:
                log_message(f"Ошибка отправки тела: {e}", connection_id)
                safe_close(proxy_socket)
                safe_close(target_socket)
                return

        threading.Thread(
            target=forward,
            args=(proxy_socket, target_socket, "client->target", connection_id)
        ).start()

        threading.Thread(
            target=forward,
            args=(target_socket, proxy_socket, "target->client", connection_id)
        ).start()

    except Exception as e:
        log_message(f"Ошибка: {e}", connection_id)
    finally:
        pass


def start_server(host, port):
    server_socket = socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET,
                                  socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(10)

    log_message(f"Сервер запущен на {host}:{port}")

    connection_id = 0
    while True:
        proxy_socket, addr = server_socket.accept()
        client_ip = addr[0]

        # Логируем полученный IP
        log_message(f"Получен IP: {client_ip} (тип: {type(client_ip)})")

        if client_ip not in ALLOWED_IPS:
            log_message(f"Отклонено соединение от IP: {client_ip}")
            safe_close(proxy_socket)
            continue

        connection_id += 1
        log_message(f"Разрешено соединение от {addr}", connection_id)
        threading.Thread(
            target=handle_connection,
            args=(proxy_socket, connection_id)
        ).start()


if __name__ == "__main__":
    start_server('0.0.0.0', 9999)
