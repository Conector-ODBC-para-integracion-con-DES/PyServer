import asyncio
import logging

from mysqlproto.protocol import start_mysql_server
from mysqlproto.protocol.base import OK, ERR, EOF
from mysqlproto.protocol.flags import Capability
from mysqlproto.protocol.handshake import HandshakeV10, HandshakeResponse41, AuthSwitchRequest
from mysqlproto.protocol.query import ColumnDefinition, ColumnDefinitionList, ResultSet
import subprocess
import time
import threading
import queue
from functools import wraps
import os

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def get_des_route():
    conf_file = "conf.txt"
    
    # Intentar leer el archivo conf.txt
    if os.path.exists(conf_file):
        logging.info("Leyendo archivo de configuración: %s", conf_file)

        with open(conf_file, "r") as file:
            lines = file.readlines()
            for line in lines:
                if "DES_ROUTE" in line:
                    des_route = line.split("=")[1].strip()
                    break
            else:
                des_route = None
    else:
        logging.warning("Archivo de configuración %s no encontrado.", conf_file)
        des_route = None

    # Si el archivo no existe o DES_ROUTE no está en el archivo
    if not des_route:
        des_route = input("Por favor, ingrese la ruta de DES en su ordenador: ")
    
    # Reemplazar barras simples por barras dobles
    des_route = des_route.replace("/", "\\")
    
    # Asegurarse de que la ruta termine con des.exe
    if not des_route.endswith("des.exe"):
        des_route += "\\des.exe"
    
    # Guardar la ruta en conf.txt
    with open(conf_file, "w") as file:
        file.write(f"DES_ROUTE={des_route}\n")
    
    return des_route

def connect_to_des():
    des_route = get_des_route()
    
    try:
        process = subprocess.Popen([des_route, "-c"],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        logging.info("Conexión con DES iniciada.")

    except FileNotFoundError:
        logging.error("No se pudo encontrar el archivo especificado en %s", des_route)
        # Borrar la ruta incorrecta y pedir al usuario que ingrese una nueva
        os.remove("conf.txt")
        return connect_to_des()
    
    output_queue = queue.Queue()


    def reader_thread(p, q):
        while True:
            char = p.stdout.read(1)
            if not char:
                break
            q.put(char)
    
    threading.Thread(target=reader_thread, args=(process, output_queue), daemon=True).start()
    
    # Limpia el mensaje inicial
    logging.info("Limpiando mensaje incial de DES...")

    read_until_markerInitialMessage(output_queue, "DES>")
    
    return process, output_queue

def parse_des_response(des_result):
    lines = des_result.splitlines()
    if not lines:
        return False, []

    # Separar cada línea por el delimitador para obtener las columnas
    rows = [line.split(' | ') for line in lines]
    
    return True, rows



def read_until_markerInitialMessage(q, marker, timeout=10):
    end_time = time.time() + timeout
    buffer = ''
    marker_detected = False

    # Leemos primero un gran trozo del buffer antes de comenzar la búsqueda.
    while len(buffer) < 50000 and time.time() < end_time:  # Ajusta el 50000 si es necesario.
        try:
            char = q.get(timeout=0.1)
            buffer += char
        except queue.Empty:
            continue

    # Ahora buscamos el marcador en el buffer.
    while time.time() < end_time:
        try:
            char = q.get(timeout=0.1)
            buffer += char
        except queue.Empty:
            continue

        if marker in buffer and not marker_detected: # Si el marcador está en el buffer y no lo hemos detectado antes
            des_index = buffer.find(marker)

            after_des = buffer[des_index + len(marker):]
            if '/restore_state' in after_des: 
                marker_detected = True
                return buffer
            elif marker in after_des:   # Si hay otro marcador en el buffer, lo ignoramos
                marker_detected = True
                return buffer

    return None



#def read_until_marker(q, marker, timeout=10):
    #end_time = time.time() + timeout
    #buffer = ''
    #while time.time() < end_time:
        #try:
            #char = q.get(timeout=0.1)
        #except queue.Empty:
            #continue
        #buffer += char
        #if marker in buffer[-len(marker):]:
            #break
    #return buffer

def read_until_marker(q, *markers):
    buffer = ''
    while True:
        try:
            char = q.get(timeout=0.1)
            buffer += char
            if any(marker in buffer[-len(marker):] for marker in markers):
                break
        except queue.Empty:
            break  # Salimos inmediatamente si no hay más datos en la cola.
    return buffer


def execute_des_query(process, q, query):
    if "/" in query:
        transformed_query = query
    else:
        transformed_query = "/tapi " + query
        
    logging.info("Ejecutando consulta: %s", transformed_query)
    process.stdin.write(transformed_query + '\n')
    process.stdin.flush()
    
    response = read_until_marker(q, "|:", "DES>")
    return response


async def accept_server(server_reader, server_writer):
    asyncio.create_task(handle_server(server_reader, server_writer))



async def handle_server(server_reader, server_writer):
    logging.info("Handling new server connection...")

    handshake = HandshakeV10()

    handshake.write(server_writer)
    await server_writer.drain()
    
    handshake_response = await HandshakeResponse41.read(server_reader.packet(), handshake.capability)

    capability = handshake_response.capability_effective

    if (Capability.PLUGIN_AUTH in capability and
            handshake.auth_plugin != handshake_response.auth_plugin):
        AuthSwitchRequest().write(server_writer)
        await server_writer.drain()

        auth_response = await  server_reader.packet().read()
        print("<=", auth_response)

    result = OK(capability, handshake.status)
    result.write(server_writer)
    await server_writer.drain()

    while True:
        server_writer.reset()
        packet = server_reader.packet()
        cmd = (await packet.read(1))[0]
        # print("<=", cmd)

        if cmd == 1:
            logging.info("Cliente desconectado.")
            return

        elif cmd == 3:
            query = (await packet.read()).decode('ascii')
            

            # Filtra las consultas no deseadas
            mysql_specific_commands = [
                "SET NAMES",
                "SET character_set_results",
                "SET SQL_AUTO_IS_NULL",
                "SET AUTOCOMMIT",
                "set @@sql_select_limit",
                "SELECT TABLE_NAME,TABLE_COMMENT,IF(TABLE_TYPE='BASE TABLE', 'TABLE', TABLE_TYPE),TABLE_SCHEMA FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=DATABASE() AND ( TABLE_TYPE='BASE TABLE' OR TABLE_TYPE='VIEW' )  ORDER BY TABLE_SCHEMA, TABLE_NAME",
                "SELECT TABLE_NAME, TABLE_COMMENT, TABLE_TYPE, TABLE_SCHEMA FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = DATABASE() AND ( TABLE_TYPE='BASE TABLE' OR TABLE_TYPE='VIEW' )"
                "ROLLBACK"

            ]
            if any(command in query for command in mysql_specific_commands) or query.startswith("SELECT TABLE_NAME,"):
                # No enviar a DES, tal vez responder con un paquete de éxito falso
                result = OK(capability, handshake.status)
            
            elif query == 'select 1':
                logging.info("Consulta recibida en select 1: %s", query)
                ColumnDefinitionList((ColumnDefinition('database'),)).write(server_writer)
                EOF(capability, handshake.status).write(server_writer)
                ResultSet(('test',)).write(server_writer)
                result = EOF(capability, handshake.status)

            else:
                logging.info("Consulta recibida en else: %s", query)
                # Reenvía la consulta a DES
                des_result = execute_des_query(process, output_queue, query)
                logging.info("Result from DES: %s", des_result)
                success, data = parse_des_response(des_result)
                if success:
                    num_columns = len(data[0])
                    column_definitions = [ColumnDefinition(f"column_{i+1}") for i in range(num_columns)]
                    ColumnDefinitionList(column_definitions).write(server_writer)
                    EOF(capability, handshake.status).write(server_writer)

                    # Envío de las filas
                    for row in data:
                        ResultSet(row).write(server_writer)
                    result = EOF(capability, handshake.status)

                else:
                    logging.info("Consulta recibida: %s", query)
                    result = ERR(capability, error_msg='Mensaje de error personalizado')

        else:
            result = ERR(capability)

        result.write(server_writer)
        await server_writer.drain()


# logging.basicConfig(level=logging.INFO)
port = 3307

try:
    loop = asyncio.get_event_loop()
    loop.run_until_complete(start_mysql_server(handle_server, host=None, port=port))
    logging.info("Servidor iniciado en el puerto: %s", port)

    process, output_queue = connect_to_des()
    loop.run_forever()
except Exception as e:
    logging.exception("Error while starting the server: %s", e)


