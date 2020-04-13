from all_modules import *

# Global variables
start_time = 0
server_port = 0
all_remailers_list_path = ''; all_remailers_list = []
public_key = b''; private_key = b''
clearfile = False

g_count = 0; g_active_remailers_count = {}; g_active_remailers = {}; first_run = True
rlock = threading.RLock()

def init_socket(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #s.settimeout(10)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(('0.0.0.0', port))
    except:
        print ('bind failed')
        sys.exit()
    print ("socket is bound to ", port)
    return s

def check_remailers():
    s_temp = None
    all_active_remailers = {} # dictionary with (ip,port) as key and public key as value
    all_active_remailers_count = {}; count = 0
    for remailer in all_remailers_list: 
        remailer_addr = (remailer.ip_address, remailer.port)
        # assuming remailer = (ip, port)
        try:
            if s_temp:
                s_temp.close()
            s_temp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s_temp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # send TS Hello 
            challenge_rm = remailer_pb2.AnonMssg()
            
            rand_bytes = os.urandom(128) # generate random byte string
            _nonce_t = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
            (rx,tx) = chash.crypto_kx_client_session_keys(public_key, private_key, remailer.public_key)
            ciphertext_resp = chash.crypto_secretbox(rand_bytes, _nonce_t, tx)
            #send ping request
            t_ping_r = remailer_pb2.PingRequest()
            t_ping_r.data = ciphertext_resp
            t_ping_r.nonce = _nonce_t
            challenge_rm.ts_hello.ping_request.CopyFrom(t_ping_r)
            challenge_rm_b = challenge_rm.SerializeToString()
            challenge_rm_len_b = auxilary_functions.int_to_bytes(len(challenge_rm_b))
            challenge_rm_resp = challenge_rm_len_b + challenge_rm_b
            
            # connect to remailer
            s_temp.connect(remailer_addr)
            s_temp.send(challenge_rm_resp)

            # Expecting remailer hello
            data = auxilary_functions.read_buffer(s_temp)
            if len(data) == 0:
                print('inside check_remailer(): incoming data from is 0')
                break
            
            talkto_ts = remailer_pb2.AnonMssg()
            talkto_ts.ParseFromString(data)
            #print(str(talkto_ts))
            mssg_type = talkto_ts.WhichOneof('message_')

            if mssg_type == 'remailer_hello':
                ping_response = talkto_ts.remailer_hello.ping_response
                if ping_response.data == rand_bytes:
                    print('Remailer ', remailer_addr, ' is alive!')
                    all_active_remailers[remailer_addr] = remailer.public_key
                    all_active_remailers_count[count] = remailer_addr
                    count += 1
            else:
                talkto_ts = remailer_pb2.AnonMssg()
                talkto_ts.error_message.error_message = 'Error! Expected remailer hello'
                talkto_ts_b = talkto_ts.SerializeToString()
                talkto_ts_b_len = auxilary_functions.int_to_bytes(len(talkto_ts_b))
                talkto_ts_resp = talkto_ts_b_len + talkto_ts_b
                s_temp.send(talkto_ts_resp)
        except:
            traceback.print_exc()
            print('Could not connect to remailer, ', str(remailer_addr))
            continue
    return (count, all_active_remailers_count, all_active_remailers)

def get_remailers_list(remailer_count: int, sender_pk):
    rlock.acquire()
    global g_count; global g_active_remailers_count; global g_active_remailers; global first_run; global start_time
    # dictionary with (ip,port) as key and public key as value
    if first_run or (int(time.time()) > (start_time+60)):
        (g_count, g_active_remailers_count, g_active_remailers) = check_remailers()
        first_run = False
        start_time = int(time.time())
    else:
        (g_count, g_active_remailers_count, g_active_remailers) = connect_and_check(g_active_remailers_count, g_active_remailers)
    
    if len(g_active_remailers_count) == 0:
        first_run = True
        return ([], b'')

    remailer_count = min(remailer_count, len(g_active_remailers_count))

    remailers_for_client = []
    #print(len(all_active_remailers_count))
    for x in range(remailer_count):
        num = secrets.randbelow(34035875527440277879)
        num = num % len(g_active_remailers_count)
        while True:
            if num not in remailers_for_client:
                remailers_for_client.append(num)
                break
            else:
                num = secrets.randbelow(len(g_active_remailers_count))
                continue
    
    active_remailers_client = []
    temp_keys_index = []
    for i in remailers_for_client:
        __remailer_temp = remailer_pb2.Remailers()
        __remailer__no = g_active_remailers_count[i]
        (ip_t,port_t) = __remailer__no
        __remailer_temp.ip_address = ip_t
        __remailer_temp.port = port_t
        __remailer_temp.public_key = g_active_remailers[__remailer__no]
        exit_node_pk = __remailer_temp.public_key
        temp_keys_index.append(__remailer_temp.public_key)

        temp_pk = sender_pk; remailer_cipher = b''
        _nonce_t = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        if len(active_remailers_client) == 0:
            (rx,tx) = chash.crypto_kx_client_session_keys(public_key, private_key, temp_pk)
            remailer_cipher = chash.crypto_secretbox(__remailer_temp.SerializeToString(), _nonce_t, tx)
        
        else:
            temp_pk = temp_keys_index[ len(temp_keys_index) - 2 ]
            (rx,tx) = chash.crypto_kx_client_session_keys(public_key, private_key, temp_pk)
            remailer_cipher = chash.crypto_secretbox(__remailer_temp.SerializeToString(), _nonce_t, tx)

        path_element = remailer_pb2.PathElement()
        path_element.remailer_on_path = remailer_cipher
        #path_element.public_key = temp_pk
        path_element.nonce = _nonce_t
        active_remailers_client.append(path_element)
    rlock.release()
    return (active_remailers_client, exit_node_pk)

def register_remailer(addr, rm_hello_mssg):
    rlock.acquire()
    (ip,port) = addr
    remailer1 = remailer_pb2.Remailers()
    remailer1.CopyFrom(rm_hello_mssg)
    remailer1.ip_address = ip
    global all_remailers_list
    print('ALL REMAILER LIST: ', all_remailers_list)
    if remailer1 not in all_remailers_list:
        all_remailers_list.append(remailer1)
    rlock.release()

def final_write(all_remailer_list_path):
    global all_remailers_list; global clearfile
    #print('Exit: ', all_remailers_list)
    all_remailer_store = remailer_pb2.RemailerList()
    if clearfile:
        with open(all_remailer_list_path, 'wb') as _file:
            _file.write(b'')
        return
    else:
        all_remailer_store.remailers.extend(all_remailers_list)
    list_rms = all_remailer_store.remailers
    with open(all_remailer_list_path, 'wb') as _file:
        _file.write(all_remailer_store.SerializeToString())

def connect_and_check(remailer_dict_count, remailer_dict):
    active_dict_count = {}; active_dict = {}; count = 0
    for r in remailer_dict.keys():
        try:
            s_temp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s_temp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s_temp.connect(r)
            s_temp.send(b'##')
            data = s_temp.recv(2)
            if data == b'@@':
                print('actually active')
                active_dict[r] = remailer_dict[r]
                active_dict_count[count] = r
                count += 1
            s_temp.close()
        except:
            continue
    
    return (count, active_dict_count,active_dict)       
        
def handle_in_mssg(c, addr):
    global public_key
    with c:
        print ("incoming from", addr)
        try:
            data = c.recv(2)
            len_data = auxilary_functions.bytes_to_int(data)
            data = auxilary_functions.recv_full_mssg(len_data, c)
        except (ConnectionResetError, OSError) as e:
            print(e)
            return
        if len(data) == 0:
            print('incoming data from ', str(addr), ' is 0')
            return

        talkto_ts = remailer_pb2.AnonMssg()
        talkto_ts.ParseFromString(data)
        mssg_type = talkto_ts.WhichOneof('message_')
        
        if mssg_type == 'remailer_hello':
            talkto_rm = remailer_pb2.AnonMssg()
            talkto_rm.ts_hello.string_agent = 'Welcome ' + talkto_ts.remailer_hello.string_agent
            talkto_rm.ts_hello.public_key = public_key
            talkto_rm_b = talkto_rm.SerializeToString()
            talkto_rm_b_len = auxilary_functions.int_to_bytes(len(talkto_rm_b))
            talkto_rm_resp = talkto_rm_b_len + talkto_rm_b
            c.send(talkto_rm_resp)
            register_remailer(addr,talkto_ts.remailer_hello.self)

        elif mssg_type == 'client_request':
            #print(len(talkto_ts.client_request.public_key))
            (remailer_list, exit_pk) = get_remailers_list(talkto_ts.client_request.no_of_remailers, talkto_ts.client_request.public_key)
            #print(remailer_list, exit_pk)
            if remailer_list == [] and exit_pk == b'':
                talkto_ts = remailer_pb2.AnonMssg()
                talkto_ts.error_message.error_message = 'No active remailers'
                talkto_ts_b = talkto_ts.SerializeToString()
                talkto_ts_b_len = auxilary_functions.int_to_bytes(len(talkto_ts_b))
                talkto_ts_resp = talkto_ts_b_len + talkto_ts_b
                c.send(talkto_ts_resp)
                return
            
            talkto_ts = remailer_pb2.AnonMssg()
            talkto_ts.ts_reply.full_path.extend(remailer_list)
            talkto_ts.ts_reply.ts_pk = public_key
            talkto_ts.ts_reply.exit_node_pk = exit_pk
            talkto_ts_b = talkto_ts.SerializeToString()
            talkto_ts_b_len = auxilary_functions.int_to_bytes(len(talkto_ts_b))
            talkto_ts_resp = talkto_ts_b_len + talkto_ts_b
            c.send(talkto_ts_resp)
        
        else:
                talkto_ts = remailer_pb2.AnonMssg()
                talkto_ts.error_message.error_message = 'Unrecognized'
                talkto_ts_b = talkto_ts.SerializeToString()
                talkto_ts_b_len = auxilary_functions.int_to_bytes(len(talkto_ts_b))
                talkto_ts_resp = talkto_ts_b_len + talkto_ts_b
                c.send(talkto_ts_resp)

def fill_global_vars(filename):
    global server_port; global all_remailers_list; global all_remailers_list_path
    global public_key; global private_key
    (server_port,all_remailers_list_path,all_remailers_list,private_key, public_key) = auxilary_functions.parse_config_file(filename)
    print('Entry: ', all_remailers_list)
    #print(server_port); print(all_remailers_list); print(server_sk); print(server_pk)
    #helpers.add_to_pinned_base(pinned_cert_db_path, nstp_v4_pb2.Certificate(), True)
    #helpers.add_to_trust_base('/home/captain/Dropbox/stuff/ns/as03/data/accept.db', nstp_v4_pb2.Certificate(), True)
def check_args():
    parser = argparse.ArgumentParser(description='Trusted Server Program')
    parser.add_argument('config', metavar='<path to file>', type=str, help='path to config file')
    parser.add_argument('--clear', action='store_true', help='clear remailer list file')
    args = parser.parse_args()
    fill_global_vars(args.config)
    global clearfile
    clearfile = args.clear
def main():
    check_args()
    global start_time; start_time = int(time.time())
    s = init_socket(server_port)
    s.listen(20)
    print ("socket is listening...")
    while True:
        try:
            (c,addr) = s.accept()
            k = threading.Thread(target=handle_in_mssg, args=(c,addr))
            k.start()
            #list1 = get_remailers_list(1)
            #print('client list: \n',str(list1))            
        except:
            traceback.print_exc()
            break
    s.close
    global all_remailers_list_path
    final_write(all_remailers_list_path)

if __name__ == "__main__":
    main()