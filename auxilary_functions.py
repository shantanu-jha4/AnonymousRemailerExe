from all_modules import *

def recv_full_mssg(_len, c):
    msg = b''
    while _len > 0:
        chunk = c.recv(_len)
        _len = _len - len(chunk)
        msg = msg + chunk
    return msg

def int_to_bytes(num):
    return num.to_bytes(2, byteorder="big")

def bytes_to_int(a):
    return int.from_bytes(a, byteorder='big')

def generate_encrypted_mssg(ciphertext, nonce):
    encrypted_mssg_resp = remailer_pb2.NSTPMessage()
    encrypted_mssg_resp.encrypted_message.ciphertext = ciphertext
    encrypted_mssg_resp.encrypted_message.nonce = nonce
    encrypted_mssg_resp_b = encrypted_mssg_resp.SerializeToString()
    encrypted_mssg_resp_b_len = auxilary_functions.int_to_bytes(len(encrypted_mssg_resp_b))
    final_resp = encrypted_mssg_resp_b_len + encrypted_mssg_resp_b
    return final_resp

def read_buffer(s, set_block=False):
    if set_block:
        s.setblocking(1)
    try:
        data = s.recv(2)
        len_data = bytes_to_int(data)
        data = recv_full_mssg(len_data, s)
        return data
    except (ConnectionResetError, OSError) as e:
        print(e)
        return b''

def parse_config_file(_config_file):
    #prim_server_port, status_server_addr, status_server_port, trusted_cert_db_path, pinned_cert_db_path, server_cert_path, server_private_key_path, users_db 
    with open(_config_file, 'r') as stream:
        try:
            config_file_dict = yaml.safe_load(stream)
            temp_dict = config_file_dict['self_server']
            prim_server_port = temp_dict['port']
            all_remailer_list_path = config_file_dict['all_remailer_list']
            server_keys_path = config_file_dict['self_server_keys']
            (all_remailer_list, sk, pk) = read_config_vars(all_remailer_list_path, server_keys_path)
            return (prim_server_port,all_remailer_list_path, all_remailer_list, sk, pk)
        except yaml.YAMLError as exc:
            print(exc)

def read_config_vars(all_remailer_list_path, server_keys_path):
    all_remailer_list = []; sk = b''; pk = b''
    with open(all_remailer_list_path, 'rb') as _file:
        data_b = _file.read()
        if data_b != 0:
            all_remailer_store = remailer_pb2.RemailerList()
            all_remailer_store.ParseFromString(data_b)
            for i in all_remailer_store.remailers:
                all_remailer_list.append(i)
    
    with open(server_keys_path, 'rb') as _file:
        data_b = _file.read()
        server_keys = remailer_pb2.Keys()
        server_keys.ParseFromString(data_b)
        sk = server_keys.private_key
        pk = server_keys.public_key
    
    if sk != b'' and pk != b'':
        return (all_remailer_list, sk, pk)
    
    else:
        print('Error in read_config_vars(). Returning empty.')
        return ([],b'',b'')
    

def test_vals(ip_addr, port, remailer_count):
    receiver = 'drrossg@mail.com'
    sender = 'captain@anon.com'
    subject = 'test email'
    body = 'Yeah all I know is I was upstairs listening to my Will Smith CD, when the flames went off'
    return (ip_addr, port, remailer_count, receiver, sender, subject, body)

def get_next_hop(pk, sk, path_node, trusted_server_pk):
    #print('AUX: ', len(trusted_server_pk))
    (rx,tx) = nacl.bindings.crypto_kx_server_session_keys(pk, sk, trusted_server_pk)
    plaintext = nacl.bindings.crypto_secretbox_open(path_node.remailer_on_path, path_node.nonce, rx)
    test_rm = remailer_pb2.Remailers()
    test_rm.ParseFromString(plaintext)
    return test_rm

def randomString(stringLength=10):
    """Generate a random string of fixed length """
    letters = string.ascii_lowercase
    return ''.join(secrets.choice(letters) for i in range(stringLength))
