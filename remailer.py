from all_modules import *
import warnings
import maplogger
from maplogger import *
import json
from urllib.request import urlopen
import mapdata_pb2

# Global variables
server_alias = 'DEFAULT'; server_port = 0
trusted_server_ip = ''; trusted_server_port = 0; trusted_server_public_key = b''
public_key = b''; private_key = b''
PADDING_SIZE = 3000
do_padding = True; do_delay = True; send_global_mail = True
rlock = threading.RLock()

def init_socket(port, no_bind = False):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #s.settimeout(10)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if no_bind:
        return s
    try:
        s.bind(('0.0.0.0', port))
    except:
        print ('bind failed')
        s.close()
        sys.exit()
    print ("socket is bound to ", port)
    return s

def strip_headers(email_str, recipient):
    msg = Parser().parsestr(email_str)
    if msg.is_multipart():
        print('if one')
        for part in msg.get_payload():
            body += part.get_payload()
    else:
        #print('else one')
        body = msg.get_payload()
    
    wrap_msg = MIMEText(body)
    wrap_msg['To'] = recipient
    print('\n\n RECEIVER ADDRESS: ', wrap_msg['To'], '\n\n')
    wrap_msg['From'] = email.utils.formataddr(('', auxilary_functions.randomString()))
    wrap_msg['Subject'] = msg['Subject']
    return wrap_msg

def construct_final_email(plaintext, mime_mssg):
    temp_hldr = plaintext.split('@',1)
    rcvr_len_str = temp_hldr[0]; rcvr_len = int(temp_hldr[0])
    rcvr_email = (temp_hldr[1])[:rcvr_len]
    plaintext = (temp_hldr[1])[rcvr_len:]
    msg = MIMEText(plaintext)
    msg['To'] = email.utils.formataddr(('', rcvr_email))
    msg['From'] = email.utils.formataddr(('', mime_mssg['from']))
    msg['Subject'] = mime_mssg['Subject']
    return msg
    
def send_to_next_hop(email_mssg, delay):
    if delay != 0:
        time.sleep(delay)
    rlock.acquire()
    global trusted_server_public_key; global send_global_mail
    full_path = email_mssg.full_path
    entry_node = full_path[0]
    #print('what the fuck')
    #print(mime_mssg.as_string())
    if len(full_path) == 1:
        try:
            #msg = Parser().parsestr(email_mssg.message)
            to_addr = remailer_pb2.Remailers()
            to_addr.ParseFromString(entry_node.remailer_on_path)
            mime_mssg = strip_headers(email_mssg.message, to_addr.ip_address)
            
            send_global_mail = (to_addr.ip_address == 'global')

            body_cipher_str = mime_mssg.get_payload()
            body_cipher_hex = body_cipher_str.encode('utf-8')
            body_cipher = binascii.unhexlify(body_cipher_hex)
            sender_deets = email_mssg.about_sender
            sender_nonce = sender_deets[0:24]; sender_pk = sender_deets[24:]
            (rx,tx) = nacl.bindings.crypto_kx_server_session_keys(public_key, private_key, sender_pk)
            plaintext = nacl.bindings.crypto_secretbox_open(body_cipher, sender_nonce, rx)
            final_mime_mssg = construct_final_email(plaintext.decode('utf-8'), mime_mssg)

            if send_global_mail:
                print('sending mail out...\n')
                port = 465  # For SSL
                smtp_server = "smtp.gmail.com"
                sender_email = "serveranon9@gmail.com"  # Enter your address
                receiver_email = final_mime_mssg['to']  # Enter receiver address
                print('Receiver email addr: ', receiver_email)
                password = '1234@anon'

                context = ssl.create_default_context()
                with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
                    server.login(sender_email, password)
                    server.sendmail(sender_email, receiver_email, final_mime_mssg.as_string())
            
            else:
                smtpObj = smtplib.SMTP(to_addr.ip_address, to_addr.port)
                smtpObj.sendmail(final_mime_mssg['from'], [final_mime_mssg['to']], final_mime_mssg.as_string())
            print("\nSuccessfully sent email")
        except:
            traceback.print_exc()
            print("Error: unable to send email")
        del full_path[0]
    
    else:
        to_addr = auxilary_functions.get_next_hop(public_key, private_key, entry_node, trusted_server_public_key)
        mime_mssg = strip_headers(email_mssg.message, to_addr.ip_address)
        del full_path[0]
        final_email = remailer_pb2.Email()
        final_email.full_path.extend(full_path)
        final_email.about_sender = email_mssg.about_sender
        final_email.message = mime_mssg.as_string()

        global do_padding
        if do_padding:
            global PADDING_SIZE
            padding_len = PADDING_SIZE - (2+(len(final_email.SerializeToString())))
            padding_content = os.urandom(padding_len)
            padding_len_b = (padding_len).to_bytes(2, byteorder="big")
            byte_block = padding_len_b + final_email.SerializeToString() + padding_content
        else:
            byte_block = final_email.SerializeToString()
        
        print('Byte block ', len(byte_block))

        _nonce_t = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        (rx,tx) = chash.crypto_kx_client_session_keys(public_key, private_key, to_addr.public_key)
        encrypted_email = chash.crypto_secretbox(byte_block, _nonce_t, tx)

        anon_mssg = remailer_pb2.AnonMssg()
        anon_mssg.encrypted_mssg.message = encrypted_email
        anon_mssg.encrypted_mssg.nonce = _nonce_t + public_key
        #anon_mssg.encrypted_mssg.pk = to_addr.public_key

        ciphertext_resp_b = anon_mssg.SerializeToString()
        ciphertext_resp_b_len = auxilary_functions.int_to_bytes(len(ciphertext_resp_b))
        ciphertext_resp = ciphertext_resp_b_len + ciphertext_resp_b
        print('Final message: ', len(ciphertext_resp))

        send_sock = init_socket(0, True)
        send_sock.connect((to_addr.ip_address, to_addr.port))
        send_sock.send(ciphertext_resp)
        print('Message Forwarded')
        send_sock.close()
        try:
            maplogger.sending_to_logger(to_addr.ip_address)
        except:
            print('no map, no visuals')
            pass

    rlock.release()
        
def handle_in_mssg(c, addr):
    global public_key; global private_key; global trusted_server_ip; global trusted_server_port; global trusted_server_public_key
    with c:
        print ("incoming from", addr)
        #try:
        while True:
            try:
                data = c.recv(2)
                if data == b'##':
                    c.send(b'@@')
                    continue
                else:
                    len_data = auxilary_functions.bytes_to_int(data)
                    data = auxilary_functions.recv_full_mssg(len_data, c)
            except (ConnectionResetError, OSError) as e:
                print(e)
                break
            if len(data) == 0:
                print('incoming data from ', str(addr), ' is 0')
                break
                        
            #print(data)
            talkto_ts = remailer_pb2.AnonMssg()
            talkto_ts.ParseFromString(data)
            #print(str(talkto_ts))
            mssg_type = talkto_ts.WhichOneof('message_')

            if mssg_type == 'ts_hello':
                #trusted_server_public_key = talkto_ts.ts_hello.public_key
                ts_challenge = talkto_ts.ts_hello.ping_request
                global trusted_server_public_key
                test_cipher = ts_challenge.data
                (rx,tx) = nacl.bindings.crypto_kx_server_session_keys(public_key, private_key, trusted_server_public_key)
                plaintext = nacl.bindings.crypto_secretbox_open(test_cipher, ts_challenge.nonce, rx)

                # ping response
                ping_response_temp = remailer_pb2.PingResponse()
                ping_response_temp.data = plaintext

                # send Remailer Hello 
                challenge_ans = remailer_pb2.AnonMssg()
                challenge_ans.remailer_hello.ping_response.CopyFrom(ping_response_temp)
                challenge_ans_b = challenge_ans.SerializeToString()
                challenge_ans_b_len = auxilary_functions.int_to_bytes(len(challenge_ans_b))
                challenge_ans_resp = challenge_ans_b_len + challenge_ans_b
                c.send(challenge_ans_resp)
            
            elif mssg_type == 'encrypted_mssg':
                sender_deets = talkto_ts.encrypted_mssg.nonce
                sender_nonce = sender_deets[0:24]; sender_pk = sender_deets[24:]
                (rx,tx) = nacl.bindings.crypto_kx_server_session_keys(public_key, private_key, sender_pk)
                plaintext = nacl.bindings.crypto_secretbox_open(talkto_ts.encrypted_mssg.message, sender_nonce, rx)
                try:
                    with warnings.catch_warnings():
                        warnings.filterwarnings('RuntimeWarning')
                        try:
                            recvd_email = remailer_pb2.Email()
                            recvd_email.ParseFromString(plaintext)
                        except Warning:
                            raise Exception('')
                except:
                    print('This mssg is padded up')
                    pad_len_b = plaintext[0:2]
                    pad_len = auxilary_functions.bytes_to_int(pad_len_b)
                    email_content = plaintext[2:(len(plaintext)-pad_len)]
                    recvd_email = remailer_pb2.Email()
                    recvd_email.ParseFromString(email_content)
                
                print()
                global do_delay
                if do_delay: 
                    randi = secrets.randbelow(28744203713818482289)
                    delay = randi%7
                else:
                    delay = 0
                #print(delay)
                k = threading.Thread(target=send_to_next_hop, args=(recvd_email, delay))
                k.start()

            else:
                talkto_ts = remailer_pb2.AnonMssg()
                talkto_ts.error_message.error_message = 'Unrecognized'
                talkto_ts_b = talkto_ts.SerializeToString()
                talkto_ts_b_len = auxilary_functions.int_to_bytes(len(talkto_ts_b))
                talkto_ts_resp = talkto_ts_b_len + talkto_ts_b
                c.send(talkto_ts_resp)
                
def ping_home(server_port, ts_ip, ts_port, server_alias, pk):
    talkto_ts = remailer_pb2.AnonMssg()
    talkto_ts.remailer_hello.string_agent = server_alias
    talkto_ts.remailer_hello.self.port = server_port
    talkto_ts.remailer_hello.self.public_key = pk
    talkto_ts_b = talkto_ts.SerializeToString()
    talkto_ts_b_len = auxilary_functions.int_to_bytes(len(talkto_ts_b))
    talkto_ts_resp = talkto_ts_b_len + talkto_ts_b
    sock = init_socket(0,True)
    try:
        sock.connect((ts_ip,ts_port))
        sock.send(talkto_ts_resp)
    except:
        print('where is trusted server?')
        sock.close()
        sys.exit()

    data = auxilary_functions.read_buffer(sock)
    if len(data) == 0:
        print('No reply from home ')
        sock.close()
        sys.exit()
    
    talkto_ts = remailer_pb2.AnonMssg()
    talkto_ts.ParseFromString(data)
    mssg_type = talkto_ts.WhichOneof('message_')
    global trusted_server_public_key
    if mssg_type == 'ts_hello':
        trusted_server_public_key = talkto_ts.ts_hello.public_key
    try:
        maplogger.location_logger()
    except:
        print('no map, no visuals')
        pass

def fill_global_vars(filename):
    global server_alias; global server_port; 
    global trusted_server_ip; global trusted_server_port
    global public_key; global private_key
    #(server_port,all_remailers_list,private_key, public_key) = auxilary_functions.parse_config_file(sys.argv[1])
    with open(filename, 'r') as stream:
        try:
            config_file_dict = yaml.safe_load(stream)
            temp_dict = config_file_dict['self_server']
            server_alias = temp_dict['alias']
            #server_port = temp_dict['port']
            temp_dict = config_file_dict['trusted_server']
            trusted_server_ip = temp_dict['ipv4_address']
            trusted_server_port = temp_dict['port']
            server_keys_path = config_file_dict['self_server_keys']
        except yaml.YAMLError as exc:
            print(exc)
    with open(server_keys_path, 'rb') as _file:
        data_b = _file.read()
        client_keys = remailer_pb2.Keys()
        client_keys.ParseFromString(data_b)
        private_key = client_keys.private_key
        public_key = client_keys.public_key
    #ping_home(server_port, trusted_server_ip, trusted_server_port, server_alias, public_key)
    #print(server_port); print(all_remailers_list); print(server_sk); print(server_pk)
    #helpers.add_to_pinned_base(pinned_cert_db_path, nstp_v4_pb2.Certificate(), True)
    #helpers.add_to_trust_base('/home/captain/Dropbox/stuff/ns/as03/data/accept.db', nstp_v4_pb2.Certificate(), True)
def check_args():
    global do_padding; global do_delay; global server_port
    global public_key; global private_key
    global trusted_server_ip; global trusted_server_port
    try:
        parser = argparse.ArgumentParser(description='Remailer Program')
        parser.add_argument('port', metavar='port', type=int, help='port for remailer to bind')
        parser.add_argument('--config', metavar='<path to file>', type=str, help='path to file')
        parser.add_argument('--ts', metavar='"ip port"', type=str, help='ip address and port of trusted server')
        parser.add_argument('--nopad', action='store_true', help='disable padding')
        parser.add_argument('--nodelay', action='store_true', help='disable latency')
        args = parser.parse_args()
        server_port = args.port
        if args.config == None and args.ts == None:
            raise Exception('')
        elif args.config != None and args.ts == None:
            fill_global_vars(args.config)
        elif args.config == None and args.ts != None:
            temp_str = args.ts.split(' ')
            trusted_server_ip = temp_str[0]
            trusted_server_port = int(temp_str[1])
            (public_key,private_key) = nacl.bindings.crypto_box_keypair()
            #ping_home(server_port, trusted_server_ip, trusted_server_port, server_alias, public_key)
        else:
            raise Exception('')
        
        do_padding = not args.nopad
        do_delay = not args.nodelay

    except:
        #traceback.print_exc()
        sys.exit()

def main():
    check_args()
    print('PORT: ', server_port)
    s = init_socket(server_port)
    s.listen(5)
    ping_home(server_port, trusted_server_ip, trusted_server_port, server_alias, public_key)
    print ("socket is listening...")
    while True:
        try:
            (c,addr) = s.accept()
            handle_in_mssg(c,addr)
            #k = threading.Thread(name=str(i), target=handle_in_mssg, args=(c,addr,0))
            #k.start()
            #k.join()
            #i +=1 
            #k = start_new_thread(handle_in_mssg, (c,addr,a[i]))
        except:
            traceback.print_exc()
            break
    s.close

if __name__ == "__main__":
    main()