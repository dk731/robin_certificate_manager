######################################################################################### Initialize new key/cert bundle
# Encrypted Key Generation
# openssl genrsa -aes256 -passout pass:{secret_password} -out {ppk_name}_ppk_enc.pem 4096

# Decrypt private key
# openssl rsa -passin pass:{secret_password} -in {ppk_name}_ppk_enc.pem -out {ppk_name}_ppk.pem

# Sign request for out key
# openssl req -new -key {ppk_name}_ppk.pem -out {new_csr_name}_csr.pem

# Generate server certificate
# openssl x509 -req -sha256 -days 9999 -in {new_csr_name}_csr.pem -signkey {ppk_name}_ppk.pem -out {new_cert_name}.pem

# Notes:
# if {ppk_name}.pem is not used anymore, must be deleted
#########################################################################################


######################################################################################### Client cert creation and signing
# Generate client private key and certificate from it
# openssl req -newkey rsa:4096 -keyout {client_ppk_name}_ppk.pem -out {client_csr_name}_csr.pem -nodes -days 365 -subj "/CN=Alice"

# Sign create certificate with out server ket and cert
# openssl x509 -days 9999 -req -in {client_csr_name}.pem -CA {new_cert_name}.pem -CAkey {ppk_name}.pem -out {client_cert_name}.pem -set_serial 01

# Signed cert as installable format
# openssl pkcs12 -export -clcerts -in {client_cert_name}.pem -inkey {client_ppk_name}.pem -out {client_cert_name}.p12
#########################################################################################

# file salf: b'\x85]\x00ABt\x9d\x12\x16\xd2\xf6\xe5CE\xbawoRg\xb1\x18\xd4N\xed\xb3\xf5O\xe08\x98R\x1a\xf11\x94\xbeL\xa8\xd0\x89wF\x11\xd6\xd7\x9b\x1f\xd1\xd9\xdc-\xff\xd3\x17g\x1a\xab\x91\xde\xa7\xe6)\x00\xa3\xf9`k\x9f\x150\xa3P\tr*d\x02\xe2\xbcW\xaeR#\xc0Q\x86v\xf5Z\xc6\xacP\x08"\x95\x88O\x8d{Y\x95\x03\xfe\xf0~8MH/\xce\x0b\xce\xde\xda\xa4*\xb1A\xe5<\xaa\x82\xb16]\xd4\xba\xd6"\x85h\xe1\x87\xd6tu\xe9\xd5\x87G\xf4\xa0P&\xdc\xc3\xcbd\x96\x1c\xda^\x9c\x7f\x8dT\xf33\xd1T\x89\xf9G\xed%v\xb1\x83\x0e\xab\t\xb3\x05hP\xa3\xc8\xa4\xa5\x02\xfa\xf9\x18J\xf2T\xc7a\xea\n\xe9\x9f\xd1\xeb\xfd\x84\xc8\xf3~\xc7i.\x1b\xf2\x8c\'\x94\x16 \x90\xa4{Uv@E\x93\x16\xe4<\xbc\xe6\xff\x96[\x9f\xf7\xf4\xf5/Q\xd6\xa1\'\xa4;f\xc0\xdc\x03=\xfd\xa4\xae\xb6\xe7\xbb\x04\t"\xa4E\x02\x85\xc9{\xf7Q\xb7T\xbd\x96m\xf9I\xc9\xd9\x06\xf8g\xc2nz4\xf6}l\xfa\xce\xe0\x0b\xab\xe5*\xdb\xaeX\xa0\xbc\xcd\x89Be\xd9\xf6\xc9N\x13\xa5\xa5\xe0\xbb1\x9fU\nx#P\x1fM\xf5g\xc7\xaf\x8ak\xf2\x8a\x12\x04\xce\xda" Rb\xb3\x01h\xc8j\xfc^\x02`\xb5\x9fh mU\xfd\xc7\xba\xc1\x82\x87\'QK\x91_.\xd6\x8e\xae?Y0\xda0`j1\x1b\xf4\x16\x8e$n9\xffr\xca\x8f\xbbm4\xb5\xbf\x9eV\xfe\x01W\xe5\x93\x14\xf8\xfe\xa4\x1b\xa2\x8d\xfc\xcd\xb5\x8f\xf1\x8a\xa3\xa2\xe4\x0f\x95\x05\x0c:w`\xe46<\xab\xbb,n\xa4\xc3)\xa0\x14\xfd\xc9S\xf0a%\xc6\xe9\xc9\xdaJ\x172\xec\xf1\xdf1\xf3P\x0f\xaa\xfd\xa6\x8d\xfbYe\x7f\xf5\x9e9\xaa\xc5\xaa\x0e[T\x0f\x8e\xb3%\x8e\xff\xf6m2\xf2_\x850f\'k\xc0\xf9\x11\xe9\x9a\xd7\xf5\xc4w-\xf6\x8e\x1b7LAoh\xee\x85*j\xbdx\n\x9cg9z/\xe7}\n\rSu'

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import os
import shutil
import ujson
import subprocess
import base64
from getpass import getpass

ROOT_DIR = os.getcwd()
TMP_DIR = os.path.join(ROOT_DIR, "tmp")

if os.path.exists(TMP_DIR):
    shutil.rmtree(TMP_DIR)
os.mkdir(TMP_DIR)

with open("file_salt.key", "rb") as pf:
    file_salt = pf.read()

file_kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=file_salt,
    iterations=1000000,
)

active_data_obj = None

def save_active():
    # file_pswd = getpass("Please enter password from pickle data file: ")
    file_pswd = "A(n]GleSMB3<CwfK"
    file_key = base64.urlsafe_b64encode(file_kdf.derive(bytes(file_pswd, encoding="utf8")))
    file_fernet = Fernet(file_key)

    data_str = bytes(ujson.dumps(active_data_obj), encoding="utf8")
    data_encr = file_fernet.encrypt(data_str)
    with open(ofile, "wb+") as f:
        f.write(data_encr)

def load_active(file_name: str):
    file_pswd = "A(n]GleSMB3<CwfK"
    file_key = base64.urlsafe_b64encode(file_kdf.derive(bytes(file_pswd, encoding="utf8")))

    file_fernet = Fernet(file_key)

    if os.path.exists("data_enc.json"):
        with open("data_enc.json", "rb") as f:
            try:
                file_str = file_fernet.decrypt(f.read())
                data_obj = ujson.loads(file_str)
            except Exception:
                raise Exception("Was not able to load data file, check password and try again")
        print("Successfully oppened data file")

    else:
        print("Was not able to locate data file...")


while True:
    command = input("Enter commnad: ")

    cmd_params = command.split(" ")

    match cmd_params[0]:
        case "q" | "Q":
            print("Saving and stopping...")
            data_str = bytes(ujson.dumps(data_obj), encoding="utf8")
            data_encr = file_fernet.encrypt(data_str)
            with open("data_enc.json", "wb+") as f:
                f.write(data_encr)
            break
        case "lc": # List clients
            if not active_data_obj:
                continue

            for client in data_obj["clients"]:
                print(client)

        case "of": # open file:
            ofile = input("enter filename: ")

        case "iemp": # init empty:
            ofile = input("enter filename: ")
            os.chdir(TMP_DIR)

            subprocess.run(["openssl", "genrsa", "-aes256", "-passout", "pass:123", "-out", "tmp_ppk_enc.pem", "4096"])
            subprocess.run(["openssl", "rsa", "-passin", f"pass:123", "-in", "tmp_ppk_enc.pem", "-out", "tmp_ppk.pem"])
            subprocess.run(["openssl", "req", "-new", "-key", "tmp_ppk.pem", "-out", "tmp_csr.pem"])
            subprocess.run(["openssl", "x509", "-req", "-sha256", "-days", "9999", "-in", "tmp_csr.pem", "-signkey", "tmp_ppk.pem", "-out", "tmp.pem"])

            default_file_structure = {
                "server_ppk": "",
                "server_csr": "",
                "server_cert": "",
                "clients": []
            }

            with open("tmp_ppk.pem", "r") as f:
                default_file_structure["server_ppk"] = f.read()

            with open("tmp_csr.pem", "r") as f:
                default_file_structure["server_csr"] = f.read()

            with open("tmp.pem", "r") as f:
                default_file_structure["server_cert"] = f.read()

            os.chdir(ROOT_DIR)
            shutil.rmtree(TMP_DIR)
            os.mkdir(TMP_DIR)

            active_data_obj = default_file_structure
            save_active()

