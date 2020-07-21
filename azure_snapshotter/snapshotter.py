import os
import json
import hashlib
from getpass import getpass
from datetime import datetime
from dataclasses import dataclass

import click
from storefact import get_store
from Crypto.Cipher import AES

params = {
    "account_name": os.environ["AZURE_SNAPSHOTTER_ACCOUNT_NAME"],
    "account_key": os.environ["AZURE_SNAPSHOTTER_ACCOUNT_KEY"],
    "container": os.environ.get("AZURE_SNAPSHOTTER_CONTAINER", "backup"),
}


@dataclass(frozen=True)
class MetaData:
    md5sum: str

    def serialize(self):
        return self.__dict__


class MetaTable(dict):
    def to_json(self):
        return json.dumps(self, default=MetaData.serialize)

    def from_json(self, json_str):
        self.update(json.loads(json_str))


_store = get_store("hazure", **params)
_prefix = None
_nonce = None
_secret_key = None
_password = os.environ.get("AZURE_SNAPSHOTTER_CYBERPASSWORD")
_partition = None
META_TABLE_KEY = "AZURE_SNAPSHOTTER_META_TABLE_KEY"
meta_table = MetaTable()


def encrypt(data):
    cipher = AES.new(_secret_key, AES.MODE_EAX, nonce=_nonce)
    ciphertext, _ = cipher.encrypt_and_digest(data)
    return ciphertext


def decrypt(data):
    cipher = AES.new(_secret_key, AES.MODE_EAX, nonce=_nonce)
    return cipher.decrypt(data)


def _delete(key):
    _store.delete(_prefix + key)


def _put(key, value):
    ciphertext = encrypt(value)
    _store.put(_prefix + key, ciphertext)

def _put_data(key, value):
    ciphertext = encrypt(value)
    _store.put(_partition + "/files/" + key, ciphertext)


def _get(key):
    try:
        ciphertext = _store.get(_prefix + key)
    except KeyError:
        return None
    return decrypt(ciphertext)

def _get_data(key):
    try:
        ciphertext = _store.get(_partition + "/files/" + + key)
    except KeyError:
        return None
    return decrypt(ciphertext)


def _keys():
    return [x[len(_prefix) :] for x in _store.keys(prefix=_prefix)]

def _files():
    return [x[len(_partition + "/files/") :] for x in _store.keys(prefix=_partition + "/files/")]


def md5(file_name):
    hash_md5 = hashlib.md5()
    with open(file_name, "rb") as f:
        for chunk in iter(lambda: f.read(16384), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def _backup_dir(path, files = None):
    files = files if files else _files()
    for f in os.listdir(path):
        full_file_path = os.path.join(path, f)

        if os.path.isdir(full_file_path):
            _backup_dir(full_file_path, files)
        else:
            md5sum = md5(full_file_path)
            meta_table[full_file_path] = md5sum
            if md5sum in files:
                print(full_file_path + " [Skipped]")
            else:
                print(full_file_path)
                with open(full_file_path, "rb") as file_handler:
                    data = file_handler.read()
                    _put_data(md5sum, data)


def backup_dir(path):
    _backup_dir(path)
    _put(META_TABLE_KEY, meta_table.to_json().encode())


def restore_to(target):

    meta_table_data = _get(META_TABLE_KEY)
    meta_table.from_json(meta_table_data.decode())
    for partial_filename, azure_key in meta_table.items():
        filename = os.path.join(target, partial_filename)
        dirname = os.path.dirname(filename)
        if not os.path.exists(dirname):
            os.makedirs(dirname, exist_ok=True)
        print(filename)
        with open(filename, "wb") as f:
            print(filename)
            data = _get_data(azure_key)
            f.write(data)


def init(timestamp):
    global _prefix, _nonce, _secret_key, _password
    if _password is None:
        _password = getpass("Cyberpassword: ")
    _prefix = _partition + "/" + timestamp + "/"
    _nonce = hashlib.md5(_prefix.encode()).digest()
    _secret_key = hashlib.md5(_password.encode()).digest()
    meta_table_data = _get(META_TABLE_KEY) or "{}"
    meta_table.from_json(meta_table_data)


@click.group()
@click.option("--partition", default="default")
def main(partition):
    global _partition
    _partition = partition


@click.option("--directories")
@main.command()
def upload(directories):
    timestamp = datetime.now().strftime("%Y-%m-%d-%H")
    init(timestamp)
    with open(directories, "r") as f:
        for line in [line.rstrip() for line in f]:
            print("Transfering " + line)
            backup_dir(line)


@click.option("--timestamp", required=True)
@click.option("--destination", required=True)
@main.command()
def restore(timestamp, destination):
    init(timestamp)
    restore_to(destination)