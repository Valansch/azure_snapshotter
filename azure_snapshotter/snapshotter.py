import os
import hashlib
from getpass import getpass
from datetime import datetime

import click
from storefact import get_store
from Crypto.Cipher import AES

params = {
    "account_name": os.environ.get("AZURE_SNAPSHOTTER_ACCOUNT_NAME"),
    "account_key": os.environ.get("AZURE_SNAPSHOTTER_ACCOUNT_KEY"),
    "container": os.environ.get("AZURE_SNAPSHOTTER_CONTAINER", "backup"),
}


_store = get_store("hazure", **params)
_prefix = None
_nonce = None
_secret_key = None
_password = os.environ.get("AZURE_SNAPSHOTTER_CYBERPASSWORD")
_partition = None


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


def _get(key):
    ciphertext = _store.get(_prefix + key)
    return decrypt(ciphertext)


def _keys():
    return [x[len(_prefix) :] for x in _store.keys(prefix=_prefix)]


def backup_dir(path):
    for f in os.listdir(path):
        full_file_path = os.path.join(path, f)

        if os.path.isdir(full_file_path):
            backup_dir(full_file_path)
        else:
            key = full_file_path
            if full_file_path[0] == u"/":
                key = full_file_path[1:]
            with open(full_file_path, "rb") as file_handler:
                data = file_handler.read()
                _put(key, data)
                print(key)


def restore_to(target):
    for key in _keys():
        filename = os.path.join(target, key)
        dirname = os.path.dirname(filename)
        if not os.path.exists(dirname):
            os.makedirs(dirname, exist_ok=True)
        with open(filename, "wb") as f:
            data = _get(key)
            print(filename)
            f.write(data)


def init(partition):
    global _prefix, _nonce, _secret_key, _password, _partition
    if _password is None:
        _password = getpass("Cyberpassword: ")
    _partition = partition
    _prefix = partition + "/" + datetime.now().strftime("%Y-%m-%d-%H") + "/"
    _nonce = hashlib.md5(_prefix.encode()).digest()
    _secret_key = hashlib.md5(_password.encode()).digest()


@click.group()
@click.option("--partition", default="")
def main(partition):
    init(partition)


@click.option("--directory", required=True)
@main.command()
def upload(directory):
    backup_dir(directory)


@click.option("--timestamp", required=True)
@click.option("--destination", required=True)
@main.command()
def restore(timestamp, destination):
    global _prefix, _nonce
    _prefix = _partition + "/" + timestamp + "/"
    _nonce = hashlib.md5(_prefix.encode()).digest()
    restore_to(destination)
