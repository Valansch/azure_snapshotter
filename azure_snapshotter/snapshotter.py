import os
import sys
import json
import hashlib
from random import random
from shutil import rmtree, copyfile
from getpass import getpass
from datetime import datetime
from dataclasses import dataclass

import click
import pyAesCrypt
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
    encryption_mode: str
    file_size: int

    def serialize(self):
        return self.__dict__


class MetaTable(dict):
    def to_json(self):
        return json.dumps(self, default=MetaData.serialize)

    def from_json(self, json_str):
        self.update(json.loads(json_str))


_store = get_store("hazure", **params)
_prefix = None
_secret_key = None
_password = os.environ.get("AZURE_SNAPSHOTTER_CYBERPASSWORD")
_partition = None
_progress_bytes = 0
_total_bytes = 420
META_TABLE_KEY = "AZURE_SNAPSHOTTER_META_TABLE_KEY"
TEMP_FOLDER = "/var/tmp/azure_snapshotter/"
PY_CRYPT_BUFFER_SIZE = 64 * 1024
_force = False
_max_line_length = 100
meta_table = MetaTable()


def update_progress(status_str, finish=False):
    percent = ("{0:.1f}").format(100 * (_progress_bytes / float(_total_bytes)))
    filled_length = int(41 * _progress_bytes / _total_bytes)
    bar = "█" * filled_length + "-" * (40 - filled_length)
    output_buffer = f"\r {human_readable_size(_progress_bytes)} |{bar}| {human_readable_size(_total_bytes)} | {percent}% {status_str}"
    global _max_line_length
    if len(output_buffer) > _max_line_length:
        _max_line_length = len(output_buffer)
    output_buffer += " " * (_max_line_length - len(output_buffer))
    end = "\n" if finish else "\r"
    print(output_buffer, end=end)


def temp_file_name():
    return os.path.join(TEMP_FOLDER, str(random()))


def rm_rf(file_name):
    if os.path.exists(file_name):
        if os.path.isdir(file_name):
            rmtree(file_name, ignore_errors=True)
        else:
            os.remove(file_name)


def dir_size(start_path="."):
    total_size = 0
    for dirpath, dirnames, filenames in os.walk(start_path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            total_size += os.path.getsize(fp)
    return total_size


def human_readable_size(num, suffix="B"):
    for unit in ["", "k", "M", "G"]:
        if abs(num) < 1000:
            return "%3.1f %s%s" % (num, unit, suffix)
        num /= 1000.0
    return "%.1f %s%s" % (num, "T", suffix)


def calculate_nonce(seed_str):
    return hashlib.md5(seed_str.encode()).digest()


def encrypt(data, nonce):
    cipher = AES.new(_secret_key, AES.MODE_EAX, nonce=nonce)
    ciphertext, _ = cipher.encrypt_and_digest(data)
    return ciphertext


def decrypt(data, nonce):
    cipher = AES.new(_secret_key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt(data)


def _delete(key):
    _store.delete(_prefix + key)


def _put(key, value, prefix=None):
    prefix = prefix if prefix else _prefix
    ciphertext = encrypt(value, calculate_nonce(key))
    _store.put(prefix + key, ciphertext)


def add_nonce(file_name, nonce):
    with open(file_name, "ab") as f:
        f.write(nonce)


def remove_nonce(file_name, nonce):
    with open(file_name, "ab+") as f:
        f.seek(-len(nonce), os.SEEK_END)
        f.truncate()


def _put_file_streaming(file_name, key):
    update_progress("[Encrypting] " + file_name)
    cleartext_file = temp_file_name()
    copyfile(file_name, cleartext_file)
    add_nonce(cleartext_file, calculate_nonce(key))
    cyber_file = temp_file_name()
    pyAesCrypt.encryptFile(cleartext_file, cyber_file, _password, PY_CRYPT_BUFFER_SIZE)
    update_progress("[Uploading]  " + file_name)
    _store.put_file(_partition + "/files/" + key, cyber_file)
    rm_rf(cleartext_file)
    rm_rf(cyber_file)


def _put_file_in_memory(file_name, key):
    update_progress("[Uploading]  " + file_name)
    with open(file_name, "rb") as f:
        _put(key, f.read(), prefix=_partition + "/files/")


def _put_file(key, file_name, size, skip):
    if size > 16777216:
        encryption_mode = "streaming"
        if skip:
            update_progress("[Skipped]    " + file_name)
        else:
            _put_file_streaming(file_name, key)
    else:
        encryption_mode = "in-memory"
        if skip:
            update_progress("[Skipped]    " + file_name)
        else:
            _put_file_in_memory(file_name, key)

    meta_table[file_name] = MetaData(
        md5sum=key, encryption_mode=encryption_mode, file_size=size
    )


def _get(key, prefix=None):
    prefix = prefix if prefix else _prefix
    try:
        ciphertext = _store.get(prefix + key)
    except KeyError:
        return None
    return decrypt(ciphertext, calculate_nonce(key))


def _get_file(meta_data, target):
    key = meta_data["md5sum"]
    encryption_mode = meta_data["encryption_mode"]
    update_progress(f"[downloading] {target}")

    global _progress_bytes
    if os.path.exists(target):
        file_md5 = md5(target)
        if key == file_md5:
            _progress_bytes += meta_data["file_size"]
            update_progress(f"[Skipping]  {target}")
        else:
            raise ValueError(f"{target} already exists.")
    else:
        if encryption_mode == "in-memory":
            with open(target, "wb") as f:
                f.write(_get(key=key, prefix=_partition + "/files/"))
                _progress_bytes += meta_data["file_size"]
        elif encryption_mode == "streaming":
            cyber_file = temp_file_name()
            cleartext_file = temp_file_name()
            try:
                with open(cyber_file, "wb") as f:
                    _store.get_file(_partition + "/files/" + key, f)
            except KeyError:
                print("Warning: Expected file " + key + " missing.")
            _progress_bytes += meta_data["file_size"]
            update_progress(f"[decrypting] {target}")
            pyAesCrypt.decryptFile(
                cyber_file, cleartext_file, _password, PY_CRYPT_BUFFER_SIZE
            )
            update_progress(f"[copying]     {target}")
            remove_nonce(cleartext_file, calculate_nonce(key))
            copyfile(cleartext_file, target)
            rm_rf(cyber_file)
            rm_rf(cleartext_file)
        else:
            raise ValueError(f"Invalid memory mode: {encryption_mode}")


def _keys():
    return [x[len(_prefix) :] for x in _store.keys(prefix=_prefix)]


def _files():
    return [
        x[len(_partition + "/files/") :]
        for x in _store.keys(prefix=_partition + "/files/")
    ]


def md5(file_name):
    hash_md5 = hashlib.md5()
    with open(file_name, "rb") as f:
        for chunk in iter(lambda: f.read(16384), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def _backup_dir(path, files=None):
    files = files if files else _files()
    for f in os.listdir(path):
        full_file_path = os.path.join(path, f)

        if os.path.isdir(full_file_path):
            _backup_dir(full_file_path, files)
        else:
            md5sum = md5(full_file_path)
            file_size = os.path.getsize(full_file_path)
            skip = False
            if md5sum in files and not _force:
                skip = True
            _put_file(key=md5sum, file_name=full_file_path, size=file_size, skip=skip)
            global _progress_bytes
            _progress_bytes += file_size


def backup_dir(path):
    _backup_dir(path)
    update_progress("Uploading meta table")
    meta_table["total_file_size"] = _total_bytes
    _put(META_TABLE_KEY, meta_table.to_json().encode())


def restore_to(target):
    for key, meta_data in meta_table.items():
        if type(meta_data) == dict:
            filename = os.path.join(target, key.strip("/"))
            dirname = os.path.dirname(filename)
            if not os.path.exists(dirname):
                os.makedirs(dirname, exist_ok=True)
            _get_file(meta_data, filename)


def init(timestamp):
    global _prefix, _nonce, _secret_key, _password
    if _password is None:
        _password = getpass("Cyberpassword: ")
    _prefix = _partition + "/" + timestamp + "/"
    _secret_key = hashlib.md5(_password.encode()).digest()
    meta_table_data = _get(META_TABLE_KEY) or "{}"
    meta_table.from_json(meta_table_data)
    rm_rf(TEMP_FOLDER)
    if not os.path.exists(TEMP_FOLDER):
        os.makedirs(TEMP_FOLDER, exist_ok=True)


@click.group()
@click.option("--partition", default="default")
def main(partition):
    global _partition
    _partition = partition


@click.option("--directories")
@click.option("--force", is_flag=True, default=False)
@main.command()
def upload(directories, force):
    global _total_bytes, _force
    _force = force
    timestamp = datetime.now().strftime("%Y-%m-%d-%H")
    init(timestamp)
    directories_lines = None

    update_progress("Calculating upload size...")
    with open(directories, "r") as f:
        directories_lines = [line.rstrip() for line in f]
    _total_bytes = 0
    for line in directories_lines:
        _total_bytes += dir_size(line)
    for directory_path in directories_lines:
        backup_dir(directory_path)
    rm_rf(TEMP_FOLDER)
    update_progress("Success", finish=True)


@click.option("--timestamp", required=True)
@click.option("--destination", required=True)
@main.command()
def restore(timestamp, destination):
    global _total_bytes
    init(timestamp)
    if meta_table == {}:
        print(
            f'Error: No backup with timestamp "{timestamp}" exists at partition "{_partition}".'
        )
        sys.exit(1)
    _total_bytes = meta_table["total_file_size"]
    restore_to(destination)
    update_progress("Success", finish=True)
    rm_rf(TEMP_FOLDER)
