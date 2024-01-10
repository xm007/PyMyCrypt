import locale
import subprocess
import re
import os
import time


def get_locale_lang() -> str:
    ret_locale = list(locale.getdefaultlocale())
    if ret_locale[1] == 'cp950':
        return 'Big5'
    elif ret_locale[1] == 'cp1252':
        return 'utf8'
    elif ret_locale[1] == 'cp936':
        return 'gbk'
    else:
        return 'utf8'


def parse_last_volume_number(diskpart_message) -> int:
    new_diskpart_message = diskpart_message
    new_diskpart_message = new_diskpart_message.replace('磁碟區', 'Volume')  # Taiwan
    new_diskpart_message = new_diskpart_message.replace('卷', 'Volume')  # China
    new_diskpart_message = new_diskpart_message.replace('양', 'Volume')  # Korea
    new_diskpart_message = new_diskpart_message.replace('ボリューム', 'Volume')  # Japan
    match = re.findall(r'Volume\s{5}\d', new_diskpart_message)
    max_numb = 0
    if len(match) > 0:
        max_numb = re.search('\d',match[len(match) - 1]).group()
    return max_numb

def diskpart_create_vdisk(filelocation: str,size: int,format: str,g_DebugEnabled: bool = False):
    ret_locale_lang = get_locale_lang()
    p = subprocess.Popen("diskpart", stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=os.environ, )
    res1 = p.stdin.write(bytes(f"CREATE VDISK FILE={filelocation} maximum={size}\n", 'utf-8'))
    res1 = p.stdin.write(bytes(f"SELECT VDISK FILE={filelocation}\n", 'utf-8'))
    res1 = p.stdin.write(bytes(f"ATTACH VDISK\n", 'utf-8'))
    res1 = p.stdin.write(bytes(f"CREATE PARTITION PRIMARY\n", 'utf-8'))
    res1 = p.stdin.write(bytes(f"FORMAT FS={format} QUICK\n", 'utf-8'))
    res1 = p.stdin.write(bytes(f"ASSIGN\n", 'utf-8'))

    stdout, stderr = p.communicate()
    output = stdout.decode(ret_locale_lang, errors='ignore')
    last_volume_index = parse_last_volume_number(output)

    if g_DebugEnabled:
        print(output)

    p.kill()
    return last_volume_index

def diskpart_attach_vdisk(vhd_file_path: str,g_DebugEnabled: bool = False, readonly: bool = False) -> int:
    ret_locale_lang = get_locale_lang()
    p = subprocess.Popen("diskpart", stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=os.environ, )
    res1 = p.stdin.write(bytes("SELECT VDISK FILE=" + vhd_file_path + "\n", 'utf-8'))

    if readonly:
        res1 = p.stdin.write(bytes("ATTACH VDISK READONLY\n", 'utf-8'))
    else:
        res1 = p.stdin.write(bytes("ATTACH VDISK\n", 'utf-8'))

    res1 = p.stdin.write(bytes("LIST VOLUME\n", 'utf-8'))
    stdout, stderr = p.communicate()
    output = stdout.decode(ret_locale_lang, errors='ignore')
    last_volume_index = parse_last_volume_number(output)

    if g_DebugEnabled:
        print(output)

    p.kill()
    return last_volume_index

def diskpart_assign_letter(last_volume_index: int,drive:str,g_DebugEnabled: bool = False):
    ret_locale_lang = get_locale_lang()
    p = subprocess.Popen("diskpart", stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=os.environ, )
    res1 = p.stdin.write(bytes(f"SEL VOL {last_volume_index}\n", 'utf-8'))
    res1 = p.stdin.write(bytes(f"ASSIGN LETTER={drive}\n", 'utf-8'))

    stdout, stderr = p.communicate()
    output = stdout.decode(ret_locale_lang, errors='ignore')

    if g_DebugEnabled:
        print(output)

    p.kill()

def diskpart_unmount(vhd_file_path: str,  last_volume_index: int, g_DebugEnabled: bool = False) -> bool:
    print('running for unmount ...')

    ret_locale_lang = get_locale_lang()
    p = subprocess.Popen("diskpart", stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=os.environ, )
    res1 = p.stdin.write(bytes("SELECT VOLUME " + str(last_volume_index) + "\n", 'utf-8'))
    res1 = p.stdin.write(bytes("REMOVE ALL DISMOUNT\n", 'utf-8'))

    res1 = p.stdin.write(bytes("SELECT VDISK FILE=" + vhd_file_path + "\n", 'utf-8'))
    res1 = p.stdin.write(bytes("DETACH VDISK\n", 'utf-8'))

    stdout, stderr = p.communicate()
    output = stdout.decode(ret_locale_lang, errors='ignore')

    if g_DebugEnabled:
        print(output)

    p.kill()
    return True


def diskpart_mount_as_folder(vhd_file_path: str, last_volume_index: int, mount_point_path: str, readonly: bool = False , g_DebugEnabled: bool = False) -> bool:
    print('running for mount ...')
    ret_locale_lang = get_locale_lang()
    p = subprocess.Popen("diskpart", stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=os.environ, )
    res1 = p.stdin.write(bytes("SELECT VDISK FILE=" + vhd_file_path + "\n", 'utf-8'))

    if readonly:
        res1 = p.stdin.write(bytes("ATTACH VDISK READONLY\n", 'utf-8'))
    else:
        res1 = p.stdin.write(bytes("ATTACH VDISK\n", 'utf-8'))

    res1 = p.stdin.write(bytes("SELECT VOLUME " + str(last_volume_index) + "\n", 'utf-8'))
    res1 = p.stdin.write(bytes("REMOVE ALL DISMOUNT\n", 'utf-8'))
    res1 = p.stdin.write(bytes("ASSIGN MOUNT=" + mount_point_path + "\n", 'utf-8'))
    stdout, stderr = p.communicate()
    output = stdout.decode(ret_locale_lang, errors='ignore')

    if g_DebugEnabled:
        print(output)

    p.kill()
    return True
