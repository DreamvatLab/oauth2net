import fileinput
import ctypes
import sys

hosts = {
    "p.test.com": "127.0.0.1",
    "i.test.com": "127.0.0.1",
    "w.test.com": "127.0.0.1",
}

hostsPath = "C:/Windows/System32/drivers/etc/hosts"


def exists(hosts, host: str) -> bool:
    return host in hosts


def replaceOrAppend(**dic):
    try:
        # replace
        for line in fileinput.input(hostsPath, inplace=True):
            found = False
            for key in dic.keys():
                if line.find(key) >= 0:
                    found = True
                    print(f"{dic[key]}\t{key}")
            if not found:
                print(line[:-1])

        # append
        f = open(hostsPath, "r+")
        hosts = f.read()
        for key in dic.keys():
            if key not in hosts:
                f.writelines(f"{dic[key]}\t{key}\n")
    except IOError as ex:
        print(ex)
    finally:
        f.close()


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


if is_admin():
    replaceOrAppend(**hosts)
else:
    if sys.version_info[0] == 3:
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, __file__, None, 1)
    else:  # in python2.x
        ctypes.windll.shell32.ShellExecuteW(
            None, u"runas", str(sys.executable), str(__file__), None, 1)
