# -*- coding: utf-8 -*-
"""
    helloworld
    ~~~~~~~~~~

    A minimal working example, showing :mod:`pyxs` API usage.
"""

from __future__ import unicode_literals, print_function

from pyxs import Client


with Client() as c:
    # a) read.
    print(
        c.read(b"/local/domain/0/domid")
    )  # ==> 0, which is just what we expect.

    # b) write-read.
    c.write(b"/foo/bar", b"baz")
    print(c.read(b"/foo/bar"))  # ==> "baz"

    # c) exceptions! let's try to read a non-existant path.
    try:
        c.read(b"/path/to/something/useless")
    except RuntimeError as e:
        print(e)

    # d) okay, time to delete that /foo/bar path.
    c.rm(b"/foo/bar")

    try:
        c.read(b"/foo/bar")
    except RuntimeError as e:
        print("`/foo/bar` is no moar!")

    # e) directory listing and permissions.
    print(c.directory(b"/local/domain/0"))
    print(c.get_perms(b"/local/domain/0"))

    # f) let's watch some paths!
    c.write(b"/foo/bar", b"baz")
    print(c.watch(b"/foo/bar", "baz"))
    print("Watching ... do `$ xenstore-write /foo/bar <anything>`.")
    print(c.watch_event())
    print(c.unwatch(b"/foo/bar", "baz"))

    # g) domain managment commands.
    print(c.get_domain_path(0))
    print(c.is_domain_introduced(0))
