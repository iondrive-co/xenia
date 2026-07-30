from __future__ import annotations

import pytest

from xenia import dbus


def roundtrip(signature: str, value):
    writer = dbus.Writer()
    writer.write(signature, value)
    return dbus.Reader(bytes(writer.buf)).read(signature)


@pytest.mark.parametrize("signature,expected", [
    ("ia{sv}av", ["i", "a{sv}", "av"]),
    ("a(iiay)ias", ["a(iiay)", "i", "as"]),
    ("(sa(iiay)ss)", ["(sa(iiay)ss)"]),
    ("u(ia{sv}av)", ["u", "(ia{sv}av)"]),
    ("", []),
])
def test_signatures_split_into_complete_types(signature, expected):
    assert dbus.split_signature(signature) == expected


@pytest.mark.parametrize("signature,value", [
    ("y", 0), ("y", 255),
    ("b", True), ("b", False),
    ("n", -32768), ("q", 65535),
    ("i", -2147483648), ("u", 4294967295),
    ("x", -2**63), ("t", 2**64 - 1),
    ("d", 1.5), ("d", -0.0),
    ("s", ""), ("s", "hello"), ("s", "café · ünïcode"),
    ("o", "/StatusNotifierItem"),
    ("g", "a(iiay)"),
])
def test_basic_types_round_trip(signature, value):
    assert roundtrip(signature, value) == value


def test_a_byte_array_round_trips_as_bytes():
    assert roundtrip("ay", b"\x00\x01\xfe\xff") == b"\x00\x01\xfe\xff"


def test_empty_containers_round_trip():
    assert roundtrip("as", []) == []
    assert roundtrip("a{sv}", {}) == {}
    assert roundtrip("ay", b"") == b""


def test_the_icon_pixmap_shape_round_trips():
    value = [(32, 32, bytes(range(256)) * 16)]
    assert roundtrip("a(iiay)", value) == value


def test_the_tooltip_shape_round_trips():
    value = ("", [], "xenia", "recording")
    assert roundtrip("(sa(iiay)ss)", value) == value


def test_a_property_dictionary_round_trips():
    value = {"label": dbus.Variant("s", "Show Report"),
             "enabled": dbus.Variant("b", True)}
    assert roundtrip("a{sv}", value) == value


def test_the_recursive_menu_layout_round_trips():
    child = dbus.Variant("(ia{sv}av)", (1, {"label": dbus.Variant("s", "Quit")}, []))
    value = (0, {"children-display": dbus.Variant("s", "submenu")}, [child])
    assert roundtrip("(ia{sv}av)", value) == value


def test_alignment_survives_an_awkward_prefix():
    value = (1, 2.5, "x", 9)
    assert roundtrip("(ydsx)", value) == value


def test_nested_arrays_round_trip():
    assert roundtrip("aas", [["a"], [], ["b", "c"]]) == [["a"], [], ["b", "c"]]


def test_a_method_call_encodes_and_decodes():
    message = dbus.Message(
        dbus.METHOD_CALL, path="/MenuBar", interface="com.canonical.dbusmenu",
        member="GetLayout", destination="org.kde.Watcher",
        signature="iias", body=[0, 2, []], serial=7)

    back = dbus.Message.decode(message.encode())

    assert back.kind == dbus.METHOD_CALL
    assert (back.path, back.interface, back.member) == (
        "/MenuBar", "com.canonical.dbusmenu", "GetLayout")
    assert back.body == [0, 2, []]
    assert back.serial == 7


def test_a_reply_carries_its_reply_serial():
    reply = dbus.Message(dbus.METHOD_RETURN, reply_serial=42,
                         signature="s", body=["ok"], serial=8)
    back = dbus.Message.decode(reply.encode())
    assert back.reply_serial == 42
    assert back.body == ["ok"]


def test_an_error_decodes_with_its_name():
    error = dbus.Message(dbus.ERROR, error_name="org.freedesktop.DBus.Error.Failed",
                         reply_serial=3, signature="s", body=["nope"], serial=9)
    back = dbus.Message.decode(error.encode())
    assert back.error_name == "org.freedesktop.DBus.Error.Failed"


def test_declared_length_matches_the_encoding():
    message = dbus.Message(
        dbus.METHOD_CALL, path="/StatusNotifierItem",
        interface="org.freedesktop.DBus.Properties", member="GetAll",
        signature="s", body=["org.kde.StatusNotifierItem"], serial=1)
    raw = message.encode()
    assert dbus.Message.header_length(raw) == len(raw)


def test_messages_frame_correctly_back_to_back():
    first = dbus.Message(dbus.SIGNAL, path="/a", interface="i.f", member="One",
                         signature="s", body=["x"], serial=1).encode()
    second = dbus.Message(dbus.SIGNAL, path="/bb", interface="i.f", member="Two",
                          signature="u", body=[7], serial=2).encode()
    stream = first + second

    length = dbus.Message.header_length(stream)
    assert length == len(first)
    assert dbus.Message.decode(stream[:length]).member == "One"
    assert dbus.Message.decode(stream[length:]).member == "Two"


def test_the_socket_path_is_read_from_a_bus_address():
    assert dbus._socket_path("unix:path=/run/user/1000/bus") == "/run/user/1000/bus"


def test_an_abstract_socket_keeps_its_leading_nul():
    assert dbus._socket_path("unix:abstract=/tmp/dbus-x").startswith("\0")


def test_a_guid_suffix_does_not_confuse_the_parser():
    address = "unix:path=/run/user/1000/bus,guid=deadbeef"
    assert dbus._socket_path(address) == "/run/user/1000/bus"


def test_an_address_with_no_socket_is_an_error():
    with pytest.raises(dbus.DBusError):
        dbus._socket_path("tcp:host=localhost,port=1234")


def test_the_session_address_falls_back_to_the_runtime_dir(monkeypatch, tmp_path):
    monkeypatch.delenv("DBUS_SESSION_BUS_ADDRESS", raising=False)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    (tmp_path / "bus").touch()
    assert dbus.session_bus_address() == f"unix:path={tmp_path / 'bus'}"


def test_no_bus_anywhere_is_a_clean_error(monkeypatch, tmp_path):
    monkeypatch.delenv("DBUS_SESSION_BUS_ADDRESS", raising=False)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    with pytest.raises(dbus.DBusError):
        dbus.session_bus_address()
