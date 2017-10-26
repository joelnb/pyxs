from __future__ import absolute_import

import sys

from .connection import PacketConnection
from .exceptions import ConnectionError, PyXSError, WindowsDriverError

if os.name in ["nt"]:
    import ctypes
    from ctypes.wintypes import HANDLE
    from ctypes.wintypes import BOOL
    from ctypes.wintypes import HWND
    from ctypes.wintypes import DWORD
    from ctypes.wintypes import WORD
    from ctypes.wintypes import LONG
    from ctypes.wintypes import ULONG
    from ctypes.wintypes import LPCSTR
    from ctypes.wintypes import HKEY
    from ctypes.wintypes import BYTE
    import wmi
else:
    raise ImportError(
        "windows functionality is not available on: {}".format(os.name)
    )

sys.coinit_flags = 0

__all__ = ['WinPVPacketConnection', 'GPLPVPacketConnection']


def _wrap_exception(ex, cause):
    if sys.hexversion >= 0x3000000:
        # raise ex from orig
        raise ex
    else:
        raise ex


class WinPVPacketConnection(PacketConnection):
    _session_query_string = ("select * from XenProjectXenStoreSession "
                             "where InstanceName = "
                             "'Xen Interface\Session_PyxsSession_0'")
    _wmi_session = None

    def __init__(self):
        pass

    def __copy__(self):
        return self.__class__(self.path)

    def connect(self, retries=20):
        def _connect_helper(sleep=5, retry=0):
            # Create a WMI Session
            try:
                if not self._wmi_session or retry > 0:
                    self._wmi_session = wmi.WMI(moniker="//./root/wmi",
                                                find_classes=False)
                xenStoreBase = self._wmi_session.XenProjectXenStoreBase()[0]
            except Exception as orig:   # WMI can raise all sorts of exceptions
                if retry < retries:
                    sleep(5)
                    _connect_helper(retry=(retry + 1))
                    return
                else:
                    _wrap_exception(PyXSError(None), orig)

        _connect_helper()

        try:
            sessions = self._wmi_session.query(self._session_query_string)
        except Exception:
            sessions = []

        if len(sessions) <= 0:
            session_name = "PyxsSession"
            session_id = xenStoreBase.AddSession(Id=session_name)[0]
            query = ("select * from XenProjectXenStoreSession where "
                     "SessionId = {id}").format(id=session_id)
            try:
                sessions = self._wmi_session.query(query)
            except Exception:
                sleep(0.5)
                try:
                    sessions = self._wmi_session.query(query)
                except Exception as e:
                    _wrap_exception(PyXSError(None), e)

        self.session = sessions.pop()

    # Emulate sending the packet directly to the XenStore interface
    # and store the result in response_packet
    def send(self, packet):
        global _wmi_session

        try:
            if not _wmi_session or not self.session:
                self.connect()
        except wmi.x_wmi as e:
            _wrap_exception(PyXSError(None), e)

        if packet.op == Op.READ:
            try:
                result = self.session.GetValue(packet.payload)[0]
            except wmi.x_wmi:
                _wrap_exception(PyXSError(None), e)
        elif packet.op == Op.WRITE:
            try:
                payload = packet.payload.split('\x00', 1)
                self.session.SetValue(payload[0], payload[1])
            except wmi.x_wmi:
                _wrap_exception(PyXSError(None), e)

            result = "OK"
        elif packet.op == Op.RM:
            try:
                self.session.RemoveValue(packet.payload)[0]
            except wmi.x_wmi:
                _wrap_exception(PyXSError(None), e)

            result = "OK"
        elif packet.op == Op.DIRECTORY:
            try:
                result = self.session.GetChildren(packet.payload)
                result = "\x00".join(result[0].childNodes)
            except wmi.x_wmi:
                _wrap_exception(PyXSError(None), e)
        else:
            raise ArgumentError(
                "Unsupported XenStore Action ({x})".format(x=packet.op)
            )

        self.response_packet = Packet(packet.op, result, packet.rq_id,
                                      packet.tx_id)

    def recv(self):
        return self.response_packet

    def disconnect(self, silent=True):
        self.session = None


class GPLPVPacketConnection(PacketConnection):
    _win_device_path = None

    def __init__(self):
        # Once the windows device path is learned once reuse it otherwise
        # ctypes.POINTER() for the same structure leaks memory.   Although
        # this can be reclaimed with ctypes._reset_cache() this is poking
        # at the internals of ctypes which doesn't seem to be a good idea.

        if self._win_device_path:
            self.path = self._win_device_path
            return

        # Determine self.path using some magic Windows code which is derived
        # from:
        # http://pydoc.net/Python/pyserial/2.6/serial.tools.list_ports_windows/.
        # The equivalent C from The GPLPV driver source can be found in
        # get_xen_interface_path() of shutdownmon.
        # http://xenbits.xensource.com/ext/win-pvdrivers/file/896402519f15/shutdownmon/shutdownmon.c

        DIGCF_PRESENT = 2
        DIGCF_DEVICEINTERFACE = 16
        NULL = None
        ERROR_SUCCESS = 0
        ERROR_INSUFFICIENT_BUFFER = 122
        ERROR_NO_MORE_ITEMS = 259

        HDEVINFO = ctypes.c_void_p
        PCTSTR = ctypes.c_char_p
        CHAR = ctypes.c_char
        PDWORD = ctypes.POINTER(DWORD)
        LPDWORD = ctypes.POINTER(DWORD)
        PULONG = ctypes.POINTER(ULONG)

        # Some structures used by the Windows API
        class GUID(ctypes.Structure):
            _fields_ = [
                ('Data1', DWORD),
                ('Data2', WORD),
                ('Data3', WORD),
                ('Data4', BYTE * 8),
            ]

            def __str__(self):
                return "{%08x-%04x-%04x-%s-%s}" % (
                    self.Data1,
                    self.Data2,
                    self.Data3,
                    ''.join(["%02x" % d for d in self.Data4[:2]]),
                    ''.join(["%02x" % d for d in self.Data4[2:]]),
                )

        PGUID = ctypes.POINTER(GUID)

        class SP_DEVINFO_DATA(ctypes.Structure):
            _fields_ = [
                ('cbSize', DWORD),
                ('ClassGuid', GUID),
                ('DevInst', DWORD),
                ('Reserved', PULONG),
            ]

            def __str__(self):
                return "SP_DEVINFO_DATA(ClassGuid={} DevInst={})".format(
                    self.ClassGuid,
                    self.DevInst
                )

        PSP_DEVINFO_DATA = ctypes.POINTER(SP_DEVINFO_DATA)

        class SP_DEVICE_INTERFACE_DATA(ctypes.Structure):
            _fields_ = [
                ('cbSize', DWORD),
                ('InterfaceClassGuid', GUID),
                ('Flags', DWORD),
                ('Reserved', PULONG),
            ]

            def __str__(self):
                return ("SP_DEVICE_INTERFACE_DATA(InterfaceClassGuid={}, "
                        "Flags={}").format(self.InterfaceClassGuid,
                                           self.Flags)

        PSP_DEVICE_INTERFACE_DATA = ctypes.POINTER(SP_DEVICE_INTERFACE_DATA)
        PSP_DEVICE_INTERFACE_DETAIL_DATA = ctypes.c_void_p

        # Import the Windows APIs
        setupapi = ctypes.windll.LoadLibrary("setupapi")

        SetupDiGetClassDevs = setupapi.SetupDiGetClassDevsA
        SetupDiGetClassDevs.argtypes = [PGUID, PCTSTR, HWND, DWORD]
        SetupDiGetClassDevs.restype = HDEVINFO

        # Return code checkers
        def _valid_handle(value, func, arguments):
            if value == 0:
                raise WindowsDriverError(str(ctypes.WinError()))
            return value

        SetupDiGetClassDevs.errcheck = _valid_handle

        SetupDiEnumDeviceInterfaces = setupapi.SetupDiEnumDeviceInterfaces
        SetupDiEnumDeviceInterfaces.argtypes = [
            HDEVINFO, PSP_DEVINFO_DATA, PGUID, DWORD, PSP_DEVICE_INTERFACE_DATA
        ]
        SetupDiEnumDeviceInterfaces.restype = BOOL

        SetupDiGetDeviceInterfaceDetail = setupapi.SetupDiGetDeviceInterfaceDetailA
        SetupDiGetDeviceInterfaceDetail.argtypes = [
            HDEVINFO, PSP_DEVICE_INTERFACE_DATA,
            PSP_DEVICE_INTERFACE_DETAIL_DATA, DWORD, PDWORD, PSP_DEVINFO_DATA
        ]
        SetupDiGetDeviceInterfaceDetail.restype = BOOL

        SetupDiDestroyDeviceInfoList = setupapi.SetupDiDestroyDeviceInfoList
        SetupDiDestroyDeviceInfoList.argtypes = [HDEVINFO]
        SetupDiDestroyDeviceInfoList.restype = BOOL

        b = (BYTE * 8)(0x92, 0x52, 0x0, 0xdb, 0xd8, 0x4f, 0x1, 0x8e)
        GUID_XENBUS_IFACE = GUID(0x14ce175a, 0x3ee2, 0x4fae, b)

        handle = SetupDiGetClassDevs(ctypes.byref(GUID_XENBUS_IFACE), NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);

        sdid = SP_DEVICE_INTERFACE_DATA()
        sdid.cbSize = ctypes.sizeof(sdid)

        enum_result = SetupDiEnumDeviceInterfaces(
            handle, NULL, ctypes.byref(GUID_XENBUS_IFACE), 0,
            ctypes.byref(sdid)
        )
        if not enum_result and ctypes.GetLastError() != ERROR_NO_MORE_ITEMS:
            raise WindowsDriverError(str(ctypes.WinError()))

        buf_len = DWORD()

        get_result = SetupDiGetDeviceInterfaceDetail(
            handle, ctypes.byref(sdid), NULL, 0, ctypes.byref(buf_len), NULL
        )
        if not get_result:
            if ctypes.GetLastError() != ERROR_INSUFFICIENT_BUFFER:
                raise WindowsDriverError(str(ctypes.WinError()))

        # We didn't know how big to make the structure until buf_len is
        # assigned...
        class SP_DEVICE_INTERFACE_DETAIL_DATA_A(ctypes.Structure):
            _fields_ = [
                ('cbSize', DWORD),
                ('DevicePath', CHAR * (buf_len.value - ctypes.sizeof(DWORD))),
            ]

            def __str__(self):
                return "DevicePath:%s" % (self.DevicePath,)

        sdidd = SP_DEVICE_INTERFACE_DETAIL_DATA_A()
        sdidd.cbSize = ctypes.sizeof(
            ctypes.POINTER(SP_DEVICE_INTERFACE_DETAIL_DATA_A)
        )

        if not SetupDiGetDeviceInterfaceDetail(handle, ctypes.byref(sdid),
                                               ctypes.byref(sdidd), buf_len,
                                               NULL, NULL):
            raise WindowsDriverError(str(ctypes.WinError()))

        self.path = "" + sdidd.DevicePath

        SetupDiDestroyDeviceInfoList(handle)

        _win_device_path = self.path

    def __copy__(self):
        return self.__class__()

    def connect(self):
        if self.fd:
            return

        # CreateFile(path, FILE_GENERIC_READ|FILE_GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        # http://docs.activestate.com/activepython/2.7/pywin32/win32file__CreateFile_meth.html
        # PyHANDLE = CreateFile(fileName, desiredAccess , shareMode , attributes , CreationDisposition , flagsAndAttributes , hTemplateFile )
        return

        try:
            self.fd = CreateFile(
                path, FILE_GENERIC_READ | FILE_GENERIC_WRITE, 0, None,
                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None
            )
        except Exception as e:
            raise ConnectionError(
                "Error while opening {0!r}: {1}".format(self.path, e.args)
            )
