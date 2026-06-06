import os, sys, json, time, socket, struct, hashlib, secrets, logging, threading, shutil, gc
from functools import wraps
import subprocess, ipaddress, re, datetime, signal
from collections import defaultdict, deque
from typing import Optional

VERSION = "1.5.0"
_update_available = False
_latest_version = VERSION

IS_WINDOWS = sys.platform == 'win32'

_SKIP_ROOT_CHECK = os.environ.get("NETGUARD_SKIP_ROOT_CHECK", "").lower() in ("1", "true", "yes")
if not _SKIP_ROOT_CHECK:
    if IS_WINDOWS:
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("NetGuard wymaga uprawnień administratora na Windows.")
    else:
        if os.geteuid() != 0:
            print("NetGuard wymaga uprawnień root.")
            sys.exit(1)

try:
    from scapy.all import (ARP, Ether, srp, sniff, send as scapy_send,
                           IP, TCP, UDP, DNS, DNSQR, DNSRR, conf as scapy_conf)
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    from flask import Flask, jsonify, request, send_from_directory, Response, stream_with_context
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False

try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init()
    C = {
        "red": Fore.RED, "green": Fore.GREEN, "yellow": Fore.YELLOW,
        "blue": Fore.CYAN, "gray": Fore.WHITE, "bold": Style.BRIGHT, "reset": Style.RESET_ALL
    }
except ImportError:
    C = defaultdict(str)

_AGENT_DIR = os.path.dirname(os.path.abspath(__file__))
_AGENT_DIR = os.path.dirname(_AGENT_DIR)  # netguard/ → parent (project root)

# Global state placeholders — populated at runtime by __main__.py
CONFIG: dict = {}  # type: ignore
IS_GATEWAY = False
GATEWAY_WAN: str = None  # type: ignore
GATEWAY_LAN: str = None  # type: ignore
IS_HOME = False
IS_ENTERPRISE = False
IS_PAID = False
