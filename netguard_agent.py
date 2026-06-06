#!/usr/bin/env python3
"""
NetGuard AI — Lokalny Agent Sieci Domowej
Backward-compatible stub that delegates to netguard/ package.
"""
import sys
import os

# Ensure the package is importable
_pkg_dir = os.path.dirname(os.path.abspath(__file__))
if _pkg_dir not in sys.path:
    sys.path.insert(0, _pkg_dir)

# Re-export everything from the netguard package for backward compatibility
from netguard import *
from netguard.config import *
from netguard.models import *
from netguard.utils import *
from netguard.database import DeviceDB
from netguard.gateway import *
from netguard.scanner import NetworkScanner
from netguard.analyzer import PacketAnalyzer
from netguard.router_sync import RouterSync
from netguard.ai_analyst import AIAnalyst
from netguard.parental import ChildDNSProxy
from netguard.gateway import SuricataManager
from netguard.alerts import AlertManager
from netguard.email_service import send_html_email, build_daily_report_html
from netguard.dashboard import start_dashboard
from netguard.license import verify_license, get_plan, get_limits, is_paid

# Delegate main
from netguard.__main__ import main, run_setup, print_banner, NetGuardAgent

if __name__ == "__main__":
    main()
