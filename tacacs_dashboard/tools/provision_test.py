import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tacacs_dashboard.services.olt_provision import provision_user_on_olt

if __name__ == "__main__":
    print(provision_user_on_olt("10.235.110.28", "view02", "OLT_VIEW", save=False))
