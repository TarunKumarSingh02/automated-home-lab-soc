
import platform
from datetime import datetime, timezone

def main():
    print("=" * 45)
    print("AUTOMATED SOC - SECURITY MONITORING LAB")
    print("=" * 45)

    print("Operating System:", platform.system())
    print("Machine:", platform.machine())
    print("Current Time:", datetime.now(timezone.utc))
    print("SOC Development Environment: READY")

if __name__ == "__main__":
    main()
