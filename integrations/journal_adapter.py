
import json
import sys
from pathlib import Path
from datetime import datetime, timezone

source = Path(sys.argv[1])
destination = Path(sys.argv[2])

converted = []

for line in source.read_text(encoding="utf-8").splitlines():
    try:
        event = json.loads(line)
        message = event["MESSAGE"]
        microseconds = int(event["__REALTIME_TIMESTAMP"])

        if not isinstance(message, str):
            continue

        timestamp = datetime.fromtimestamp(
            microseconds / 1_000_000,
            tz=timezone.utc
        ).isoformat()

        converted.append(f"{timestamp} {message}")

    except (ValueError, KeyError, TypeError, OverflowError):
        continue

destination.write_text(
    "\n".join(converted) + ("\n" if converted else ""),
    encoding="utf-8"
)

print(f"Converted {len(converted)} SSH log entries.")
