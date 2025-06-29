# AC Watch Program

This program monitors the gang AC for errors and automatically recovers from them.

## Features

- Monitors AC status every minute
- Saves current temperature setting when AC is on
- Detects error codes and attempts automatic recovery
- Logs all errors to `error_journal.json`
- Implements rate limiting: waits 30 minutes if more than 2 errors occur in 5 minutes
- Only operates when AC is on (does nothing when AC is off)

## Recovery Process

When an error is detected:
1. Stop the AC
2. Wait 5 seconds
3. Start the AC
4. Restore the previously saved temperature

## Files Created

- `ac_state.json` - Stores the last known temperature setting
- `error_journal.json` - Logs all errors with timestamps and error codes

## Usage

```bash
# Run the watch program
./ac-watch

# Run in background
nohup ./ac-watch > ac-watch.log 2>&1 &

# Check the logs
tail -f ac-watch.log

# View error journal
cat error_journal.json | jq .
```

## Error Journal Format

```json
{
  "entries": [
    {
      "timestamp": "2024-01-20T15:30:45Z",
      "error_code": 5,
      "action": "restart_attempt",
      "temperature": 18
    }
  ],
  "error_counts": ["2024-01-20T15:30:45Z"]
}
```

## State File Format

```json
{
  "last_temperature": 18,
  "last_check": "2024-01-20T15:29:00Z"
}
```