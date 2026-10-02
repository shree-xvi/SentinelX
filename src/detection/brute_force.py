from datetime import timedelta

MAX_ATTEMPTS = 5
TIME_WINDOW_MINUTES = 5


def detect_brute_force(failed_timestamps):
    failed_timestamps.sort()

    time_window = timedelta(minutes=TIME_WINDOW_MINUTES)

    for i in range(len(failed_timestamps)):
        window_start = failed_timestamps[i]

        attempts_in_window = 0

        for timestamp in failed_timestamps[i:]:
            if timestamp - window_start <= time_window:
                attempts_in_window += 1
            else:
                break

        if attempts_in_window >= MAX_ATTEMPTS:
            return {
                "type": "BRUTE_FORCE",
                "severity": "HIGH",
                "attempts": attempts_in_window,
                "time_window_minutes": TIME_WINDOW_MINUTES
            }

    return None