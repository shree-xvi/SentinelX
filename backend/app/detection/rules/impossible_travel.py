import math
from datetime import datetime, timezone
from typing import List, Dict, Any
from backend.app.detection.base import DetectionRule


def haversine_distance_miles(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate the great-circle distance between two points on Earth in miles."""
    r = 3958.8  # Earth radius in miles
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = math.sin(delta_phi / 2.0) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2.0) ** 2
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    return r * c


class ImpossibleTravelRule(DetectionRule):
    rule_type = "IMPOSSIBLE_TRAVEL"
    default_severity = "CRITICAL"

    def evaluate(self, events: List[Dict[str, Any]], config: Dict[str, Any]) -> List[Dict[str, Any]]:
        max_speed_mph = float(config.get("max_speed_mph", 500.0))  # Max commercial flight speed
        max_window_hours = float(config.get("max_window_hours", 6.0))

        # Group login events by user / employee
        events_by_user: Dict[str, List[Dict[str, Any]]] = {}

        for event in events:
            etype = str(event.get("event_type", "")).lower()
            if etype not in ("auth_success", "login_successful", "vpn_connect", "session_start"):
                continue

            user = event.get("username") or event.get("employee_id")
            ts = event.get("timestamp")
            if isinstance(ts, str):
                ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if not user or not ts:
                continue

            data = event.get("data") or event.get("event_data") or {}
            events_by_user.setdefault(user, []).append({
                "timestamp": ts,
                "source_ip": event.get("source_ip"),
                "employee_id": event.get("employee_id"),
                "username": user,
                "country": data.get("country"),
                "city": data.get("city"),
                "lat": data.get("lat") or data.get("latitude"),
                "lon": data.get("lon") or data.get("longitude"),
            })

        alerts = []
        for user, user_events in events_by_user.items():
            user_events.sort(key=lambda x: x["timestamp"])

            for i in range(len(user_events) - 1):
                first = user_events[i]
                second = user_events[i + 1]

                time_diff_hours = (second["timestamp"] - first["timestamp"]).total_seconds() / 3600.0
                if time_diff_hours <= 0.0 or time_diff_hours > max_window_hours:
                    continue

                # 1. Coordinate-based speed check
                if (first.get("lat") is not None and first.get("lon") is not None and
                    second.get("lat") is not None and second.get("lon") is not None):
                    try:
                        dist = haversine_distance_miles(
                            float(first["lat"]), float(first["lon"]),
                            float(second["lat"]), float(second["lon"])
                        )
                        calculated_speed = dist / time_diff_hours

                        if dist > 50.0 and calculated_speed > max_speed_mph:
                            alerts.append({
                                "alert_type": self.rule_type,
                                "severity": config.get("severity", self.default_severity),
                                "source_ip": second["source_ip"],
                                "employee_id": second["employee_id"],
                                "evidence": {
                                    "rule": self.rule_type,
                                    "username": user,
                                    "distance_miles": round(dist, 1),
                                    "time_diff_minutes": round(time_diff_hours * 60, 1),
                                    "speed_mph": round(calculated_speed, 1),
                                    "origin": f"{first.get('city', 'Unknown')}, {first.get('country', 'Unknown')} ({first['source_ip']})",
                                    "destination": f"{second.get('city', 'Unknown')}, {second.get('country', 'Unknown')} ({second['source_ip']})",
                                    "origin_time": first["timestamp"].isoformat(),
                                    "destination_time": second["timestamp"].isoformat(),
                                },
                                "detected_at": datetime.now(timezone.utc)
                            })
                            continue
                    except (ValueError, TypeError):
                        pass

                # 2. Country-based check if different countries within short time (e.g. < 2 hours)
                if (first.get("country") and second.get("country") and
                    first["country"] != second["country"] and time_diff_hours < 2.0):
                    alerts.append({
                        "alert_type": self.rule_type,
                        "severity": config.get("severity", self.default_severity),
                        "source_ip": second["source_ip"],
                        "employee_id": second["employee_id"],
                        "evidence": {
                            "rule": self.rule_type,
                            "username": user,
                            "time_diff_minutes": round(time_diff_hours * 60, 1),
                            "origin_country": first["country"],
                            "destination_country": second["country"],
                            "origin_ip": first["source_ip"],
                            "destination_ip": second["source_ip"],
                        },
                        "detected_at": datetime.now(timezone.utc)
                    })

        return alerts

