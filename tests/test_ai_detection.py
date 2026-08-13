import importlib


def test_build_detection_summary_counts_threats():
    app_module = importlib.import_module("app")

    packets = [
        {"src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "TCP", "length": 120, "prediction": "BENIGN", "status": "SAFE"},
        {"src": "10.0.0.3", "dst": "10.0.0.4", "protocol": "UDP", "length": 1400, "prediction": "SUSPICIOUS", "status": "ALERT"},
        {"src": "10.0.0.5", "dst": "10.0.0.6", "protocol": "TCP", "length": 5000, "prediction": "ATTACK", "status": "THREAT"},
    ]

    summary = app_module.build_detection_summary(packets)

    assert summary["total_packets"] == 3
    assert summary["safe_count"] == 1
    assert summary["alert_count"] == 1
    assert summary["threat_count"] == 1
    assert summary["attack_rate"] == 66.7
    assert summary["latest_alerts"][0]["prediction"] == "ATTACK"
