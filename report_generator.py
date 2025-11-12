import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List


class ReportGenerator:
    def __init__(self, output_dir: Path):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
    
    def generate_json_report(self, data: Dict, filename: str) -> Path:
        filepath = self.output_dir / filename
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        return filepath
    
    def generate_summary_report(self, summary_data: Dict, timestamp: datetime) -> Path:
        report_data = {
            'report_metadata': {
                'generated_at': timestamp.isoformat(),
                'report_type': 'simulation_summary'
            },
            'simulation_summary': {
                'cycles': summary_data.get('simulation_cycles', 0),
                'start_time': summary_data.get('start_time'),
                'end_time': summary_data.get('end_time'),
                'duration_seconds': summary_data.get('duration_seconds', 0)
            },
            'packet_statistics': {
                'total_packets': summary_data.get('total_packets', 0),
                'checksum_mismatches': summary_data.get('checksum_mismatches', 0),
                'checksum_mismatch_rate': summary_data.get('checksum_mismatch_rate', 0),
                'unique_uav_ids': summary_data.get('unique_uav_ids', 0)
            },
            'latency_metrics': {
                'average_latency': summary_data.get('average_latency', 0),
                'latency_variance': summary_data.get('latency_variance', 0)
            },
            'alert_summary': {
                'total_alerts': summary_data.get('total_alerts', 0),
                'alerts_by_type': summary_data.get('alerts_by_type', {}),
                'alerts_by_severity': summary_data.get('alerts_by_severity', {})
            },
            'all_alerts': summary_data.get('all_alerts', [])
        }
        
        filename = f'analysis_run_{timestamp.strftime("%Y%m%d")}.json'
        return self.generate_json_report(report_data, filename)
    
    def generate_detailed_report(self, summary_data: Dict, stats_data: Dict, validation_data: Dict, timestamp: datetime) -> Path:
        report_data = {
            'report_metadata': {
                'generated_at': timestamp.isoformat(),
                'report_type': 'detailed_analysis'
            },
            'simulation_summary': {
                'cycles': summary_data.get('simulation_cycles', 0),
                'start_time': summary_data.get('start_time'),
                'end_time': summary_data.get('end_time'),
                'duration_seconds': summary_data.get('duration_seconds', 0)
            },
            'packet_statistics': {
                'total_packets': summary_data.get('total_packets', 0),
                'checksum_mismatches': summary_data.get('checksum_mismatches', 0),
                'checksum_mismatch_rate': summary_data.get('checksum_mismatch_rate', 0),
                'unique_uav_ids': summary_data.get('unique_uav_ids', 0)
            },
            'latency_metrics': {
                'average_latency': summary_data.get('average_latency', 0),
                'latency_variance': summary_data.get('latency_variance', 0)
            },
            'advanced_statistics': stats_data,
            'validation_statistics': validation_data,
            'alert_summary': {
                'total_alerts': summary_data.get('total_alerts', 0),
                'alerts_by_type': summary_data.get('alerts_by_type', {}),
                'alerts_by_severity': summary_data.get('alerts_by_severity', {})
            },
            'all_alerts': summary_data.get('all_alerts', [])
        }
        
        filename = f'detailed_analysis_{timestamp.strftime("%Y%m%d_%H%M%S")}.json'
        return self.generate_json_report(report_data, filename)
    
    def generate_alert_report(self, alerts: List[Dict], timestamp: datetime) -> Path:
        alert_report = {
            'report_metadata': {
                'generated_at': timestamp.isoformat(),
                'report_type': 'alert_analysis',
                'total_alerts': len(alerts)
            },
            'alerts_by_severity': self._group_alerts_by_severity(alerts),
            'alerts_by_type': self._group_alerts_by_type(alerts),
            'chronological_alerts': sorted(alerts, key=lambda x: x.get('timestamp', 0)),
            'critical_alerts': [a for a in alerts if a.get('severity') == 'critical'],
            'high_severity_alerts': [a for a in alerts if a.get('severity') == 'high'],
            'medium_severity_alerts': [a for a in alerts if a.get('severity') == 'medium'],
            'low_severity_alerts': [a for a in alerts if a.get('severity') == 'low']
        }
        
        filename = f'alerts_{timestamp.strftime("%Y%m%d_%H%M%S")}.json'
        return self.generate_json_report(alert_report, filename)
    
    def _group_alerts_by_severity(self, alerts: List[Dict]) -> Dict:
        grouped = {}
        for alert in alerts:
            severity = alert.get('severity', 'unknown')
            if severity not in grouped:
                grouped[severity] = []
            grouped[severity].append(alert)
        return grouped
    
    def _group_alerts_by_type(self, alerts: List[Dict]) -> Dict:
        grouped = {}
        for alert in alerts:
            alert_type = alert.get('type', 'unknown')
            if alert_type not in grouped:
                grouped[alert_type] = []
            grouped[alert_type].append(alert)
        return grouped
    
    def generate_metrics_report(self, stats_data: Dict, timestamp: datetime) -> Path:
        metrics_report = {
            'report_metadata': {
                'generated_at': timestamp.isoformat(),
                'report_type': 'performance_metrics'
            },
            'packet_metrics': {
                'packet_rate': stats_data.get('packet_rate', 0),
                'total_packets_processed': stats_data.get('total_packets_processed', 0),
                'time_span_seconds': stats_data.get('time_span_seconds', 0)
            },
            'latency_metrics': stats_data.get('latency_statistics', {}),
            'checksum_metrics': {
                'error_rate': stats_data.get('checksum_error_rate', 0)
            },
            'uav_distribution': stats_data.get('uav_distribution', {}),
            'anomaly_distribution': stats_data.get('anomaly_distribution', {}),
            'network_statistics': {
                'unique_uavs': stats_data.get('unique_uavs', 0),
                'unique_anomaly_types': stats_data.get('unique_anomaly_types', 0)
            }
        }
        
        filename = f'metrics_{timestamp.strftime("%Y%m%d_%H%M%S")}.json'
        return self.generate_json_report(metrics_report, filename)

