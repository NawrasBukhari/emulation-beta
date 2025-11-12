import time
from collections import defaultdict, deque
from typing import Dict, List


class StatisticsAggregator:
    def __init__(self, window_size=100):
        self.window_size = window_size
        self.packet_timestamps = deque(maxlen=window_size)
        self.latency_samples = deque(maxlen=window_size)
        self.checksum_errors = deque(maxlen=window_size)
        self.uav_packet_counts = defaultdict(int)
        self.anomaly_counts = defaultdict(int)
        self.alert_counts = defaultdict(int)
        self.severity_counts = defaultdict(int)
        self.cycle_metrics = []
        self.start_time = time.time()
    
    def record_packet(self, packet, cycle_number: int):
        current_time = time.time()
        self.packet_timestamps.append(current_time)
        
        if packet:
            self.uav_packet_counts[packet.get('uav_id', 'unknown')] += 1
            if packet.get('anomaly'):
                self.anomaly_counts[packet['anomaly']] += 1
        
        if len(self.packet_timestamps) >= 2:
            latency = self.packet_timestamps[-1] - self.packet_timestamps[-2]
            self.latency_samples.append(latency)
    
    def record_checksum_error(self, has_error: bool):
        self.checksum_errors.append(1 if has_error else 0)
    
    def record_alert(self, alert: Dict):
        alert_type = alert.get('type', 'unknown')
        severity = alert.get('severity', 'unknown')
        self.alert_counts[alert_type] += 1
        self.severity_counts[severity] += 1
    
    def record_cycle_metrics(self, cycle_number: int, metrics: Dict):
        self.cycle_metrics.append({
            'cycle': cycle_number,
            'timestamp': time.time(),
            'metrics': metrics
        })
    
    def calculate_packet_rate(self) -> float:
        if len(self.packet_timestamps) < 2:
            return 0.0
        time_span = self.packet_timestamps[-1] - self.packet_timestamps[0]
        if time_span == 0:
            return 0.0
        return (len(self.packet_timestamps) - 1) / time_span
    
    def calculate_latency_stats(self) -> Dict:
        if not self.latency_samples:
            return {
                'mean': 0.0,
                'median': 0.0,
                'min': 0.0,
                'max': 0.0,
                'std_dev': 0.0,
                'variance': 0.0
            }
        
        sorted_latencies = sorted(self.latency_samples)
        n = len(sorted_latencies)
        mean = sum(sorted_latencies) / n
        
        if n % 2 == 0:
            median = (sorted_latencies[n//2 - 1] + sorted_latencies[n//2]) / 2
        else:
            median = sorted_latencies[n//2]
        
        variance = sum((x - mean) ** 2 for x in sorted_latencies) / n
        std_dev = variance ** 0.5
        
        return {
            'mean': mean,
            'median': median,
            'min': min(sorted_latencies),
            'max': max(sorted_latencies),
            'std_dev': std_dev,
            'variance': variance
        }
    
    def calculate_checksum_error_rate(self) -> float:
        if not self.checksum_errors:
            return 0.0
        return sum(self.checksum_errors) / len(self.checksum_errors)
    
    def get_uav_distribution(self) -> Dict:
        total = sum(self.uav_packet_counts.values())
        if total == 0:
            return {}
        
        distribution = {}
        for uav_id, count in self.uav_packet_counts.items():
            distribution[uav_id] = {
                'count': count,
                'percentage': (count / total) * 100
            }
        return distribution
    
    def get_anomaly_distribution(self) -> Dict:
        total = sum(self.anomaly_counts.values())
        if total == 0:
            return {}
        
        distribution = {}
        for anomaly_type, count in self.anomaly_counts.items():
            distribution[anomaly_type] = {
                'count': count,
                'percentage': (count / total) * 100
            }
        return distribution
    
    def get_alert_statistics(self) -> Dict:
        return {
            'total_alerts': sum(self.alert_counts.values()),
            'alerts_by_type': dict(self.alert_counts),
            'alerts_by_severity': dict(self.severity_counts),
            'unique_alert_types': len(self.alert_counts)
        }
    
    def get_time_series_data(self) -> List[Dict]:
        return list(self.cycle_metrics)
    
    def get_comprehensive_stats(self) -> Dict:
        latency_stats = self.calculate_latency_stats()
        
        return {
            'packet_rate': self.calculate_packet_rate(),
            'latency_statistics': latency_stats,
            'checksum_error_rate': self.calculate_checksum_error_rate(),
            'uav_distribution': self.get_uav_distribution(),
            'anomaly_distribution': self.get_anomaly_distribution(),
            'alert_statistics': self.get_alert_statistics(),
            'total_packets_processed': len(self.packet_timestamps),
            'time_span_seconds': self.packet_timestamps[-1] - self.packet_timestamps[0] if len(self.packet_timestamps) >= 2 else 0,
            'unique_uavs': len(self.uav_packet_counts),
            'unique_anomaly_types': len(self.anomaly_counts)
        }
    
    def reset(self):
        self.packet_timestamps.clear()
        self.latency_samples.clear()
        self.checksum_errors.clear()
        self.uav_packet_counts.clear()
        self.anomaly_counts.clear()
        self.alert_counts.clear()
        self.severity_counts.clear()
        self.cycle_metrics.clear()
        self.start_time = time.time()

