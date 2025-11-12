import asyncio
import base64
import json
import logging
import random
import time
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ChannelEmulator:
    def __init__(self, seed=42, anomaly_rate=0.1):
        random.seed(seed)
        self.anomaly_rate = anomaly_rate
        self.packet_counter = 0
        self.uav_ids = [f"UAV_{i:03d}" for i in range(1, 11)]
        self.anomaly_types = ['packet_loss', 'malformed_payload', 'spoofed_id']
        
    async def generate_packet(self):
        await asyncio.sleep(random.uniform(0.01, 0.05))
        self.packet_counter += 1
        
        if random.random() < self.anomaly_rate:
            anomaly_type = random.choice(self.anomaly_types)
            return self._create_anomalous_packet(anomaly_type)
        else:
            return self._create_normal_packet()
    
    def _create_normal_packet(self):
        uav_id = random.choice(self.uav_ids)
        timestamp = time.time()
        telemetry_data = {
            'uav_id': uav_id,
            'timestamp': timestamp,
            'altitude': random.uniform(100, 5000),
            'speed': random.uniform(10, 100),
            'heading': random.uniform(0, 360),
            'battery': random.uniform(20, 100),
            'status': 'operational'
        }
        payload = json.dumps(telemetry_data).encode('utf-8')
        encoded = base64.b64encode(payload).decode('utf-8')
        checksum = self._calculate_checksum(payload)
        
        return {
            'packet_id': self.packet_counter,
            'uav_id': uav_id,
            'timestamp': timestamp,
            'payload': encoded,
            'checksum': checksum,
            'anomaly': None
        }
    
    def _create_anomalous_packet(self, anomaly_type):
        if anomaly_type == 'packet_loss':
            return None
        
        uav_id = random.choice(self.uav_ids)
        timestamp = time.time()
        
        if anomaly_type == 'malformed_payload':
            telemetry_data = {
                'uav_id': uav_id,
                'timestamp': timestamp,
                'altitude': random.uniform(100, 5000),
                'speed': random.uniform(10, 100),
                'heading': random.uniform(0, 360),
                'battery': random.uniform(20, 100),
                'status': 'operational'
            }
            payload = json.dumps(telemetry_data).encode('utf-8')
            encoded = base64.b64encode(payload).decode('utf-8')
            checksum = random.randint(1000, 9999)
            
            return {
                'packet_id': self.packet_counter,
                'uav_id': uav_id,
                'timestamp': timestamp,
                'payload': encoded,
                'checksum': checksum,
                'anomaly': 'malformed_payload'
            }
        
        elif anomaly_type == 'spoofed_id':
            fake_id = f"UAV_{random.randint(100, 999):03d}"
            telemetry_data = {
                'uav_id': fake_id,
                'timestamp': timestamp,
                'altitude': random.uniform(100, 5000),
                'speed': random.uniform(10, 100),
                'heading': random.uniform(0, 360),
                'battery': random.uniform(20, 100),
                'status': 'operational'
            }
            payload = json.dumps(telemetry_data).encode('utf-8')
            encoded = base64.b64encode(payload).decode('utf-8')
            checksum = self._calculate_checksum(payload)
            
            return {
                'packet_id': self.packet_counter,
                'uav_id': fake_id,
                'timestamp': timestamp,
                'payload': encoded,
                'checksum': checksum,
                'anomaly': 'spoofed_id'
            }
    
    def _calculate_checksum(self, data):
        return sum(data) % 10000


class AnomalyDetector:
    def __init__(self, latency_threshold=0.1, checksum_threshold=0.05, repeat_id_threshold=0.3):
        self.latency_threshold = latency_threshold
        self.checksum_threshold = checksum_threshold
        self.repeat_id_threshold = repeat_id_threshold
        
        self.packet_history = deque(maxlen=100)
        self.latencies = deque(maxlen=50)
        self.checksum_mismatches = 0
        self.total_packets = 0
        self.id_frequencies = defaultdict(int)
        self.alerts = []
        
    async def analyze_packet(self, packet):
        if packet is None:
            self.alerts.append({
                'type': 'packet_loss',
                'timestamp': time.time(),
                'severity': 'high'
            })
            return
        
        self.total_packets += 1
        current_time = time.time()
        
        if self.packet_history:
            last_packet = self.packet_history[-1]
            latency = current_time - last_packet['timestamp']
            self.latencies.append(latency)
        
        self.packet_history.append({
            'packet_id': packet['packet_id'],
            'uav_id': packet['uav_id'],
            'timestamp': packet['timestamp'],
            'checksum': packet['checksum']
        })
        
        self.id_frequencies[packet['uav_id']] += 1
        
        payload_bytes = base64.b64decode(packet['payload'])
        expected_checksum = sum(payload_bytes) % 10000
        
        if packet['checksum'] != expected_checksum:
            self.checksum_mismatches += 1
        
        if packet.get('anomaly') == 'spoofed_id':
            if packet['uav_id'] not in [f"UAV_{i:03d}" for i in range(1, 11)]:
                self.alerts.append({
                    'type': 'spoofed_id',
                    'timestamp': current_time,
                    'uav_id': packet['uav_id'],
                    'severity': 'critical'
                })
        
        if packet.get('anomaly') == 'malformed_payload':
            self.alerts.append({
                'type': 'malformed_payload',
                'timestamp': current_time,
                'packet_id': packet['packet_id'],
                'severity': 'medium'
            })
        
        self._check_statistical_thresholds(current_time)
    
    def _check_statistical_thresholds(self, current_time):
        if len(self.latencies) >= 10:
            latency_variance = self._calculate_variance(list(self.latencies))
            if latency_variance > self.latency_threshold:
                self.alerts.append({
                    'type': 'high_latency_variance',
                    'timestamp': current_time,
                    'variance': latency_variance,
                    'severity': 'medium'
                })
        
        if self.total_packets > 0:
            checksum_mismatch_rate = self.checksum_mismatches / self.total_packets
            if checksum_mismatch_rate > self.checksum_threshold:
                self.alerts.append({
                    'type': 'high_checksum_mismatch_rate',
                    'timestamp': current_time,
                    'rate': checksum_mismatch_rate,
                    'severity': 'high'
                })
        
        if self.total_packets > 0:
            for uav_id, count in self.id_frequencies.items():
                frequency = count / self.total_packets
                if frequency > self.repeat_id_threshold:
                    self.alerts.append({
                        'type': 'repeated_id_frequency',
                        'timestamp': current_time,
                        'uav_id': uav_id,
                        'frequency': frequency,
                        'severity': 'medium'
                    })
    
    def _calculate_variance(self, values):
        if len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return variance
    
    def get_summary(self):
        return {
            'total_packets': self.total_packets,
            'checksum_mismatches': self.checksum_mismatches,
            'checksum_mismatch_rate': self.checksum_mismatches / self.total_packets if self.total_packets > 0 else 0,
            'average_latency': sum(self.latencies) / len(self.latencies) if self.latencies else 0,
            'latency_variance': self._calculate_variance(list(self.latencies)) if self.latencies else 0,
            'unique_uav_ids': len(self.id_frequencies),
            'total_alerts': len(self.alerts),
            'alerts_by_type': self._count_alerts_by_type(),
            'alerts_by_severity': self._count_alerts_by_severity()
        }
    
    def _count_alerts_by_type(self):
        counts = defaultdict(int)
        for alert in self.alerts:
            counts[alert['type']] += 1
        return dict(counts)
    
    def _count_alerts_by_severity(self):
        counts = defaultdict(int)
        for alert in self.alerts:
            counts[alert['severity']] += 1
        return dict(counts)
    
    def get_all_alerts(self):
        return self.alerts


class SimulationRunner:
    def __init__(self, cycles=100, seed=42, anomaly_rate=0.1):
        self.cycles = cycles
        self.channel = ChannelEmulator(seed=seed, anomaly_rate=anomaly_rate)
        self.detector = AnomalyDetector()
        self.log_dir = Path('logs')
        self.log_dir.mkdir(exist_ok=True)
        self.start_time = datetime.now()
        self.log_file = None
        
    async def run(self):
        timestamp_str = self.start_time.strftime('%Y%m%d_%H%M%S')
        log_filename = self.log_dir / f'anomalies_{timestamp_str}.log'
        self.log_file = open(log_filename, 'w')
        
        logger.info(f"Starting simulation with {self.cycles} cycles")
        
        for cycle in range(1, self.cycles + 1):
            packet = await self.channel.generate_packet()
            await self.detector.analyze_packet(packet)
            
            if packet and packet.get('anomaly'):
                log_entry = f"[Cycle {cycle}] Anomaly detected: {packet['anomaly']} - UAV: {packet['uav_id']} - Packet ID: {packet['packet_id']}\n"
                self.log_file.write(log_entry)
                logger.warning(f"Cycle {cycle}: Anomaly - {packet['anomaly']}")
            
            alerts = self.detector.get_all_alerts()
            new_alerts = [a for a in alerts if a['timestamp'] >= (time.time() - 0.1)]
            for alert in new_alerts:
                alert_entry = f"[Cycle {cycle}] Alert: {alert['type']} - Severity: {alert['severity']} - {json.dumps(alert)}\n"
                self.log_file.write(alert_entry)
        
        self.log_file.close()
        
        summary = self.detector.get_summary()
        summary['simulation_cycles'] = self.cycles
        summary['start_time'] = self.start_time.isoformat()
        summary['end_time'] = datetime.now().isoformat()
        summary['duration_seconds'] = (datetime.now() - self.start_time).total_seconds()
        summary['all_alerts'] = self.detector.get_all_alerts()
        
        report_filename = self.log_dir / f'analysis_run_{self.start_time.strftime("%Y%m%d")}.json'
        with open(report_filename, 'w') as f:
            json.dump(summary, f, indent=2)
        
        logger.info(f"Simulation completed. Summary saved to {report_filename}")
        logger.info(f"Total packets: {summary['total_packets']}, Total alerts: {summary['total_alerts']}")
        
        return summary


async def main():
    runner = SimulationRunner(cycles=100, seed=42, anomaly_rate=0.1)
    await runner.run()


if __name__ == '__main__':
    asyncio.run(main())

