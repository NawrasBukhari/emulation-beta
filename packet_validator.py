import base64
import json
import time
from typing import Dict, Optional, Tuple


class PacketValidator:
    def __init__(self, valid_uav_ids=None):
        if valid_uav_ids is None:
            self.valid_uav_ids = {f"UAV_{i:03d}" for i in range(1, 11)}
        else:
            self.valid_uav_ids = set(valid_uav_ids)
        
        self.validation_errors = []
        self.validated_count = 0
        self.invalid_count = 0
    
    def validate_structure(self, packet: Optional[Dict]) -> Tuple[bool, str]:
        if packet is None:
            return False, "packet_is_none"
        
        required_fields = ['packet_id', 'uav_id', 'timestamp', 'payload', 'checksum']
        for field in required_fields:
            if field not in packet:
                return False, f"missing_field_{field}"
        
        return True, "valid"
    
    def validate_checksum(self, packet: Dict) -> Tuple[bool, int, int]:
        try:
            payload_bytes = base64.b64decode(packet['payload'])
            expected_checksum = sum(payload_bytes) % 10000
            actual_checksum = packet['checksum']
            return actual_checksum == expected_checksum, expected_checksum, actual_checksum
        except Exception:
            return False, 0, packet.get('checksum', 0)
    
    def validate_uav_id(self, packet: Dict) -> bool:
        uav_id = packet.get('uav_id', '')
        return uav_id in self.valid_uav_ids
    
    def validate_payload_format(self, packet: Dict) -> Tuple[bool, Optional[Dict]]:
        try:
            payload_bytes = base64.b64decode(packet['payload'])
            decoded = payload_bytes.decode('utf-8')
            telemetry = json.loads(decoded)
            
            required_telemetry_fields = ['uav_id', 'timestamp', 'altitude', 'speed', 'heading', 'battery', 'status']
            for field in required_telemetry_fields:
                if field not in telemetry:
                    return False, None
            
            if not isinstance(telemetry['altitude'], (int, float)):
                return False, None
            if not isinstance(telemetry['speed'], (int, float)):
                return False, None
            if not isinstance(telemetry['heading'], (int, float)):
                return False, None
            if not isinstance(telemetry['battery'], (int, float)):
                return False, None
            
            return True, telemetry
        except Exception:
            return False, None
    
    def validate_timestamp(self, packet: Dict, max_age_seconds: float = 60.0) -> bool:
        packet_timestamp = packet.get('timestamp', 0)
        current_time = time.time()
        age = current_time - packet_timestamp
        return 0 <= age <= max_age_seconds
    
    def full_validation(self, packet: Optional[Dict]) -> Dict:
        result = {
            'is_valid': False,
            'errors': [],
            'warnings': [],
            'validation_details': {}
        }
        
        structure_valid, structure_error = self.validate_structure(packet)
        if not structure_valid:
            result['errors'].append(structure_error)
            self.invalid_count += 1
            return result
        
        self.validated_count += 1
        
        checksum_valid, expected, actual = self.validate_checksum(packet)
        result['validation_details']['checksum'] = {
            'valid': checksum_valid,
            'expected': expected,
            'actual': actual
        }
        if not checksum_valid:
            result['errors'].append('checksum_mismatch')
        
        uav_id_valid = self.validate_uav_id(packet)
        result['validation_details']['uav_id'] = {
            'valid': uav_id_valid,
            'id': packet.get('uav_id', 'unknown')
        }
        if not uav_id_valid:
            result['errors'].append('invalid_uav_id')
        
        payload_valid, telemetry = self.validate_payload_format(packet)
        result['validation_details']['payload'] = {
            'valid': payload_valid,
            'telemetry_available': telemetry is not None
        }
        if not payload_valid:
            result['errors'].append('invalid_payload_format')
        
        timestamp_valid = self.validate_timestamp(packet)
        result['validation_details']['timestamp'] = {
            'valid': timestamp_valid,
            'age_seconds': time.time() - packet.get('timestamp', 0)
        }
        if not timestamp_valid:
            result['warnings'].append('timestamp_out_of_range')
        
        if not result['errors']:
            result['is_valid'] = True
        
        if result['errors']:
            self.invalid_count += 1
            self.validation_errors.append({
                'packet_id': packet.get('packet_id'),
                'errors': result['errors'],
                'timestamp': time.time()
            })
        
        return result
    
    def get_validation_stats(self) -> Dict:
        total = self.validated_count + self.invalid_count
        return {
            'total_validated': self.validated_count,
            'total_invalid': self.invalid_count,
            'validation_rate': self.validated_count / total if total > 0 else 0,
            'error_count': len(self.validation_errors),
            'recent_errors': self.validation_errors[-10:] if self.validation_errors else []
        }
    
    def reset_stats(self):
        self.validation_errors.clear()
        self.validated_count = 0
        self.invalid_count = 0

