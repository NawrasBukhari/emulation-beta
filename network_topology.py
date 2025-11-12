import random
from typing import Dict, List, Set, Optional


class NetworkTopology:
    def __init__(self, seed=42):
        random.seed(seed)
        self.uavs = {}
        self.connections = {}
        self.regions = {}
        self.initialized = False
    
    def initialize_network(self, num_uavs=10, connection_probability=0.3):
        uav_ids = [f"UAV_{i:03d}" for i in range(1, num_uavs + 1)]
        
        for uav_id in uav_ids:
            self.uavs[uav_id] = {
                'id': uav_id,
                'status': 'active',
                'region': self._assign_region(uav_id),
                'connection_strength': random.uniform(0.5, 1.0),
                'last_seen': None
            }
            self.connections[uav_id] = set()
        
        for uav_id in uav_ids:
            for other_id in uav_ids:
                if uav_id != other_id and random.random() < connection_probability:
                    self.connections[uav_id].add(other_id)
                    self.connections[other_id].add(uav_id)
        
        self.initialized = True
    
    def _assign_region(self, uav_id: str) -> str:
        region_map = {
            'UAV_001': 'north',
            'UAV_002': 'north',
            'UAV_003': 'east',
            'UAV_004': 'east',
            'UAV_005': 'south',
            'UAV_006': 'south',
            'UAV_007': 'west',
            'UAV_008': 'west',
            'UAV_009': 'center',
            'UAV_010': 'center'
        }
        return region_map.get(uav_id, 'unknown')
    
    def get_uav_info(self, uav_id: str) -> Optional[Dict]:
        return self.uavs.get(uav_id)
    
    def update_uav_status(self, uav_id: str, status: str = 'active', last_seen: Optional[float] = None):
        if uav_id in self.uavs:
            self.uavs[uav_id]['status'] = status
            if last_seen:
                self.uavs[uav_id]['last_seen'] = last_seen
    
    def get_connected_uavs(self, uav_id: str) -> Set[str]:
        return self.connections.get(uav_id, set())
    
    def is_valid_uav(self, uav_id: str) -> bool:
        return uav_id in self.uavs
    
    def get_region_uavs(self, region: str) -> List[str]:
        return [uav_id for uav_id, info in self.uavs.items() if info['region'] == region]
    
    def get_network_statistics(self) -> Dict:
        active_count = sum(1 for info in self.uavs.values() if info['status'] == 'active')
        total_connections = sum(len(conns) for conns in self.connections.values()) // 2
        
        region_counts = {}
        for info in self.uavs.values():
            region = info['region']
            region_counts[region] = region_counts.get(region, 0) + 1
        
        return {
            'total_uavs': len(self.uavs),
            'active_uavs': active_count,
            'inactive_uavs': len(self.uavs) - active_count,
            'total_connections': total_connections,
            'average_connections_per_uav': total_connections / len(self.uavs) if self.uavs else 0,
            'region_distribution': region_counts,
            'network_density': total_connections / (len(self.uavs) * (len(self.uavs) - 1) / 2) if len(self.uavs) > 1 else 0
        }
    
    def find_path(self, source: str, destination: str) -> Optional[List[str]]:
        if source not in self.uavs or destination not in self.uavs:
            return None
        
        if source == destination:
            return [source]
        
        visited = set()
        queue = [(source, [source])]
        
        while queue:
            current, path = queue.pop(0)
            if current == destination:
                return path
            
            visited.add(current)
            for neighbor in self.connections.get(current, set()):
                if neighbor not in visited:
                    queue.append((neighbor, path + [neighbor]))
        
        return None
    
    def get_isolated_uavs(self) -> List[str]:
        isolated = []
        for uav_id, connections in self.connections.items():
            if len(connections) == 0:
                isolated.append(uav_id)
        return isolated
    
    def get_highly_connected_uavs(self, min_connections: int = 5) -> List[str]:
        highly_connected = []
        for uav_id, connections in self.connections.items():
            if len(connections) >= min_connections:
                highly_connected.append(uav_id)
        return highly_connected
    
    def simulate_connection_failure(self, uav_id: str, probability: float = 0.1):
        if uav_id not in self.connections:
            return
        
        connections_to_remove = []
        for connected_id in self.connections[uav_id]:
            if random.random() < probability:
                connections_to_remove.append(connected_id)
        
        for connected_id in connections_to_remove:
            self.connections[uav_id].discard(connected_id)
            self.connections[connected_id].discard(uav_id)
    
    def reset_network(self):
        self.uavs.clear()
        self.connections.clear()
        self.regions.clear()
        self.initialized = False

