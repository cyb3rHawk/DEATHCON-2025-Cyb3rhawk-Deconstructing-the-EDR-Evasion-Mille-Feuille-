"""
Threat Hunting Toolkit - Core Analysis Engine

Provides comprehensive Windows event log analysis capabilities including:
- Multi-provider event processing
- Process and thread correlation
- Registry and file operation tracking
- Timeline construction
- Field discovery and search
- Event correlation across providers
"""

import json
from collections import defaultdict, Counter
from typing import Dict, List, Set, Any, Optional
from datetime import datetime


class ThreatHunter:
    """
    Core threat hunting and forensic analysis toolkit for Windows event logs.
    
    Supports JSONL and JSON array formats with automatic detection.
    Provides search, correlation, timeline, and export capabilities.
    """
    
    def __init__(self, filepath: str, auto_analyze: bool = True):
        """
        Initialize the threat hunter with event log data.
        
        Args:
            filepath: Path to JSONL or JSON file containing event logs
            auto_analyze: Automatically run overview analysis on load
        """
        print("="*80)
        print("THREAT HUNTING TOOLKIT")
        print("="*80)
        
        self.filepath = filepath
        self.data = []
        self._provider_hierarchy = None
        self._event_counts = None
        
        self._load_data()
        
        if auto_analyze:
            self.overview()
    
    def discover_fields(self, rebuild: bool = False) -> Dict[str, Any]:
        """
        Discover all available fields in the dataset with coverage statistics.
        Results are cached for performance on subsequent calls.
        
        Args:
            rebuild: Force rebuild the field cache
        
        Returns:
            Dictionary containing field information with counts and samples
        """
        if hasattr(self, '_field_cache') and not rebuild:
            return self._field_cache
        
        print("[*] Discovering all fields in dataset...")
        
        header_fields = defaultdict(lambda: {'count': 0, 'samples': set()})
        property_fields = defaultdict(lambda: {'count': 0, 'samples': set()})
        
        for i, record in enumerate(self.data):
            fields = self._extract_fields(record)
            for key, value in fields.items():
                if value is not None:
                    header_fields[key]['count'] += 1
                    if len(header_fields[key]['samples']) < 5:
                        header_fields[key]['samples'].add(str(value)[:100])
            
            props = record.get('properties', {})
            for key, value in props.items():
                if value is not None:
                    property_fields[key]['count'] += 1
                    if len(property_fields[key]['samples']) < 5:
                        property_fields[key]['samples'].add(str(value)[:100])
            
            if (i + 1) % 50000 == 0:
                print(f"  Scanned {i+1:,} events...")
        
        self._field_cache = {
            'header_fields': dict(header_fields),
            'property_fields': dict(property_fields),
            'total_fields': len(header_fields) + len(property_fields),
            'total_events': len(self.data)
        }
        
        print(f"[+] Discovered {len(header_fields)} header fields and {len(property_fields)} property fields")
        
        return self._field_cache

    def list_fields(self, location: str = 'all', show_samples: bool = False, limit: int = None) -> List[Dict]:
        """
        List all available fields with coverage information.
        
        Args:
            location: Filter by 'all', 'header', or 'properties'
            show_samples: Display sample values for each field
            limit: Maximum number of fields to display per category
        
        Returns:
            List of field information dictionaries
        """
        if not hasattr(self, '_field_cache'):
            self.discover_fields()
        
        cache = self._field_cache
        total_events = cache['total_events']
        
        print("\n" + "="*80)
        print(f"AVAILABLE FIELDS")
        print("="*80)
        
        results = []
        
        if location in ['all', 'header']:
            print(f"\n📋 HEADER FIELDS ({len(cache['header_fields'])} fields):")
            print("-" * 80)
            
            header_sorted = sorted(cache['header_fields'].items(), 
                                key=lambda x: x[1]['count'], 
                                reverse=True)
            
            for field, data in header_sorted[:limit]:
                coverage = (data['count'] / total_events * 100)
                results.append({
                    'location': 'header',
                    'field': field,
                    'count': data['count'],
                    'coverage': coverage
                })
                
                if show_samples:
                    samples = ' | '.join(list(data['samples'])[:2])
                    print(f"  {field:<30} {data['count']:>10,} ({coverage:>5.1f}%)  {samples[:40]}")
                else:
                    print(f"  {field:<30} {data['count']:>10,} ({coverage:>5.1f}%)")
        
        if location in ['all', 'properties']:
            print(f"\n📋 PROPERTY FIELDS ({len(cache['property_fields'])} fields):")
            print("-" * 80)
            
            property_sorted = sorted(cache['property_fields'].items(), 
                                    key=lambda x: x[1]['count'], 
                                    reverse=True)
            
            display_limit = limit if limit else len(property_sorted)
            
            for field, data in property_sorted[:display_limit]:
                coverage = (data['count'] / total_events * 100)
                results.append({
                    'location': 'properties',
                    'field': field,
                    'count': data['count'],
                    'coverage': coverage
                })
                
                if show_samples:
                    samples = ' | '.join(list(data['samples'])[:2])
                    print(f"  {field:<40} {data['count']:>10,} ({coverage:>5.1f}%)  {samples[:30]}")
                else:
                    print(f"  {field:<40} {data['count']:>10,} ({coverage:>5.1f}%)")
            
            if len(property_sorted) > display_limit:
                print(f"\n... and {len(property_sorted) - display_limit} more fields")
                print(f"Tip: Use list_fields(limit=None) to see all fields")
        
        print(f"\n📊 Total: {cache['total_fields']} unique fields")
        
        return results

    def lookup_field(self, field_name: str) -> Optional[Dict]:
        """
        Get detailed information about a specific field including samples and usage.
        
        Args:
            field_name: Name of the field to lookup
        
        Returns:
            Dictionary with field information or None if not found
        """
        if not hasattr(self, '_field_cache'):
            self.discover_fields()
        
        cache = self._field_cache
        
        print("\n" + "="*80)
        print(f"FIELD LOOKUP: {field_name}")
        print("="*80)
        
        if field_name in cache['header_fields']:
            data = cache['header_fields'][field_name]
            coverage = (data['count'] / cache['total_events'] * 100)
            
            print(f"\n📍 Location: header (metadata)")
            print(f"Occurrences: {data['count']:,} events ({coverage:.2f}% coverage)")
            print(f"\nSample values:")
            for i, val in enumerate(list(data['samples'])[:5], 1):
                print(f"  {i}. {val}")
            
            print(f"\n💡 How to search:")
            print(f"  hunter.search({field_name}=<value>)")
            print(f"  hunter.unique_values('{field_name}', location='header')")
            
            return {
                'location': 'header',
                'field': field_name,
                'count': data['count'],
                'coverage': coverage,
                'samples': list(data['samples'])
            }
        
        elif field_name in cache['property_fields']:
            data = cache['property_fields'][field_name]
            coverage = (data['count'] / cache['total_events'] * 100)
            
            print(f"\n📍 Location: properties (event-specific data)")
            print(f"Occurrences: {data['count']:,} events ({coverage:.2f}% coverage)")
            print(f"\nSample values:")
            for i, val in enumerate(list(data['samples'])[:5], 1):
                print(f"  {i}. {val}")
            
            print(f"\n💡 How to search:")
            print(f"  hunter.search('{field_name}')  # Universal search")
            print(f"  hunter.unique_values('{field_name}', location='properties')")
            
            providers_with_field = set()
            for record in self.data[:1000]:
                fields_extracted = self._extract_fields(record)
                props = record.get('properties', {})
                if field_name in props:
                    provider = fields_extracted.get('provider_name')
                    if provider:
                        providers_with_field.add(provider)
            
            if providers_with_field:
                print(f"\n🔍 Found in providers: {', '.join(sorted(providers_with_field)[:5])}")
            
            return {
                'location': 'properties',
                'field': field_name,
                'count': data['count'],
                'coverage': coverage,
                'samples': list(data['samples']),
                'providers': list(providers_with_field)
            }
        
        else:
            print(f"\n❌ Field '{field_name}' not found in dataset")
            
            all_fields = list(cache['header_fields'].keys()) + list(cache['property_fields'].keys())
            similar = [f for f in all_fields if field_name.lower() in f.lower()]
            
            if similar:
                print(f"\n💡 Did you mean one of these?")
                for field in similar[:10]:
                    print(f"  • {field}")
            
            return None

    def show_field_samples(self, field_name: str, limit: int = 20) -> List[str]:
        """
        Display all unique values for a specific field.
        
        Args:
            field_name: Name of the field to examine
            limit: Maximum number of unique values to display
        
        Returns:
            List of unique values (sorted)
        """
        print(f"\n[*] Getting unique values for '{field_name}'...")
        
        values = set()
        location = None
        
        for record in self.data:
            fields = self._extract_fields(record)
            
            if field_name in fields and fields[field_name] is not None:
                values.add(str(fields[field_name]))
                location = 'header'
            
            props = record.get('properties', {})
            if field_name in props and props[field_name] is not None:
                values.add(str(props[field_name])[:200])
                location = 'properties'
        
        if not values:
            print(f"[!] No values found for field '{field_name}'")
            print(f"[!] Use lookup_field('{field_name}') to check if field exists")
            return []
        
        print(f"\n[+] Found {len(values)} unique values for '{field_name}' ({location})")
        
        if len(values) <= limit:
            print(f"\nAll {len(values)} unique values:")
            for i, val in enumerate(sorted(values), 1):
                print(f"  {i:3d}. {val}")
        else:
            print(f"\nShowing first {limit} of {len(values)} unique values:")
            for i, val in enumerate(sorted(values)[:limit], 1):
                print(f"  {i:3d}. {val}")
            print(f"\n... and {len(values) - limit} more values")
            print(f"Tip: Use show_field_samples('{field_name}', limit={len(values)}) to see all")
        
        return sorted(values)

    def export_field_reference(self, filename: str = 'field_reference.csv'):
        """
        Export complete field reference documentation to CSV.
        
        Args:
            filename: Output CSV filename
        """
        if not hasattr(self, '_field_cache'):
            self.discover_fields()
        
        cache = self._field_cache
        total_events = cache['total_events']
        
        import csv
        
        rows = []
        
        for field, data in cache['header_fields'].items():
            rows.append({
                'Location': 'header',
                'Field_Name': field,
                'Occurrences': data['count'],
                'Coverage_%': round(data['count'] / total_events * 100, 2),
                'Sample_1': list(data['samples'])[0] if data['samples'] else '',
                'Sample_2': list(data['samples'])[1] if len(data['samples']) > 1 else '',
                'Sample_3': list(data['samples'])[2] if len(data['samples']) > 2 else '',
                'Search_Example': f"hunter.search({field}=<value>)"
            })
        
        for field, data in cache['property_fields'].items():
            rows.append({
                'Location': 'properties',
                'Field_Name': field,
                'Occurrences': data['count'],
                'Coverage_%': round(data['count'] / total_events * 100, 2),
                'Sample_1': list(data['samples'])[0] if data['samples'] else '',
                'Sample_2': list(data['samples'])[1] if len(data['samples']) > 1 else '',
                'Sample_3': list(data['samples'])[2] if len(data['samples']) > 2 else '',
                'Search_Example': f"hunter.search('{field}')"
            })
        
        rows.sort(key=lambda x: x['Occurrences'], reverse=True)
        
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            if rows:
                writer = csv.DictWriter(f, fieldnames=rows[0].keys())
                writer.writeheader()
                writer.writerows(rows)
        
        print(f"[+] Exported field reference to {filename}")
        print(f"    Total fields: {len(rows)}")
        print(f"    Header fields: {len(cache['header_fields'])}")
        print(f"    Property fields: {len(cache['property_fields'])}")

    def fields_by_category(self) -> Dict[str, List[str]]:
        """
        Categorize fields by type (Process, Registry, File, Network, etc.).
        
        Returns:
            Dictionary mapping category names to lists of fields
        """
        if not hasattr(self, '_field_cache'):
            self.discover_fields()
        
        cache = self._field_cache
        
        categories = {
            'Process': [],
            'Registry': [],
            'File': [],
            'Network': [],
            'User': [],
            'Metadata': [],
            'Other': []
        }
        
        for field in cache['property_fields'].keys():
            field_lower = field.lower()
            
            if any(x in field_lower for x in ['image', 'process', 'command', 'parent', 'exec']):
                categories['Process'].append(field)
            elif any(x in field_lower for x in ['key', 'registry', 'value', 'hive']):
                categories['Registry'].append(field)
            elif any(x in field_lower for x in ['file', 'path', 'directory', 'folder']):
                categories['File'].append(field)
            elif any(x in field_lower for x in ['ip', 'port', 'network', 'destination', 'source', 'protocol']):
                categories['Network'].append(field)
            elif any(x in field_lower for x in ['user', 'sid', 'logon', 'account']):
                categories['User'].append(field)
            else:
                categories['Other'].append(field)
        
        categories['Metadata'] = list(cache['header_fields'].keys())
        
        print("\n" + "="*80)
        print("FIELDS BY CATEGORY")
        print("="*80)
        
        for category, fields in categories.items():
            if fields:
                print(f"\n🔍 {category} ({len(fields)} fields):")
                for field in sorted(fields)[:15]:
                    count = cache['property_fields'].get(field, cache['header_fields'].get(field, {})).get('count', 0)
                    print(f"  • {field:<40} {count:>10,} events")
                
                if len(fields) > 15:
                    print(f"  ... and {len(fields) - 15} more")
        
        return categories

    def _load_data(self):
        """Load event data from JSONL or JSON array file."""
        print(f"[*] Loading: {self.filepath}")
        
        with open(self.filepath, 'r', encoding='utf-8') as f:
            first_char = f.read(1)
            f.seek(0)
            
            if first_char == '[':
                try:
                    self.data = json.load(f)
                    print(f"[+] Loaded JSON array: {len(self.data):,} records")
                    return
                except json.JSONDecodeError:
                    f.seek(0)
            
            print("[*] Loading as JSONL...")
            records = []
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError as e:
                    print(f"[!] Skipping line {line_num}: {e}")
            
            self.data = records
            print(f"[+] Loaded JSONL: {len(self.data):,} records")
    
    def _extract_fields(self, record: Dict) -> Dict:
        """Extract standard fields from event record regardless of structure."""
        if 'header' in record:
            h = record['header']
            return {
                'provider_name': h.get('provider_name'),
                'task_name': h.get('task_name'),
                'event_name': h.get('event_name'),
                'event_opcode': h.get('event_opcode'),
                'event_id': h.get('event_id'),
                'process_id': h.get('process_id'),
                'thread_id': h.get('thread_id'),
                'timestamp': h.get('timestamp')
            }
        return {
            'provider_name': record.get('provider_name'),
            'task_name': record.get('task_name'),
            'event_name': record.get('event_name'),
            'event_opcode': record.get('event_opcode'),
            'event_id': record.get('event_id'),
            'process_id': record.get('process_id'),
            'thread_id': record.get('thread_id'),
            'timestamp': record.get('timestamp')
        }
    
    def _build_hierarchy(self):
        """Build internal provider/task/event hierarchy for analysis."""
        if self._provider_hierarchy is not None:
            return
        
        print("[*] Building hierarchy...")
        self._provider_hierarchy = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
        self._event_counts = defaultdict(lambda: defaultdict(dict))
        
        for record in self.data:
            fields = self._extract_fields(record)
            provider = fields['provider_name'] or 'UNKNOWN'
            task = fields['task_name'] or 'NO_TASK'
            event_name = fields['event_name'] or 'NO_EVENT_NAME'
            event_opcode = fields['event_opcode']
            event_id = fields['event_id']
            
            self._provider_hierarchy[provider][task][event_name].add(event_opcode)
            
            event_key = f"ID:{event_id}|Name:{event_name}|Op:{event_opcode}"
            if event_key not in self._event_counts[provider][task]:
                self._event_counts[provider][task][event_key] = {
                    'count': 0,
                    'event_id': event_id,
                    'event_name': event_name,
                    'event_opcode': event_opcode
                }
            self._event_counts[provider][task][event_key]['count'] += 1
        
        print(f"[+] Hierarchy built: {len(self._provider_hierarchy)} providers")
    
    def overview(self) -> Dict[str, Any]:
        """
        Display comprehensive data overview including providers, events, and processes.
        
        Returns:
            Dictionary with overview statistics
        """
        self._build_hierarchy()
        
        print("\n" + "="*80)
        print("DATA OVERVIEW")
        print("="*80)
        
        total_events = len(self.data)
        providers = len(self._provider_hierarchy)
        total_tasks = sum(len(tasks) for tasks in self._provider_hierarchy.values())
        
        print(f"\nTotal Events:     {total_events:,}")
        print(f"Providers:        {providers}")
        print(f"Unique Tasks:     {total_tasks}")
        
        print("\n" + "-"*80)
        print("PROVIDERS (by event volume)")
        print("-"*80)
        
        provider_stats = []
        for provider, tasks in self._event_counts.items():
            total = sum(
                sum(e['count'] for e in events.values())
                for events in tasks.values()
            )
            provider_stats.append((provider, total, len(tasks)))
        
        for provider, count, task_count in sorted(provider_stats, key=lambda x: x[1], reverse=True):
            pct = (count / total_events * 100) if total_events > 0 else 0
            print(f"  {provider:<45} {count:>12,} ({pct:>5.1f}%) | {task_count} tasks")
        
        unique_pids = {
            fields['process_id']
            for record in self.data
            if (fields := self._extract_fields(record))['process_id']
        }
        
        print(f"\nUnique Process IDs: {len(unique_pids)}")
        print(f"Process IDs: {sorted(unique_pids)}")
        
        return {
            'total_events': total_events,
            'providers': providers,
            'unique_pids': unique_pids
        }
    
    def stats(self) -> Dict[str, Any]:
        """Alias for overview()."""
        return self.overview()
    
    def find_process(self, process_id: int, detailed: bool = True) -> Optional[Dict]:
        """
        Investigate all activity for a specific process ID.
        
        Args:
            process_id: Process ID to investigate
            detailed: Show detailed event preview
        
        Returns:
            Dictionary with process investigation results
        """
        events = [r for r in self.data 
                 if self._extract_fields(r)['process_id'] == process_id]
        
        if not events:
            print(f"[!] No events found for PID {process_id}")
            return None
        
        print(f"\n{'='*80}")
        print(f"PROCESS INVESTIGATION: PID {process_id}")
        print("="*80)
        print(f"Total Events: {len(events):,}")
        
        task_counts = Counter(
            self._extract_fields(e)['task_name'] or 'UNKNOWN'
            for e in events
        )
        
        print(f"\nEvent Types:")
        for task, count in task_counts.most_common():
            print(f"  {task:<30} {count:>8,}")
        
        timestamps = [
            self._extract_fields(e)['timestamp']
            for e in events
            if self._extract_fields(e)['timestamp']
        ]
        if timestamps:
            print(f"\nTime Span:")
            print(f"  First: {min(timestamps)}")
            print(f"  Last:  {max(timestamps)}")
        
        threads = {
            self._extract_fields(e)['thread_id']
            for e in events
            if self._extract_fields(e)['thread_id']
        }
        print(f"\nUnique Threads: {len(threads)}")
        if len(threads) <= 10:
            print(f"  Thread IDs: {sorted(threads)}")
        
        if detailed:
            print(f"\nFirst 5 Events:")
            for i, event in enumerate(events[:5], 1):
                fields = self._extract_fields(event)
                summary = self._summarize_event(event)
                print(f"  {i}. [{fields['timestamp']}] {summary}")
        
        return {
            'process_id': process_id,
            'event_count': len(events),
            'event_types': dict(task_counts),
            'threads': threads,
            'events': events
        }
    
    def find_process_by_name(self, process_name: str, partial: bool = True) -> List[Dict]:
        """
        Find events by process name (searches ImageFileName, CommandLine, etc.).
        
        Args:
            process_name: Process name to search for
            partial: Allow partial matching (substring)
        
        Returns:
            List of matching event records
        """
        matches = []
        search_fields = ['ImageFileName', 'CommandLine', 'ProcessName', 'ParentImageName', 'Image']
        
        for record in self.data:
            props = record.get('properties', {})
            for field in search_fields:
                value = props.get(field, '')
                if value and isinstance(value, str):
                    if partial:
                        if process_name.lower() in value.lower():
                            matches.append(record)
                            break
                    else:
                        if process_name.lower() == value.lower():
                            matches.append(record)
                            break
        
        print(f"\n[*] Found {len(matches)} events matching '{process_name}'")
        
        pids = {self._extract_fields(r)['process_id'] for r in matches}
        print(f"[*] Process IDs: {sorted(pids)}")
        
        return matches
    
    def list_processes(self) -> Dict[int, int]:
        """
        List all process IDs with event counts.
        
        Returns:
            Dictionary mapping PID to event count
        """
        process_counts = Counter(
            fields['process_id']
            for record in self.data
            if (fields := self._extract_fields(record))['process_id']
        )
        
        print(f"\n{'='*80}")
        print(f"ALL PROCESSES (sorted by activity)")
        print("="*80)
        
        for pid, count in process_counts.most_common():
            print(f"  PID {pid:<10} {count:>12,} events")
        
        return dict(process_counts)
    
    def find_thread(self, thread_id: int) -> List[Dict]:
        """
        Find all events for a specific thread ID.
        
        Args:
            thread_id: Thread ID to search for
        
        Returns:
            List of events for the thread
        """
        events = [r for r in self.data 
                 if self._extract_fields(r)['thread_id'] == thread_id]
        
        print(f"\n[*] Thread {thread_id}: {len(events)} events")
        
        if events:
            pid = self._extract_fields(events[0])['process_id']
            print(f"[*] Parent Process: {pid}")
        
        return events
    
    def pivot_thread_to_process(self, thread_id: int) -> Optional[Dict]:
        """
        Pivot from thread to parent process, showing all related activity.
        
        Args:
            thread_id: Thread ID to pivot from
        
        Returns:
            Dictionary with thread and process information
        """
        thread_events = self.find_thread(thread_id)
        
        if not thread_events:
            return None
        
        process_id = self._extract_fields(thread_events[0])['process_id']
        
        print(f"\n{'='*80}")
        print(f"PIVOT: Thread {thread_id} → Process {process_id}")
        print("="*80)
        
        process_result = self.find_process(process_id, detailed=False)
        
        return {
            'thread_id': thread_id,
            'process_id': process_id,
            'thread_events': len(thread_events),
            'process_events': process_result['event_count'] if process_result else 0,
            'all_events': process_result['events'] if process_result else []
        }
    
    def registry_operations(self, key_filter: Optional[str] = None, limit: int = None) -> List[Dict]:
        """
        Extract and analyze registry operations.
        
        Args:
            key_filter: Filter by registry key path (case-insensitive substring)
            limit: Maximum number of operations to return
        
        Returns:
            List of registry operation records
        """
        registry_ops = []
        
        for record in self.data:
            fields = self._extract_fields(record)
            task = fields['task_name'] or ''
            props = record.get('properties', {})
            
            if 'Registry' in task or any(k in props for k in ['KeyName', 'ValueName', 'RelativeName', 'TargetObject']):
                key_name = props.get('KeyName') or props.get('RelativeName') or props.get('TargetObject')
                
                if key_filter and key_name:
                    if key_filter.lower() not in str(key_name).lower():
                        continue
                
                registry_ops.append({
                    'timestamp': fields['timestamp'],
                    'process_id': fields['process_id'],
                    'thread_id': fields['thread_id'],
                    'opcode': fields['event_opcode'],
                    'key_name': key_name,
                    'value_name': props.get('ValueName'),
                    'data': props.get('Data') or props.get('Details'),
                    'status': props.get('Status') or props.get('ReturnCode'),
                    'desired_access': props.get('DesiredAccess'),
                    'event_type': props.get('EventType'),
                    'record': record
                })
        
        print(f"\n{'='*80}")
        print(f"REGISTRY OPERATIONS")
        if key_filter:
            print(f"Filtered by: {key_filter}")
        print("="*80)
        print(f"Total operations: {len(registry_ops):,}")
        
        if registry_ops:
            unique_keys = {op['key_name'] for op in registry_ops if op['key_name']}
            print(f"Unique registry keys: {len(unique_keys)}")
            
            key_counter = Counter(op['key_name'] for op in registry_ops if op['key_name'])
            print(f"\nTop 10 Most Accessed Keys:")
            for key, count in key_counter.most_common(10):
                print(f"  {count:>6,}x - {key}")
            
            pids = {op['process_id'] for op in registry_ops if op['process_id']}
            print(f"\nProcesses accessing registry: {sorted(pids)}")
        
        return registry_ops[:limit] if limit else registry_ops
    
    def registry_key(self, key_path: str) -> List[Dict]:
        """Shorthand for registry_operations with key filter."""
        return self.registry_operations(key_filter=key_path)
    
    def file_operations(self, file_filter: Optional[str] = None, limit: int = None) -> List[Dict]:
        """
        Extract and analyze file operations.
        
        Args:
            file_filter: Filter by file path (case-insensitive substring)
            limit: Maximum number of operations to return
        
        Returns:
            List of file operation records
        """
        file_ops = []
        
        for record in self.data:
            fields = self._extract_fields(record)
            task = fields['task_name'] or ''
            props = record.get('properties', {})
            
            if 'FileIo' in task or 'Image' in task or 'File' in task or any(k in props for k in ['FileName', 'ImageFileName', 'TargetFilename']):
                file_name = props.get('FileName') or props.get('ImageFileName') or props.get('TargetFilename')
                
                if file_filter and file_name:
                    if file_filter.lower() not in str(file_name).lower():
                        continue
                
                file_ops.append({
                    'timestamp': fields['timestamp'],
                    'process_id': fields['process_id'],
                    'thread_id': fields['thread_id'],
                    'opcode': fields['event_opcode'],
                    'file_name': file_name,
                    'io_size': props.get('IoSize'),
                    'io_flags': props.get('IoFlags'),
                    'record': record
                })
        
        print(f"\n{'='*80}")
        print(f"FILE OPERATIONS")
        if file_filter:
            print(f"Filtered by: {file_filter}")
        print("="*80)
        print(f"Total operations: {len(file_ops):,}")
        
        if file_ops:
            unique_files = {op['file_name'] for op in file_ops if op['file_name']}
            print(f"Unique files: {len(unique_files)}")
            
            file_counter = Counter(op['file_name'] for op in file_ops if op['file_name'])
            print(f"\nTop 10 Most Accessed Files:")
            for file_path, count in file_counter.most_common(10):
                display = file_path if len(file_path) < 70 else "..." + file_path[-67:]
                print(f"  {count:>6,}x - {display}")
            
            pids = {op['process_id'] for op in file_ops if op['process_id']}
            print(f"\nProcesses accessing files: {sorted(pids)}")
        
        return file_ops[:limit] if limit else file_ops
    
    def file_access(self, file_path: str) -> List[Dict]:
        """Shorthand for file_operations with file filter."""
        return self.file_operations(file_filter=file_path)
    
    def timeline(self, events: Optional[List] = None, limit: int = 50, show_pids: bool = True) -> List[Dict]:
        """
        Build chronological timeline of events.
        
        Args:
            events: List of events to timeline (defaults to first 1000)
            limit: Maximum events to display
            show_pids: Include process IDs in output
        
        Returns:
            List of timeline entries (sorted by timestamp)
        """
        if events is None:
            events = self.data[:1000]
            print(f"[*] Building timeline from first 1000 events")
        
        timeline_data = []
        for record in events:
            fields = self._extract_fields(record)
            timeline_data.append({
                'timestamp': fields['timestamp'],
                'provider': fields['provider_name'],
                'task': fields['task_name'],
                'event_id': fields['event_id'],
                'opcode': fields['event_opcode'],
                'process_id': fields['process_id'],
                'thread_id': fields['thread_id'],
                'summary': self._summarize_event(record),
                'record': record
            })
        
        timeline_data.sort(key=lambda x: x['timestamp'] or '')
        
        print(f"\n{'='*80}")
        print(f"TIMELINE ({len(timeline_data)} events)")
        print("="*80)
        
        for i, event in enumerate(timeline_data[:limit], 1):
            pid_str = f"PID:{event['process_id']:<6}" if show_pids else ""
            print(f"{i:3d}. [{event['timestamp']}] {pid_str} {event['summary']}")
        
        if len(timeline_data) > limit:
            print(f"\n... {len(timeline_data) - limit} more events not shown")
        
        return timeline_data
    
    def _summarize_event(self, record: Dict) -> str:
        """Generate human-readable event summary."""
        fields = self._extract_fields(record)
        props = record.get('properties', {})
        task = fields['task_name'] or 'Unknown'
        provider = fields['provider_name'] or ''
        
        if 'Registry' in task:
            key = props.get('KeyName') or props.get('RelativeName') or props.get('TargetObject', '')
            event_type = props.get('EventType', '')
            return f"Registry {event_type}: {key[:50]}"
        elif 'FileIo' in task or 'Image' in task or 'File' in provider:
            file = props.get('FileName') or props.get('ImageFileName') or props.get('TargetFilename', '')
            return f"File: {file[:50]}"
        elif 'Process' in task:
            img = props.get('ImageFileName') or props.get('Image', '')
            return f"Process: {img[:50]}"
        elif 'Audit' in provider:
            link_src = props.get('LinkSourceName', '')
            link_tgt = props.get('LinkTargetName', '')
            if link_src or link_tgt:
                return f"Audit: {link_src} → {link_tgt}"
        
        return f"{task} (Event {fields['event_id']})"
    
    def search(self, search_term=None, display_limit=None, **kwargs) -> List[Dict]:
        """
        Universal search across all event fields.
        
        Args:
            search_term: String to search for (searches all fields)
            display_limit: Maximum results to display (smart default: all if ≤20, else 20)
            **kwargs: Field-specific search criteria (e.g., process_id=4, event_id=13)
        
        Returns:
            List of matching event records
        """
        results = []
        
        if search_term is not None:
            print(f"\n[*] Searching for '{search_term}' across all fields...")
            search_lower = str(search_term).lower()
            
            results = [
                record for record in self.data
                if search_lower in json.dumps(record, default=str).lower()
            ]
            
            print(f"[+] Found {len(results)} events containing '{search_term}'")
            
            if results:
                if display_limit is None:
                    display_limit = len(results) if len(results) <= 20 else 20
                
                display_count = min(display_limit, len(results))
                
                print(f"\nShowing {'all' if display_count == len(results) else 'first'} {display_count} {'match' if display_count == 1 else 'matches'}:")
                
                for i, record in enumerate(results[:display_count], 1):
                    fields = self._extract_fields(record)
                    props = record.get('properties', {})
                    
                    matching_fields = []
                    
                    for key, value in fields.items():
                        if value and search_lower in str(value).lower():
                            matching_fields.append(f"header.{key}={value}")
                    
                    for key, value in props.items():
                        if value and search_lower in str(value).lower():
                            val_display = str(value)[:50]
                            matching_fields.append(f"properties.{key}={val_display}")
                    
                    print(f"\n  {i}. [{fields['timestamp']}] PID:{fields['process_id']}")
                    if matching_fields:
                        print(f"     Found in: {matching_fields[0]}")
                        if len(matching_fields) > 1:
                            print(f"     Also in: {', '.join(matching_fields[1:3])}")
                
                if len(results) > display_count:
                    print(f"\n... and {len(results) - display_count} more results not displayed")
                    print(f"💡 Tip: All {len(results)} results are stored in your variable.")
                    print(f"         Use display_limit to show more: search('term', display_limit=50)")
            
            return results
        
        elif kwargs:
            for record in self.data:
                fields = self._extract_fields(record)
                props = record.get('properties', {})
                
                match = True
                for key, value in kwargs.items():
                    if key in fields:
                        if isinstance(value, str):
                            if value.lower() not in str(fields[key]).lower():
                                match = False
                                break
                        else:
                            if fields[key] != value:
                                match = False
                                break
                    elif key in props:
                        if isinstance(value, str):
                            if value.lower() not in str(props[key]).lower():
                                match = False
                                break
                        else:
                            if props[key] != value:
                                match = False
                                break
                    else:
                        match = False
                        break
                
                if match:
                    results.append(record)
            
            print(f"\n[*] Found {len(results)} matching events")
            
            if results:
                if display_limit is None:
                    display_limit = len(results) if len(results) <= 20 else 20
                
                display_count = min(display_limit, len(results))
                
                if display_count < len(results):
                    print(f"[*] Showing first {display_count} of {len(results)} results")
                
                for i, record in enumerate(results[:display_count], 1):
                    fields = self._extract_fields(record)
                    print(f"  {i}. [{fields['timestamp']}] PID:{fields['process_id']} - {fields['task_name']}")
                
                if len(results) > display_count:
                    print(f"\n... and {len(results) - display_count} more results not displayed")
            
            return results
        
        else:
            print("[!] Usage: hunter.search('term') or hunter.search(field=value)")
            print("[!] Optional: hunter.search('term', display_limit=50) to show more results")
            return []
    
    def search_all(self, search_term: str) -> List[Dict]:
        """Alias for universal search."""
        return self.search(search_term)
    
    def unique_values(self, field: str, location: str = 'properties') -> Set:
        """
        Get all unique values for a specific field.
        
        Args:
            field: Field name to examine
            location: Search in 'header', 'properties', or 'any'
        
        Returns:
            Set of unique values
        """
        values = set()
        
        for record in self.data:
            if location in ['header', 'any']:
                fields = self._extract_fields(record)
                if field in fields and fields[field] is not None:
                    values.add(fields[field])
            
            if location in ['properties', 'any']:
                props = record.get('properties', {})
                if field in props and props[field] is not None:
                    values.add(props[field])
        
        print(f"\n[*] Found {len(values)} unique values for '{field}'")
        if len(values) <= 20:
            print(f"Values: {sorted(values)}")
        
        return values
    
    def correlate(self, process_id: int, time_window_seconds: int = 60) -> List[Dict]:
        """
        Find events correlated to a process within a time window.
        
        Args:
            process_id: Process ID to correlate
            time_window_seconds: Time window for correlation
        
        Returns:
            List of correlated events
        """
        process_events = [r for r in self.data 
                         if self._extract_fields(r)['process_id'] == process_id]
        
        if not process_events:
            print(f"[!] No events found for PID {process_id}")
            return []
        
        first_ts = self._extract_fields(process_events[0])['timestamp']
        if not first_ts:
            return process_events
        
        try:
            first_time = datetime.fromisoformat(first_ts.replace('Z', '+00:00'))
        except:
            return process_events
        
        correlated = []
        for event in process_events:
            ts = self._extract_fields(event)['timestamp']
            if ts:
                try:
                    event_time = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                    delta = abs((event_time - first_time).total_seconds())
                    if delta <= time_window_seconds:
                        correlated.append(event)
                except:
                    continue
        
        print(f"[*] Found {len(correlated)} events within {time_window_seconds}s window")
        return correlated
    
    def find_related_processes(self, process_id: int) -> List[int]:
        """
        Find processes active during the same timeframe as target process.
        
        Args:
            process_id: Process ID to find related processes for
        
        Returns:
            List of related process IDs
        """
        target_events = [r for r in self.data 
                        if self._extract_fields(r)['process_id'] == process_id]
        
        if not target_events:
            return []
        
        timestamps = [
            self._extract_fields(e)['timestamp']
            for e in target_events
            if self._extract_fields(e)['timestamp']
        ]
        
        if not timestamps:
            return []
        
        min_ts = min(timestamps)
        max_ts = max(timestamps)
        
        related_pids = {
            fields['process_id']
            for record in self.data
            if (fields := self._extract_fields(record))['process_id']
            and fields['process_id'] != process_id
            and fields['timestamp']
            and min_ts <= fields['timestamp'] <= max_ts
        }
        
        print(f"\n[*] Found {len(related_pids)} processes active in same timeframe")
        print(f"PIDs: {sorted(related_pids)}")
        
        return list(related_pids)
    
    def export(self, events: List[Dict], filename: str):
        """Export events to JSON file."""
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(events, f, indent=2, default=str)
        print(f"[+] Exported {len(events)} events to {filename}")
    
    def export_csv(self, filename: str = 'event_overview.csv'):
        """Export event overview to CSV."""
        self._build_hierarchy()
        
        import csv
        
        overview = []
        for provider, tasks in self._event_counts.items():
            for task, events in tasks.items():
                for event_key, details in events.items():
                    overview.append({
                        'provider_name': provider,
                        'task_name': task,
                        'event_id': details['event_id'],
                        'event_name': details['event_name'],
                        'event_opcode': details['event_opcode'],
                        'count': details['count']
                    })
        
        overview.sort(key=lambda x: x['count'], reverse=True)
        
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            if overview:
                writer = csv.DictWriter(f, fieldnames=overview[0].keys())
                writer.writeheader()
                writer.writerows(overview)
        
        print(f"[+] Exported overview to {filename}")
    
    def export_timeline(self, events: List[Dict], filename: str):
        """Export timeline to JSON file."""
        timeline_data = self.timeline(events, limit=len(events))
        self.export([t['record'] for t in timeline_data], filename)
    
    def show(self, event: Dict):
        """Display detailed view of a single event."""
        fields = self._extract_fields(event)
        props = event.get('properties', {})
        
        print("\n" + "="*80)
        print(f"EVENT DETAILS")
        print("="*80)
        print(f"Timestamp:    {fields['timestamp']}")
        print(f"Provider:     {fields['provider_name']}")
        print(f"Task:         {fields['task_name']}")
        print(f"Event ID:     {fields['event_id']} | Opcode: {fields['event_opcode']}")
        print(f"Process ID:   {fields['process_id']} | Thread ID: {fields['thread_id']}")
        
        if props:
            print(f"\nProperties:")
            for key, value in props.items():
                val_str = str(value)
                if len(val_str) > 100:
                    val_str = val_str[:97] + "..."
                print(f"  {key:<25} : {val_str}")
        print("="*80)
    
    def help(self):
        """Display comprehensive help with all available functions."""
        print("\n" + "="*80)
        print("THREAT HUNTER - AVAILABLE FUNCTIONS")
        print("="*80)
        
        functions = [
            ("OVERVIEW", [
                ("overview() or stats()", "Show data overview and statistics"),
                ("list_processes()", "List all process IDs and event counts"),
            ]),
            ("FIELD DISCOVERY", [
                ("discover_fields()", "Discover all available fields in dataset"),
                ("list_fields()", "List all fields with coverage info"),
                ("list_fields('properties')", "Show only property fields"),
                ("lookup_field('FieldName')", "Get detailed info about a field"),
                ("show_field_samples('Field')", "Show unique values for a field"),
                ("fields_by_category()", "Group fields by category (Process/Registry/etc)"),
                ("export_field_reference()", "Export field reference to CSV"),
            ]),
            ("PROCESS INVESTIGATION", [
                ("find_process(pid)", "Get all events for process ID"),
                ("find_process_by_name('name')", "Find events by process name"),
            ]),
            ("THREAD INVESTIGATION", [
                ("find_thread(tid)", "Get all events for thread ID"),
                ("pivot_thread_to_process(tid)", "Pivot from thread to process"),
            ]),
            ("REGISTRY ANALYSIS", [
                ("registry_operations()", "Get all registry operations"),
                ("registry_operations(key_filter='Run')", "Filter by registry key"),
                ("registry_key('path')", "Shortcut for key filter"),
            ]),
            ("FILE ANALYSIS", [
                ("file_operations()", "Get all file operations"),
                ("file_operations(file_filter='temp')", "Filter by file path"),
                ("file_access('path')", "Shortcut for file filter"),
            ]),
            ("TIMELINE", [
                ("timeline()", "Build chronological timeline"),
                ("timeline(events)", "Timeline from specific events"),
            ]),
            ("SEARCH & QUERY", [
                ("search('NSecKrnl')", "Search for term across ALL fields"),
                ("search('term', display_limit=50)", "Show more results"),
                ("search(process_id=4)", "Search by specific field"),
                ("search(event_id=1, provider_name='...')", "Multi-field search"),
                ("search_all('term')", "Alias for universal search"),
                ("unique_values('ImageFileName')", "Get unique field values"),
            ]),
            ("CORRELATION", [
                ("correlate(pid, time_window)", "Find events in time window"),
                ("find_related_processes(pid)", "Find related processes"),
            ]),
            ("EXPORT", [
                ("export(events, 'file.json')", "Export events to JSON"),
                ("export_csv('overview.csv')", "Export overview to CSV"),
                ("export_timeline(events, 'timeline.json')", "Export timeline"),
            ]),
            ("UTILITY", [
                ("show(event)", "Display detailed event view"),
                ("help()", "Show this help message"),
            ]),
        ]
        
        for category, funcs in functions:
            print(f"\n{category}:")
            for func, desc in funcs:
                print(f"  {func:<50} - {desc}")
        
        print("\n" + "="*80)
        print("\nField Discovery Examples:")
        print("  hunter.list_fields()                    # See all available fields")
        print("  hunter.lookup_field('ImageFileName')    # Get field details")
        print("  hunter.show_field_samples('KeyName')    # See unique values")
        print("  hunter.fields_by_category()             # Fields by type")
        print("\nQuick Examples:")
        print("  hunter.search('NSecKrnl')               # Universal search")
        print("  hunter.search('powershell', display_limit=100)  # Show 100 results")
        print("  hunter.find_process(4)                   # Investigate PID")
        print("  hunter.registry_key('Run')               # Registry hunting")
        print("  hunter.pivot_thread_to_process(380)      # Thread pivot")
        print("="*80)