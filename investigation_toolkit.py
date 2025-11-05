import json
from collections import defaultdict, Counter
from typing import Dict, List, Set, Any, Optional
from datetime import datetime


class ThreatHunter:
    
    def __init__(self, filepath: str, auto_analyze: bool = True):
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
    
    def _load_data(self):
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
    
    def overview(self):
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
        
        unique_pids = set()
        for record in self.data:
            fields = self._extract_fields(record)
            if fields['process_id']:
                unique_pids.add(fields['process_id'])
        
        print(f"\nUnique Process IDs: {len(unique_pids)}")
        print(f"Process IDs: {sorted(unique_pids)}")
        
        return {
            'total_events': total_events,
            'providers': providers,
            'unique_pids': unique_pids
        }
    
    def stats(self):
        return self.overview()
    
    def find_process(self, process_id: int, detailed: bool = True):
        events = [r for r in self.data 
                 if self._extract_fields(r)['process_id'] == process_id]
        
        if not events:
            print(f"[!] No events found for PID {process_id}")
            return None
        
        print(f"\n{'='*80}")
        print(f"PROCESS INVESTIGATION: PID {process_id}")
        print("="*80)
        print(f"Total Events: {len(events):,}")
        
        task_counts = Counter()
        for e in events:
            task = self._extract_fields(e)['task_name'] or 'UNKNOWN'
            task_counts[task] += 1
        
        print(f"\nEvent Types:")
        for task, count in task_counts.most_common():
            print(f"  {task:<30} {count:>8,}")
        
        timestamps = [self._extract_fields(e)['timestamp'] for e in events 
                     if self._extract_fields(e)['timestamp']]
        if timestamps:
            print(f"\nTime Span:")
            print(f"  First: {min(timestamps)}")
            print(f"  Last:  {max(timestamps)}")
        
        threads = set(self._extract_fields(e)['thread_id'] for e in events 
                     if self._extract_fields(e)['thread_id'])
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
    
    def find_process_by_name(self, process_name: str, partial: bool = True):
        matches = []
        search_fields = ['ImageFileName', 'CommandLine', 'ProcessName', 'ParentImageName']
        
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
        
        pids = set(self._extract_fields(r)['process_id'] for r in matches)
        print(f"[*] Process IDs: {sorted(pids)}")
        
        return matches
    
    def list_processes(self):
        process_counts = Counter()
        
        for record in self.data:
            pid = self._extract_fields(record)['process_id']
            if pid:
                process_counts[pid] += 1
        
        print(f"\n{'='*80}")
        print(f"ALL PROCESSES (sorted by activity)")
        print("="*80)
        
        for pid, count in process_counts.most_common():
            print(f"  PID {pid:<10} {count:>12,} events")
        
        return dict(process_counts)
    
    def find_thread(self, thread_id: int):
        events = [r for r in self.data 
                 if self._extract_fields(r)['thread_id'] == thread_id]
        
        print(f"\n[*] Thread {thread_id}: {len(events)} events")
        
        if events:
            pid = self._extract_fields(events[0])['process_id']
            print(f"[*] Parent Process: {pid}")
        
        return events
    
    def pivot_thread_to_process(self, thread_id: int):
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
    
    def registry_operations(self, key_filter: Optional[str] = None, limit: int = None):
        registry_ops = []
        
        for record in self.data:
            fields = self._extract_fields(record)
            task = fields['task_name'] or ''
            props = record.get('properties', {})
            
            if 'Registry' in task or any(k in props for k in ['KeyName', 'ValueName', 'RelativeName']):
                key_name = props.get('KeyName') or props.get('RelativeName')
                
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
                    'data': props.get('Data'),
                    'status': props.get('Status') or props.get('ReturnCode'),
                    'desired_access': props.get('DesiredAccess'),
                    'record': record
                })
        
        print(f"\n{'='*80}")
        print(f"REGISTRY OPERATIONS")
        if key_filter:
            print(f"Filtered by: {key_filter}")
        print("="*80)
        print(f"Total operations: {len(registry_ops):,}")
        
        if registry_ops:
            unique_keys = set(op['key_name'] for op in registry_ops if op['key_name'])
            print(f"Unique registry keys: {len(unique_keys)}")
            
            key_counter = Counter(op['key_name'] for op in registry_ops if op['key_name'])
            print(f"\nTop 10 Most Accessed Keys:")
            for key, count in key_counter.most_common(10):
                print(f"  {count:>6,}x - {key}")
            
            pids = set(op['process_id'] for op in registry_ops if op['process_id'])
            print(f"\nProcesses accessing registry: {sorted(pids)}")
        
        return registry_ops[:limit] if limit else registry_ops
    
    def registry_key(self, key_path: str):
        return self.registry_operations(key_filter=key_path)
    
    def file_operations(self, file_filter: Optional[str] = None, limit: int = None):
        file_ops = []
        
        for record in self.data:
            fields = self._extract_fields(record)
            task = fields['task_name'] or ''
            props = record.get('properties', {})
            
            if 'FileIo' in task or 'Image' in task or any(k in props for k in ['FileName', 'ImageFileName']):
                file_name = props.get('FileName') or props.get('ImageFileName')
                
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
            unique_files = set(op['file_name'] for op in file_ops if op['file_name'])
            print(f"Unique files: {len(unique_files)}")
            
            file_counter = Counter(op['file_name'] for op in file_ops if op['file_name'])
            print(f"\nTop 10 Most Accessed Files:")
            for file_path, count in file_counter.most_common(10):
                display = file_path if len(file_path) < 70 else "..." + file_path[-67:]
                print(f"  {count:>6,}x - {display}")
            
            pids = set(op['process_id'] for op in file_ops if op['process_id'])
            print(f"\nProcesses accessing files: {sorted(pids)}")
        
        return file_ops[:limit] if limit else file_ops
    
    def file_access(self, file_path: str):
        return self.file_operations(file_filter=file_path)
    
    def timeline(self, events: Optional[List] = None, limit: int = 50, show_pids: bool = True):
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
        fields = self._extract_fields(record)
        props = record.get('properties', {})
        task = fields['task_name'] or 'Unknown'
        
        if 'Registry' in task:
            key = props.get('KeyName') or props.get('RelativeName', '')
            return f"Registry: {key[:50]}"
        elif 'FileIo' in task or 'Image' in task:
            file = props.get('FileName') or props.get('ImageFileName', '')
            return f"File: {file[:50]}"
        elif 'Process' in task:
            img = props.get('ImageFileName', '')
            return f"Process: {img[:50]}"
        elif 'Audit' in fields['provider_name']:
            link_src = props.get('LinkSourceName', '')
            link_tgt = props.get('LinkTargetName', '')
            if link_src or link_tgt:
                return f"Audit: {link_src} → {link_tgt}"
        
        return f"{task} (opcode {fields['event_opcode']})"
    
    def search(self, search_term=None, **kwargs):
        results = []
        
        if search_term is not None:
            print(f"\n[*] Searching for '{search_term}' across all fields...")
            search_lower = str(search_term).lower()
            
            for record in self.data:
                record_str = json.dumps(record, default=str).lower()
                
                if search_lower in record_str:
                    results.append(record)
            
            print(f"[+] Found {len(results)} events containing '{search_term}'")
            
            if results:
                print(f"\nSample matches (showing first 3):")
                for i, record in enumerate(results[:3], 1):
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
            return results
        
        else:
            print("[!] Usage: hunter.search('term') or hunter.search(field=value)")
            return []
    
    def search_all(self, search_term: str):
        return self.search(search_term)
    
    def unique_values(self, field: str, location: str = 'properties'):
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
    
    def correlate(self, process_id: int, time_window_seconds: int = 60):
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
    
    def find_related_processes(self, process_id: int):
        target_events = [r for r in self.data 
                        if self._extract_fields(r)['process_id'] == process_id]
        
        if not target_events:
            return []
        
        timestamps = [self._extract_fields(e)['timestamp'] for e in target_events 
                     if self._extract_fields(e)['timestamp']]
        
        if not timestamps:
            return []
        
        min_ts = min(timestamps)
        max_ts = max(timestamps)
        
        related_pids = set()
        for record in self.data:
            fields = self._extract_fields(record)
            ts = fields['timestamp']
            pid = fields['process_id']
            
            if pid and pid != process_id and ts:
                if min_ts <= ts <= max_ts:
                    related_pids.add(pid)
        
        print(f"\n[*] Found {len(related_pids)} processes active in same timeframe")
        print(f"PIDs: {sorted(related_pids)}")
        
        return list(related_pids)
    
    def export(self, events: List[Dict], filename: str):
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(events, f, indent=2, default=str)
        print(f"[+] Exported {len(events)} events to {filename}")
    
    def export_csv(self, filename: str = 'event_overview.csv'):
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
        timeline_data = self.timeline(events, limit=len(events))
        self.export([t['record'] for t in timeline_data], filename)
    
    def show(self, event: Dict):
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
        print("\n" + "="*80)
        print("THREAT HUNTER - AVAILABLE FUNCTIONS")
        print("="*80)
        
        functions = [
            ("OVERVIEW", [
                ("overview() or stats()", "Show data overview and statistics"),
                ("list_processes()", "List all process IDs and event counts"),
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
        print("\nQuick Examples:")
        print("  hunter.search('NSecKrnl')           # Universal search")
        print("  hunter.find_process(4)               # Investigate PID")
        print("  hunter.registry_key('Run')           # Registry hunting")
        print("  hunter.pivot_thread_to_process(380)  # Thread pivot")
        print("="*80)


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python threat_hunting_toolkit.py <jsonl_file>")
        print("\nExample:")
        print("  python threat_hunting_toolkit.py events.jsonl")
        sys.exit(1)
    
    hunter = ThreatHunter(sys.argv[1])
    hunter.help()
    
    print("\n" + "="*80)
    print("EXAMPLE INVESTIGATIONS")
    print("="*80)
    
    print("\n[Example 1] Most active process:")
    process_counts = hunter.list_processes()
    if process_counts:
        most_active_pid = max(process_counts, key=process_counts.get)
        hunter.find_process(most_active_pid, detailed=False)
    
    print("\n[Example 2] Universal search:")
    results = hunter.search('NSecKrnl')
    
    print("\n[Example 3] Registry analysis:")
    registry_ops = hunter.registry_operations(limit=5)
    
    print("\n" + "="*80)
    print("TOOLKIT READY - Use hunter.help() to see all functions")
    print("="*80)