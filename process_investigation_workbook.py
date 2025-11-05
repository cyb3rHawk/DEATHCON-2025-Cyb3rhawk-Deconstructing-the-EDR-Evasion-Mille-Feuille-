"""
Process Investigation Workbook

Provides deep process-level investigation capabilities including:
- Multi-PID tracking and analysis
- Parent-child relationship mapping
- Cross-process resource sharing analysis
- Activity timeline construction
- Comprehensive reporting and export
"""

from threat_hunting_toolkit import ThreatHunter
from collections import defaultdict, Counter
from typing import Dict, List, Set, Any, Optional
import json


class ProcessInvestigationWorkbook:
    """
    Deep process investigation toolkit for analyzing process behavior across events.
    
    Tracks process activity, relationships, and resource access patterns.
    Generates comprehensive reports with timeline and correlation data.
    """
    
    def __init__(self, hunter: ThreatHunter):
        """
        Initialize investigation workbook with a ThreatHunter instance.
        
        Args:
            hunter: ThreatHunter instance containing loaded event data
        """
        self.hunter = hunter
        self.investigation_data = {}
    
    def investigate_process_name(self, process_name: str, export_report: bool = True) -> Optional[Dict]:
        """
        Conduct comprehensive investigation of all instances of a process name.
        
        Analyzes all PIDs associated with the process name and builds:
        - Per-PID activity breakdown
        - Parent-child relationships
        - Resource access patterns
        - Cross-PID correlations
        - Complete timeline
        
        Args:
            process_name: Process name to investigate
            export_report: Export results to JSON and text files
        
        Returns:
            Dictionary containing complete investigation results
        """
        print("="*100)
        print(f"DEEP PROCESS INVESTIGATION: {process_name}")
        print("="*100)
        
        self.investigation_data = {
            'target_process_name': process_name,
            'all_pids': [],
            'pid_details': {},
            'parent_child_relationships': [],
            'activity_summary': {},
            'timeline': [],
            'findings': []
        }
        
        print("\n[STEP 1] Finding all instances of process...")
        all_events = self.hunter.find_process_by_name(process_name, partial=True)
        
        if not all_events:
            print(f"[!] No events found for process: {process_name}")
            return None
        
        print(f"[+] Found {len(all_events)} events")
        
        print("\n[STEP 2] Extracting unique Process IDs...")
        pids = {
            self.hunter._extract_fields(event).get('process_id')
            for event in all_events
            if self.hunter._extract_fields(event).get('process_id')
        }
        
        self.investigation_data['all_pids'] = sorted(pids)
        print(f"[+] Found {len(pids)} unique PIDs: {sorted(pids)}")
        
        print("\n[STEP 3] Analyzing each Process ID...")
        for pid in sorted(pids):
            self._analyze_pid(pid)
        
        print("\n[STEP 4] Identifying parent-child relationships...")
        self._find_parent_child_relationships()
        
        print("\n[STEP 5] Building activity timeline...")
        self._build_activity_timeline(all_events)
        
        print("\n[STEP 6] Analyzing cross-PID activity...")
        self._analyze_cross_pid_activity()
        
        print("\n[STEP 7] Identifying touched events...")
        self._analyze_touched_events()
        
        print("\n[STEP 8] Generating summary report...")
        self._generate_summary()
        
        if export_report:
            self._export_investigation_report()
        
        return self.investigation_data
    
    def _analyze_pid(self, pid: int):
        """
        Analyze comprehensive activity for a single process ID.
        
        Extracts operation counts, resource access patterns, parent info,
        and temporal information.
        
        Args:
            pid: Process ID to analyze
        """
        print(f"\n  → Analyzing PID {pid}...")
        
        result = self.hunter.find_process(pid, detailed=False)
        
        if not result:
            print(f"    [!] No data returned for PID {pid}")
            return
        
        events = result.get('events', [])
        if not events:
            print(f"    [!] No events found for PID {pid}")
            return
        
        threads = result.get('threads', set())
        if not isinstance(threads, set):
            threads = set(threads) if threads else set()
        
        if not threads:
            threads = {
                fields.get('thread_id')
                for e in events
                if (fields := self.hunter._extract_fields(e)).get('thread_id') is not None
            }
        
        event_types = result.get('event_types', {})
        if not isinstance(event_types, dict):
            event_types = {}
        
        pid_data = {
            'pid': pid,
            'total_events': len(events),
            'event_types': event_types,
            'threads': sorted(list(threads)),
            'registry_operations': 0,
            'file_operations': 0,
            'network_operations': 0,
            'process_operations': 0,
            'unique_registry_keys': set(),
            'unique_files': set(),
            'parent_process_id': None,
            'parent_image_name': None,
            'command_line': None,
            'user_sid': None,
            'timestamps': {'first': None, 'last': None}
        }
        
        for event in events:
            fields = self.hunter._extract_fields(event)
            props = event.get('properties', {})
            task = fields.get('task_name', '') or ''
            
            if 'Registry' in task:
                pid_data['registry_operations'] += 1
                key = props.get('KeyName') or props.get('RelativeName') or props.get('TargetObject')
                if key:
                    pid_data['unique_registry_keys'].add(key)
            
            if 'FileIo' in task or 'Image' in task or 'File' in task:
                pid_data['file_operations'] += 1
                file = props.get('FileName') or props.get('ImageFileName') or props.get('ImageLoaded')
                if file:
                    pid_data['unique_files'].add(file)
            
            if 'Process' in task:
                pid_data['process_operations'] += 1
            
            if props.get('ParentId') and not pid_data['parent_process_id']:
                pid_data['parent_process_id'] = props.get('ParentId')
            if props.get('ParentProcessId') and not pid_data['parent_process_id']:
                pid_data['parent_process_id'] = props.get('ParentProcessId')
            if props.get('ParentImageName') and not pid_data['parent_image_name']:
                pid_data['parent_image_name'] = props.get('ParentImageName')
            if props.get('ParentImage') and not pid_data['parent_image_name']:
                pid_data['parent_image_name'] = props.get('ParentImage')
            if props.get('CommandLine') and not pid_data['command_line']:
                pid_data['command_line'] = props.get('CommandLine')
            if props.get('UserSID') and not pid_data['user_sid']:
                pid_data['user_sid'] = props.get('UserSID')
        
        timestamps = [
            fields.get('timestamp')
            for e in events
            if (fields := self.hunter._extract_fields(e)).get('timestamp')
        ]
        
        if timestamps:
            pid_data['timestamps']['first'] = min(timestamps)
            pid_data['timestamps']['last'] = max(timestamps)
        
        pid_data['unique_registry_keys'] = list(pid_data['unique_registry_keys'])[:50]
        pid_data['unique_files'] = list(pid_data['unique_files'])[:50]
        
        self.investigation_data['pid_details'][pid] = pid_data
        
        print(f"    Events: {pid_data['total_events']:,}")
        print(f"    Registry ops: {pid_data['registry_operations']:,}")
        print(f"    File ops: {pid_data['file_operations']:,}")
        print(f"    Threads: {len(threads)}")
        print(f"    Parent PID: {pid_data['parent_process_id'] or 'N/A'}")
    
    def _find_parent_child_relationships(self):
        """Identify and document parent-child process relationships."""
        relationships = []
        
        for pid, data in self.investigation_data['pid_details'].items():
            parent_pid = data.get('parent_process_id')
            if parent_pid:
                relationships.append({
                    'child_pid': pid,
                    'parent_pid': parent_pid,
                    'parent_image': data.get('parent_image_name'),
                    'command_line': data.get('command_line')
                })
        
        self.investigation_data['parent_child_relationships'] = relationships
        
        print(f"[+] Found {len(relationships)} parent-child relationships")
        for rel in relationships:
            print(f"    Parent PID {rel['parent_pid']} → Child PID {rel['child_pid']}")
            if rel['parent_image']:
                print(f"      Parent: {rel['parent_image']}")
    
    def _build_activity_timeline(self, events: List[Dict]):
        """
        Build chronological timeline of all process activity.
        
        Args:
            events: List of events to include in timeline
        """
        timeline = []
        
        for event in events:
            fields = self.hunter._extract_fields(event)
            props = event.get('properties', {})
            
            timeline.append({
                'timestamp': fields.get('timestamp'),
                'pid': fields.get('process_id'),
                'tid': fields.get('thread_id'),
                'provider': fields.get('provider_name'),
                'task': fields.get('task_name'),
                'event_id': fields.get('event_id'),
                'opcode': fields.get('event_opcode'),
                'summary': self.hunter._summarize_event(event),
                'key_properties': {
                    'ImageFileName': props.get('ImageFileName') or props.get('Image'),
                    'CommandLine': props.get('CommandLine'),
                    'KeyName': props.get('KeyName') or props.get('RelativeName') or props.get('TargetObject'),
                    'FileName': props.get('FileName') or props.get('ImageLoaded')
                }
            })
        
        timeline.sort(key=lambda x: x['timestamp'] or '')
        self.investigation_data['timeline'] = timeline
        
        print(f"[+] Built timeline with {len(timeline):,} events")
        if timeline:
            print(f"    Time span: {timeline[0]['timestamp']} to {timeline[-1]['timestamp']}")
    
    def _analyze_cross_pid_activity(self):
        """Analyze resources and activities shared across multiple PIDs."""
        activity = {
            'registry_keys_accessed': defaultdict(list),
            'files_accessed': defaultdict(list),
            'event_types': defaultdict(list),
            'shared_threads': defaultdict(list)
        }
        
        for pid, data in self.investigation_data['pid_details'].items():
            for key in data.get('unique_registry_keys', []):
                activity['registry_keys_accessed'][key].append(pid)
            
            for file in data.get('unique_files', []):
                activity['files_accessed'][file].append(pid)
            
            for event_type, count in data.get('event_types', {}).items():
                activity['event_types'][event_type].append({'pid': pid, 'count': count})
        
        shared_resources = {
            'registry_keys': {k: v for k, v in activity['registry_keys_accessed'].items() if len(v) > 1},
            'files': {k: v for k, v in activity['files_accessed'].items() if len(v) > 1},
            'event_types': dict(activity['event_types'])
        }
        
        self.investigation_data['activity_summary'] = {
            'total_unique_registry_keys': len(activity['registry_keys_accessed']),
            'total_unique_files': len(activity['files_accessed']),
            'shared_registry_keys': len(shared_resources['registry_keys']),
            'shared_files': len(shared_resources['files']),
            'shared_resources': shared_resources
        }
        
        print(f"[+] Cross-PID Activity Analysis:")
        print(f"    Total unique registry keys: {self.investigation_data['activity_summary']['total_unique_registry_keys']:,}")
        print(f"    Total unique files: {self.investigation_data['activity_summary']['total_unique_files']:,}")
        print(f"    Shared registry keys: {self.investigation_data['activity_summary']['shared_registry_keys']:,}")
        print(f"    Shared files: {self.investigation_data['activity_summary']['shared_files']:,}")
    
    def _analyze_touched_events(self):
        """Analyze event provider and type coverage."""
        event_analysis = {
            'unique_providers': set(),
            'unique_tasks': set(),
            'unique_event_ids': set(),
            'unique_opcodes': set(),
            'provider_task_combinations': defaultdict(set),
            'event_id_distribution': Counter()
        }
        
        for event in self.investigation_data['timeline']:
            provider = event.get('provider')
            task = event.get('task')
            event_id = event.get('event_id')
            opcode = event.get('opcode')
            
            if provider:
                event_analysis['unique_providers'].add(provider)
            if task:
                event_analysis['unique_tasks'].add(task)
            if event_id is not None:
                event_analysis['unique_event_ids'].add(event_id)
            if opcode is not None:
                event_analysis['unique_opcodes'].add(opcode)
            
            if provider and task:
                event_analysis['provider_task_combinations'][provider].add(task)
            
            if event_id is not None:
                event_analysis['event_id_distribution'][event_id] += 1
        
        self.investigation_data['touched_events'] = {
            'unique_providers': sorted([p for p in event_analysis['unique_providers'] if p]),
            'unique_tasks': sorted([t for t in event_analysis['unique_tasks'] if t]),
            'unique_event_ids': sorted([e for e in event_analysis['unique_event_ids'] if e is not None]),
            'unique_opcodes': sorted([o for o in event_analysis['unique_opcodes'] if o is not None]),
            'provider_task_map': {k: sorted(v) for k, v in event_analysis['provider_task_combinations'].items()},
            'top_10_event_ids': event_analysis['event_id_distribution'].most_common(10)
        }
        
        print(f"[+] Event Coverage Analysis:")
        print(f"    Unique providers: {len(event_analysis['unique_providers'])}")
        print(f"    Unique tasks: {len(event_analysis['unique_tasks'])}")
        print(f"    Unique event IDs: {len(event_analysis['unique_event_ids'])}")
    
    def _generate_summary(self):
        """Generate and display comprehensive investigation summary."""
        print("\n" + "="*100)
        print("INVESTIGATION SUMMARY")
        print("="*100)
        
        print(f"\nTarget Process: {self.investigation_data['target_process_name']}")
        print(f"Process IDs Found: {self.investigation_data['all_pids']}")
        
        total_events = sum(d.get('total_events', 0) for d in self.investigation_data['pid_details'].values())
        print(f"Total Events: {total_events:,}")
        
        print("\n" + "-"*100)
        print("PER-PID BREAKDOWN")
        print("-"*100)
        
        for pid in sorted(self.investigation_data['all_pids']):
            data = self.investigation_data['pid_details'].get(pid, {})
            print(f"\nPID {pid}:")
            print(f"  Total Events:        {data.get('total_events', 0):>8,}")
            print(f"  Registry Operations: {data.get('registry_operations', 0):>8,}")
            print(f"  File Operations:     {data.get('file_operations', 0):>8,}")
            print(f"  Process Operations:  {data.get('process_operations', 0):>8,}")
            print(f"  Unique Threads:      {len(data.get('threads', [])):>8,}")
            
            cmd = data.get('command_line')
            cmd_display = cmd[:80] if cmd else 'N/A'
            print(f"  Command Line:        {cmd_display}")
            print(f"  Parent PID:          {data.get('parent_process_id') or 'N/A'}")
            
            timestamps = data.get('timestamps', {})
            first = timestamps.get('first', 'N/A')
            last = timestamps.get('last', 'N/A')
            print(f"  Time Span:           {first} to {last}")
        
        print("\n" + "-"*100)
        print("ACTIVITY SUMMARY")
        print("-"*100)
        
        activity = self.investigation_data['activity_summary']
        print(f"Total Unique Registry Keys Accessed: {activity.get('total_unique_registry_keys', 0):,}")
        print(f"Total Unique Files Accessed:         {activity.get('total_unique_files', 0):,}")
        print(f"Registry Keys Shared Across PIDs:    {activity.get('shared_registry_keys', 0):,}")
        print(f"Files Shared Across PIDs:            {activity.get('shared_files', 0):,}")
        
        shared_resources = activity.get('shared_resources', {})
        
        if activity.get('shared_registry_keys', 0) > 0:
            print("\nTop Shared Registry Keys:")
            registry_keys = shared_resources.get('registry_keys', {})
            for key, pids in list(registry_keys.items())[:10]:
                key_display = key[:70] if len(key) > 70 else key
                print(f"  {key_display}")
                print(f"    Accessed by PIDs: {pids}")
        
        if activity.get('shared_files', 0) > 0:
            print("\nTop Shared Files:")
            files = shared_resources.get('files', {})
            for file, pids in list(files.items())[:10]:
                file_display = file[:70] if len(file) > 70 else file
                print(f"  {file_display}")
                print(f"    Accessed by PIDs: {pids}")
        
        print("\n" + "-"*100)
        print("EVENT COVERAGE")
        print("-"*100)
        
        touched = self.investigation_data['touched_events']
        unique_providers = touched.get('unique_providers', [])
        print(f"Unique Event Providers: {len(unique_providers)}")
        for provider in unique_providers[:10]:
            print(f"  - {provider}")
        if len(unique_providers) > 10:
            print(f"  ... and {len(unique_providers) - 10} more")
        
        print(f"\nTop 10 Event IDs by Frequency:")
        for event_id, count in touched.get('top_10_event_ids', []):
            print(f"  Event ID {event_id}: {count:>8,} occurrences")
        
        print("\n" + "-"*100)
        print("PARENT-CHILD RELATIONSHIPS")
        print("-"*100)
        
        relationships = self.investigation_data.get('parent_child_relationships', [])
        if relationships:
            for rel in relationships:
                print(f"\nParent PID {rel['parent_pid']} spawned Child PID {rel['child_pid']}")
                if rel.get('parent_image'):
                    print(f"  Parent Image: {rel['parent_image']}")
                if rel.get('command_line'):
                    cmd_display = rel['command_line'][:80] if len(rel['command_line']) > 80 else rel['command_line']
                    print(f"  Command Line: {cmd_display}")
        else:
            print("No parent-child relationships found in dataset")
        
        print("\n" + "="*100)
    
    def _export_investigation_report(self):
        """Export investigation results to multiple file formats."""
        process_name_safe = self.investigation_data['target_process_name'].replace(' ', '_').replace('/', '_').replace('\\', '_')
        
        report_file = f"investigation_{process_name_safe}_full.json"
        timeline_file = f"investigation_{process_name_safe}_timeline.json"
        summary_file = f"investigation_{process_name_safe}_summary.txt"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(self.investigation_data, f, indent=2, default=str)
        print(f"\n[+] Exported full investigation to: {report_file}")
        
        with open(timeline_file, 'w', encoding='utf-8') as f:
            json.dump(self.investigation_data['timeline'], f, indent=2, default=str)
        print(f"[+] Exported timeline to: {timeline_file}")
        
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write(f"INVESTIGATION SUMMARY: {self.investigation_data['target_process_name']}\n")
            f.write("="*100 + "\n\n")
            
            f.write(f"Process IDs: {self.investigation_data['all_pids']}\n")
            total_events = sum(d.get('total_events', 0) for d in self.investigation_data['pid_details'].values())
            f.write(f"Total Events: {total_events:,}\n\n")
            
            f.write("PER-PID DETAILS:\n")
            f.write("-"*100 + "\n")
            for pid in sorted(self.investigation_data['all_pids']):
                data = self.investigation_data['pid_details'].get(pid, {})
                f.write(f"\nPID {pid}:\n")
                f.write(f"  Events: {data.get('total_events', 0):,}\n")
                f.write(f"  Registry: {data.get('registry_operations', 0):,}\n")
                f.write(f"  Files: {data.get('file_operations', 0):,}\n")
                f.write(f"  Parent: {data.get('parent_process_id', 'N/A')}\n")
                f.write(f"  Command: {data.get('command_line', 'N/A')}\n")
        
        print(f"[+] Exported summary to: {summary_file}")
    
    def print_timeline(self, limit: int = 50):
        """
        Display detailed timeline with key properties.
        
        Args:
            limit: Maximum number of events to display
        """
        print("\n" + "="*100)
        print("DETAILED TIMELINE")
        print("="*100)
        
        timeline = self.investigation_data.get('timeline', [])
        
        if not timeline:
            print("No timeline data available")
            return
        
        display_count = min(limit, len(timeline))
        
        if display_count == len(timeline):
            print(f"Showing all {len(timeline)} events:")
        else:
            print(f"Showing first {display_count} of {len(timeline)} events:")
        
        for i, event in enumerate(timeline[:display_count], 1):
            print(f"\n{i:3d}. [{event.get('timestamp', 'N/A')}] PID:{event.get('pid', 'N/A')} TID:{event.get('tid', 'N/A')}")
            print(f"     {event.get('summary', 'N/A')}")
            
            key_props = event.get('key_properties', {})
            if key_props.get('CommandLine'):
                cmd = key_props['CommandLine']
                cmd_display = cmd[:80] if len(cmd) > 80 else cmd
                print(f"     CMD: {cmd_display}")
            if key_props.get('KeyName'):
                key = key_props['KeyName']
                key_display = key[:80] if len(key) > 80 else key
                print(f"     REG: {key_display}")
            if key_props.get('FileName'):
                file = key_props['FileName']
                file_display = file[:80] if len(file) > 80 else file
                print(f"     FILE: {file_display}")
        
        if len(timeline) > display_count:
            print(f"\n... {len(timeline) - display_count} more events not shown")
            print(f"💡 Tip: Use print_timeline(limit={len(timeline)}) to see all events")
    
    def get_pid_details(self, pid: int) -> Optional[Dict]:
        """
        Retrieve detailed analysis for a specific PID.
        
        Args:
            pid: Process ID to get details for
        
        Returns:
            Dictionary with PID analysis or None
        """
        return self.investigation_data.get('pid_details', {}).get(pid)
    
    def get_shared_resources(self) -> Dict:
        """
        Get resources shared across multiple PIDs.
        
        Returns:
            Dictionary with shared registry keys, files, etc.
        """
        return self.investigation_data.get('activity_summary', {}).get('shared_resources', {})
    
    def search_in_investigation(self, search_term: str, display_limit: int = None) -> List[Dict]:
        """
        Search within investigation timeline.
        
        Args:
            search_term: Term to search for
            display_limit: Maximum results to display
        
        Returns:
            List of matching timeline events
        """
        results = [
            event for event in self.investigation_data.get('timeline', [])
            if search_term.lower() in json.dumps(event, default=str).lower()
        ]
        
        print(f"\n[*] Found {len(results)} matching events in investigation timeline")
        
        if results:
            if display_limit is None:
                display_limit = len(results) if len(results) <= 20 else 20
            
            display_count = min(display_limit, len(results))
            
            if display_count == len(results):
                print(f"Showing all {len(results)} matches:")
            else:
                print(f"Showing first {display_count} of {len(results)} matches:")
            
            for i, event in enumerate(results[:display_count], 1):
                print(f"\n  {i}. [{event.get('timestamp', 'N/A')}] PID:{event.get('pid', 'N/A')}")
                print(f"     {event.get('summary', 'N/A')}")
            
            if len(results) > display_count:
                print(f"\n... and {len(results) - display_count} more results")
                print(f"💡 Tip: Use search_in_investigation('{search_term}', display_limit={len(results)}) to see all")
        
        return results


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python process_investigation_workbook.py <jsonl_file> <process_name>")
        print("\nExample:")
        print("  python process_investigation_workbook.py events.jsonl powershell")
        print("  python process_investigation_workbook.py events.jsonl svchost.exe")
        sys.exit(1)
    
    jsonl_file = sys.argv[1]
    process_name = sys.argv[2]
    
    print("Initializing Threat Hunter...")
    hunter = ThreatHunter(jsonl_file)
    
    print("\nInitializing Investigation Workbook...")
    workbook = ProcessInvestigationWorkbook(hunter)
    
    investigation = workbook.investigate_process_name(process_name, export_report=True)
    
    if investigation:
        print("\n" + "="*100)
        print("INVESTIGATION COMPLETE")
        print("="*100)
        print("\nYou can now:")
        print("  1. Review the summary above")
        print("  2. Check exported JSON files for detailed data")
        print("  3. Use workbook methods for further analysis:")
        print("     - workbook.print_timeline(limit=100)")
        print("     - workbook.get_pid_details(4)")
        print("     - workbook.get_shared_resources()")
        print("     - workbook.search_in_investigation('term')")