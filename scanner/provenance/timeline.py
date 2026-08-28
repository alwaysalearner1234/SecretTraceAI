from typing import List, Dict, Any, Tuple
from scanner.detector.candidate_extractor import Candidate
from scanner.history.git_walker import GitCommit

class TimelineEvent:
    def __init__(self,
                 commit_hash: str,
                 commit_message: str,
                 author: str,
                 timestamp: int,
                 file_path: str,
                 line_number: int,
                 event_type: str):
        self.commit_hash = commit_hash
        self.commit_message = commit_message
        self.author = author
        self.timestamp = timestamp
        self.file_path = file_path
        self.line_number = line_number
        self.event_type = event_type # 'INTRODUCED', 'MODIFIED', 'DELETED', 'COPIED'

    def to_dict(self) -> Dict[str, Any]:
        return {
            "commit_hash": self.commit_hash,
            "commit_message": self.commit_message,
            "author": self.author,
            "timestamp": self.timestamp,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "event_type": self.event_type
        }

class Finding:
    def __init__(self,
                 fingerprint: str,
                 masked_value: str,
                 provider: str,
                 credential_type: str,
                 candidates: List[Candidate],
                 commits_map: Dict[str, GitCommit]):
        self.fingerprint = fingerprint
        self.masked_value = masked_value
        self.provider = provider
        self.type = credential_type
        self.candidates = candidates
        
        # Build timeline
        self.timeline: List[TimelineEvent] = []
        self.status = "ACTIVE" # 'ACTIVE' or 'DELETED'
        self._build_timeline(commits_map)

    def _build_timeline(self, commits_map: Dict[str, GitCommit]):
        # Sort candidates chronologically based on commit timestamp
        # Fall back to 0 if commit not in map
        sorted_candidates = sorted(
            self.candidates,
            key=lambda c: commits_map[c.commit_hash].timestamp if c.commit_hash in commits_map else 0
        )
        
        active_instances = set() # Set of (file_path) where secret is active
        
        for idx, c in enumerate(sorted_candidates):
            commit = commits_map.get(c.commit_hash)
            timestamp = commit.timestamp if commit else 0
            message = commit.message if commit else "Working Tree"
            author = commit.author if commit else "Developer"
            
            # Determine event type
            if idx == 0:
                if c.change_type == "DELETED":
                    event_type = "DELETED"
                else:
                    event_type = "INTRODUCED"
                    active_instances.add(c.file_path)
            else:
                if c.change_type == "ADDED":
                    if c.file_path in active_instances:
                        event_type = "MODIFIED"
                    else:
                        event_type = "COPIED"
                        active_instances.add(c.file_path)
                else: # DELETED
                    event_type = "DELETED"
                    if c.file_path in active_instances:
                        active_instances.remove(c.file_path)
            
            self.timeline.append(TimelineEvent(
                commit_hash=c.commit_hash,
                commit_message=message,
                author=author,
                timestamp=timestamp,
                file_path=c.file_path,
                line_number=c.line_number,
                event_type=event_type
            ))
            
        # Determine final status: if there are still active instances of the secret, status is ACTIVE, otherwise DELETED
        # For working tree scans, if it's there, it's active.
        has_working_tree = any(c.commit_hash == "WORKING_TREE" for c in sorted_candidates)
        if has_working_tree:
            self.status = "ACTIVE"
        else:
            self.status = "ACTIVE" if len(active_instances) > 0 else "DELETED"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "masked_value": self.masked_value,
            "provider": self.provider,
            "type": self.type,
            "status": self.status,
            "timeline": [t.to_dict() for t in self.timeline]
        }

class ProvenanceEngine:
    @staticmethod
    def process_candidates(candidates: List[Candidate], commits: List[GitCommit]) -> List[Finding]:
        """Group candidates into logical findings and construct timelines."""
        commits_map = {c.hash: c for c in commits}
        
        # Group by fingerprint
        grouped: Dict[str, List[Candidate]] = {}
        for c in candidates:
            if c.fingerprint not in grouped:
                grouped[c.fingerprint] = []
            grouped[c.fingerprint].append(c)
            
        findings = []
        for fingerprint, cand_list in grouped.items():
            first = cand_list[0]
            findings.append(Finding(
                fingerprint=fingerprint,
                masked_value=first.masked_value,
                provider=first.provider,
                credential_type=first.type,
                candidates=cand_list,
                commits_map=commits_map
            ))
            
        return findings
