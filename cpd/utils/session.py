"""
Session Manager for CPD Scan Pause/Resume functionality.

Saves scan progress to allow pausing and resuming scans.
"""

import os
import json
import time
import hashlib
from typing import List, Dict, Optional, Set
from pathlib import Path

from cpd.utils.logger import logger


class SessionManager:
    """
    Manages scan sessions for pause/resume functionality.
    
    Session file structure:
    {
        "version": 1,
        "created_at": timestamp,
        "updated_at": timestamp,
        "config": {...},
        "pending_urls": [...],
        "completed_urls": [...],
        "findings": [...],
        "stats": {...}
    }
    """
    
    SESSION_DIR = os.path.expanduser("~/.cpd/sessions")
    SESSION_VERSION = 1
    
    def __init__(self, session_id: Optional[str] = None):
        self.session_id = session_id or self._generate_session_id()
        self.session_file = os.path.join(self.SESSION_DIR, f"{self.session_id}.json")
        
        # Ensure session directory exists
        os.makedirs(self.SESSION_DIR, exist_ok=True)
        
        # Session state
        self.pending_urls: List[str] = []
        self.completed_urls: Set[str] = set()
        self.findings: List[Dict] = []
        self.config: Dict = {}
        self.stats: Dict = {}
        self.created_at: float = time.time()
        self.updated_at: float = time.time()
        self._paused = False
    
    @staticmethod
    def _generate_session_id() -> str:
        """Generate unique session ID based on timestamp."""
        return f"cpd_{int(time.time())}_{hashlib.md5(str(time.time()).encode()).hexdigest()[:6]}"
    
    def initialize(self, urls: List[str], config: Dict = None):
        """Initialize a new session with URLs to scan."""
        self.pending_urls = urls.copy()
        self.completed_urls = set()
        self.findings = []
        self.config = config or {}
        self.created_at = time.time()
        self.updated_at = time.time()
        self._save()
        logger.info(f"Session initialized: {self.session_id} ({len(urls)} URLs)")
    
    def mark_completed(self, url: str, url_findings: List[Dict] = None):
        """Mark a URL as completed and save any findings."""
        if url in self.pending_urls:
            self.pending_urls.remove(url)
        self.completed_urls.add(url)
        
        if url_findings:
            self.findings.extend(url_findings)
        
        self.updated_at = time.time()
        # Save periodically (every 10 completed)
        if len(self.completed_urls) % 10 == 0:
            self._save()
    
    def get_pending_urls(self) -> List[str]:
        """Get remaining URLs to scan."""
        return self.pending_urls.copy()
    
    def pause(self):
        """Pause the scan and save state."""
        self._paused = True
        self._save()
        logger.info(f"Session paused: {self.session_id}")
        logger.info(f"  Completed: {len(self.completed_urls)}/{len(self.completed_urls) + len(self.pending_urls)}")
        logger.info(f"  Findings: {len(self.findings)}")
        logger.info(f"  Resume with: cpd scan --resume {self.session_id}")
    
    def is_paused(self) -> bool:
        """Check if session is paused."""
        return self._paused
    
    def update_stats(self, stats: Dict):
        """Update session statistics."""
        self.stats = stats.copy()
        self.updated_at = time.time()
    
    def _save(self):
        """Save session to file."""
        data = {
            "version": self.SESSION_VERSION,
            "session_id": self.session_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "config": self.config,
            "pending_urls": self.pending_urls,
            "completed_urls": list(self.completed_urls),
            "findings": self.findings,
            "stats": self.stats,
            "paused": self._paused,
        }
        
        try:
            with open(self.session_file, 'w') as f:
                json.dump(data, f, indent=2)
        except IOError as e:
            logger.error(f"Failed to save session: {e}")
    
    @classmethod
    def load(cls, session_id: str) -> Optional["SessionManager"]:
        """Load an existing session."""
        session_file = os.path.join(cls.SESSION_DIR, f"{session_id}.json")
        
        if not os.path.exists(session_file):
            logger.error(f"Session not found: {session_id}")
            return None
        
        try:
            with open(session_file, 'r') as f:
                data = json.load(f)
            
            session = cls(session_id=data["session_id"])
            session.created_at = data["created_at"]
            session.updated_at = data["updated_at"]
            session.config = data.get("config", {})
            session.pending_urls = data.get("pending_urls", [])
            session.completed_urls = set(data.get("completed_urls", []))
            session.findings = data.get("findings", [])
            session.stats = data.get("stats", {})
            session._paused = False  # Reset paused state on load
            
            logger.info(f"Session loaded: {session_id}")
            logger.info(f"  Remaining: {len(session.pending_urls)} URLs")
            logger.info(f"  Completed: {len(session.completed_urls)} URLs")
            logger.info(f"  Findings so far: {len(session.findings)}")
            
            return session
            
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Failed to load session: {e}")
            return None
    
    @classmethod
    def list_sessions(cls) -> List[Dict]:
        """List all available sessions."""
        sessions = []
        
        if not os.path.exists(cls.SESSION_DIR):
            return sessions
        
        for filename in os.listdir(cls.SESSION_DIR):
            if filename.endswith('.json'):
                filepath = os.path.join(cls.SESSION_DIR, filename)
                try:
                    with open(filepath, 'r') as f:
                        data = json.load(f)
                    
                    sessions.append({
                        "session_id": data.get("session_id", filename[:-5]),
                        "created_at": data.get("created_at"),
                        "updated_at": data.get("updated_at"),
                        "pending": len(data.get("pending_urls", [])),
                        "completed": len(data.get("completed_urls", [])),
                        "findings": len(data.get("findings", [])),
                        "paused": data.get("paused", False),
                    })
                except Exception:
                    pass
        
        return sorted(sessions, key=lambda x: x.get("updated_at", 0), reverse=True)
    
    @classmethod
    def delete_session(cls, session_id: str) -> bool:
        """Delete a session file."""
        session_file = os.path.join(cls.SESSION_DIR, f"{session_id}.json")
        
        if os.path.exists(session_file):
            os.remove(session_file)
            logger.info(f"Session deleted: {session_id}")
            return True
        
        return False
    
    def finalize(self):
        """Finalize the session (mark as complete and optionally delete)."""
        self._paused = False
        self._save()
        
        # If fully complete, we can delete the session file
        if not self.pending_urls:
            try:
                os.remove(self.session_file)
                logger.info(f"Session completed and cleaned up: {self.session_id}")
            except IOError:
                pass
    
    def get_summary(self) -> str:
        """Get a summary string for the session."""
        total = len(self.completed_urls) + len(self.pending_urls)
        return (
            f"Session: {self.session_id}\n"
            f"Progress: {len(self.completed_urls)}/{total} URLs "
            f"({len(self.pending_urls)} remaining)\n"
            f"Findings: {len(self.findings)}"
        )
