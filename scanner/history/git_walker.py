import subprocess
import os
import re
from typing import List, Dict, Any, Set, Tuple

class GitCommit:
    def __init__(self, commit_hash: str, parents: List[str], author: str, email: str, timestamp: int, message: str):
        self.hash = commit_hash
        self.parents = parents
        self.author = author
        self.email = email
        self.timestamp = timestamp
        self.message = message

class GitOccurrence:
    def __init__(self, commit_hash: str, file_path: str, line_number: int, change_type: str, line_content: str):
        self.commit_hash = commit_hash
        self.file_path = file_path
        self.line_number = line_number
        self.change_type = change_type  # 'ADDED' or 'DELETED'
        self.line_content = line_content

class GitWalker:
    def __init__(self, repo_path: str):
        self.repo_path = os.path.abspath(repo_path)

    def _run_git(self, args: List[str]) -> str:
        """Run a git command in the repository path and return its stdout."""
        try:
            result = subprocess.run(
                ["git"] + args,
                cwd=self.repo_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=True
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            # Handle Git errors gracefully
            return ""
        except FileNotFoundError:
            raise RuntimeError("Git executable not found on system path.")

    def is_git_repo(self) -> bool:
        """Check if the path is a valid Git repository."""
        if not os.path.isdir(self.repo_path):
            return False
        res = self._run_git(["rev-parse", "--is-inside-work-tree"])
        return res.strip() == "true"

    def get_commits(self, deep_history: bool = False) -> List[GitCommit]:
        """
        Get all commits in chronological order (oldest first).
        If deep_history is True, also scan unreachable commits and reflogs.
        """
        if not self.is_git_repo():
            return []

        # Format: hash | parents | author | email | timestamp | message
        sep = "__ST_SEP__"
        log_format = f"%H{sep}%P{sep}%an{sep}%ae{sep}%at{sep}%s"
        
        # Get reachable commits
        stdout = self._run_git(["log", "--all", "--reverse", f"--pretty=format:{log_format}"])
        commits = self._parse_log_output(stdout, sep)
        
        if not deep_history:
            return commits

        # Set of already parsed commit hashes
        seen_hashes = {c.hash for c in commits}
        all_commits = commits.copy()

        # Add commits from reflogs
        reflog_stdout = self._run_git(["log", "-g", "--all", "--reverse", f"--pretty=format:{log_format}"])
        reflog_commits = self._parse_log_output(reflog_stdout, sep)
        for c in reflog_commits:
            if c.hash not in seen_hashes:
                seen_hashes.add(c.hash)
                all_commits.append(c)

        # Add unreachable commits from fsck
        fsck_stdout = self._run_git(["fsck", "--unreachable", "--no-reflogs"])
        unreachable_hashes = []
        for line in fsck_stdout.splitlines():
            if "unreachable commit" in line:
                parts = line.split()
                if len(parts) >= 3:
                    unreachable_hashes.append(parts[2])

        if unreachable_hashes:
            # Get metadata for unreachable commits
            # We fetch them in batches or individually
            for h in unreachable_hashes:
                if h in seen_hashes:
                    continue
                c_stdout = self._run_git(["show", "--no-patch", f"--pretty=format:{log_format}", h])
                c_list = self._parse_log_output(c_stdout, sep)
                if c_list:
                    c = c_list[0]
                    seen_hashes.add(c.hash)
                    all_commits.append(c)

        # Sort commits chronologically by timestamp
        all_commits.sort(key=lambda x: x.timestamp)
        return all_commits

    def _parse_log_output(self, stdout: str, sep: str) -> List[GitCommit]:
        commits = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(sep)
            if len(parts) >= 6:
                commit_hash = parts[0]
                parents = parts[1].split() if parts[1] else []
                author = parts[2]
                email = parts[3]
                try:
                    timestamp = int(parts[4])
                except ValueError:
                    timestamp = 0
                message = parts[5]
                commits.append(GitCommit(commit_hash, parents, author, email, timestamp, message))
        return commits

    def get_commit_diff_occurrences(self, commit_hash: str) -> List[GitOccurrence]:
        """
        Get all occurrences of added and deleted lines in a commit's diff.
        Parses hunk headers to track correct line numbers.
        """
        # Run git show with 0 context lines to only see exact edits
        stdout = self._run_git(["show", "-U0", "--no-notes", "--pretty=format:", commit_hash])
        
        occurrences = []
        current_file = ""
        
        old_line_cursor = 0
        new_line_cursor = 0
        
        # Regex for hunk headers: @@ -old_start[,old_count] +new_start[,new_count] @@
        hunk_pattern = re.compile(r'^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@')
        
        for line in stdout.splitlines():
            # Check for file path headers
            if line.startswith("+++ b/"):
                current_file = line[6:]
                continue
            elif line.startswith("--- a/") and not current_file:
                # In case file is deleted, use a/ path
                current_file = line[6:]
                continue
            elif line.startswith("+++ ") or line.startswith("--- "):
                # Skip other headers or binary indicators
                continue
            
            # Check for hunk headers
            match = hunk_pattern.match(line)
            if match:
                old_start = int(match.group(1))
                new_start = int(match.group(3))
                old_line_cursor = old_start
                new_line_cursor = new_start
                continue
            
            # If we haven't identified a file yet, skip
            if not current_file:
                continue
                
            # Parse diff contents
            if line.startswith("+"):
                # Line added
                content = line[1:]
                occurrences.append(GitOccurrence(
                    commit_hash=commit_hash,
                    file_path=current_file,
                    line_number=new_line_cursor,
                    change_type="ADDED",
                    line_content=content
                ))
                new_line_cursor += 1
            elif line.startswith("-"):
                # Line deleted
                content = line[1:]
                occurrences.append(GitOccurrence(
                    commit_hash=commit_hash,
                    file_path=current_file,
                    line_number=old_line_cursor,
                    change_type="DELETED",
                    line_content=content
                ))
                old_line_cursor += 1
                
        return occurrences

    def get_current_working_tree_occurrences(self) -> List[GitOccurrence]:
        """
        Scans all files in the current working tree and returns them as "ADDED" occurrences in a mock commit "WORKING_TREE".
        This helps run current tree scans.
        """
        occurrences = []
        # Get list of files tracked by git
        stdout = self._run_git(["ls-files"])
        files = [f.strip() for f in stdout.splitlines() if f.strip()]
        
        for file_path in files:
            full_path = os.path.join(self.repo_path, file_path)
            if not os.path.isfile(full_path):
                continue
            # Read file lines
            try:
                with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                    for idx, line in enumerate(f, 1):
                        occurrences.append(GitOccurrence(
                            commit_hash="WORKING_TREE",
                            file_path=file_path,
                            line_number=idx,
                            change_type="ADDED",
                            line_content=line.rstrip("\r\n")
                        ))
            except Exception:
                # Skip files we cannot read (e.g. binary)
                continue
        return occurrences
