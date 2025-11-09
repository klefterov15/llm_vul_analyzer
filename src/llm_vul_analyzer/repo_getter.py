#from git import Repo
#from datetime import datetime
from dataclasses import dataclass
from git_utils.repo_read import prepare_repo
import os

#DATE_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S%z"
EMPTY_TREE_SHA   = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
# Dataclass which will contain every commit :
@dataclass(slots=True)
class GitCommit:
    commit_hash: str
    message: str
    author: str


# Dataclass for storing every diff info from each commit
@dataclass(slots=True)
class FileChange:
    file_path: str
    commit_hash: str
    diff_content: str

# A class for the commit extraction of the repo
class GitCommitExtractor:
    def __init__(self, repo_url_or_path: str, base_dir: str = "scanned_repos"):
        self.commits = []
        self.file_changes = []
        self.repo = prepare_repo(repo_url_or_path, base_dir)

    def extract(self, repo_path, num_commits):
        """
        extract gets all commits and diff from a git repository.
        The program only supports commits with only one parent.
        All other commits are ignored.
        """
        # obtain repository
        repo = self.repo
        # traverse through N last commits from repo starting from the head one
        for commit in repo.iter_commits(rev= 'HEAD', max_count=num_commits ) :
            # add the commit
            git_commit = GitCommit(
                commit_hash = commit.hexsha,
                message = commit.message,
                author = commit.author.name,
            )
            self.commits.append(git_commit)

            #check if commit is initial or has more than one parent
            if len(commit.parents) == 0:    parent = EMPTY_TREE_SHA
            elif len(commit.parents) == 1:  parent = commit.parents[0]
            else :                          continue

            diffs = {diff.a_path: diff for diff in commit.diff(parent, create_patch = True)}
            for objpath, stats in commit.stats.files.items():
                diff = diffs.get(objpath)

                if not diff:
                    for diff in diffs.values():
                        if diff.b_path == objpath and diff.renamed_file:
                            break


                if diff is None:
                    continue

                commit_diff = FileChange(
                    file_path = objpath,
                    commit_hash = commit.hexsha,
                    diff_content= diff.diff.decode("utf-8", errors = "ignore")
                )
                self.file_changes.append(commit_diff)


        print (f"Found {len(self.commits)} commits, {len(self.file_changes)} files changed")
        return self.commits, self.file_changes