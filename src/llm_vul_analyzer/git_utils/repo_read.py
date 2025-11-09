import os
from git import Repo, InvalidGitRepositoryError, NoSuchPathError

def _derive_local_path(repo_url_or_path: str, base_dir: str = "repos") -> str:
    """
    If repo_url_or_path is URL, derive a folder inside base_dir.
    If it is already a local path, return it.
    """
    if repo_url_or_path.startswith(("http://","https://","git@")):
        # strip trailing .git and take last path component
        name = repo_url_or_path.rstrip("/").rsplit("/", 1)[-1]
        if name.endswith(".git"):
            name = name[:-4]
        local_folder = os.path.join(base_dir, name)
    else:
        local_folder = repo_url_or_path
    return local_folder

def prepare_repo(repo_url_or_path: str, base_dir: str = "scanned_repos") -> Repo:
    """
    prepare_repo ensures that the git repository is ready for commit and diff extraction.
    """
    local_path = _derive_local_path(repo_url_or_path, base_dir)
    # Ensure directory exists / make parent folders
    os.makedirs(os.path.dirname(local_path), exist_ok=True)
    # Continue with open or clone logic her
    try:
        repo = Repo(local_path)
        if repo.bare:
            raise InvalidGitRepositoryError(local_path)
        print(f"Using existing repo at {local_path}")
        return repo
    except (InvalidGitRepositoryError, NoSuchPathError):
        print(f"Cloning {repo_url_or_path} into {local_path}")
        repo = Repo.clone_from(repo_url_or_path, local_path)
        print("Clone complete.")
        return repo