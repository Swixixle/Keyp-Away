import os


def congress_url() -> str:
    return os.environ.get("CONGRESS_API_KEY")
