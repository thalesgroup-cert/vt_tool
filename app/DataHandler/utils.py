import os
import logging
from pathlib import Path
from typing import List, Optional, Literal, Union
from datetime import datetime, timezone  # for working with dates and times
from pytz import timezone as pytz_timezone

from rich.console import Console
from rich.prompt import Prompt, InvalidResponse
from rich.table import Table

console = Console()

ANALYSIS_OPTIONS = {
    "1": "IPs",
    "2": "Domains",
    "3": "URLs",
    "4": "Hashes"
}

ALL_ANALYSIS_TYPES = ["ips", "domains", "urls", "hashes"]

logger = logging.getLogger(__name__)

def utc2local(utc: Union[datetime, str]) -> datetime:
    """
    Convert UTC time to local time.

    Parameters:
    - utc (datetime | str): The UTC time to convert (can be a `datetime` or an ISO 8601 string).

    Returns:
    - datetime: The converted local time.
    """
    if isinstance(utc, str):
        utc = datetime.fromisoformat(utc)  # Allows ISO 8601 string input

    if not isinstance(utc, datetime):
        raise ValueError("Invalid input: utc must be a datetime object or ISO 8601 string.")

    return utc.replace(tzinfo=timezone.utc).astimezone(pytz_timezone("localtime"))


def get_api_key(api_key: Optional[str] = None, api_key_file: Optional[str] = None, env_var: str = "VTAPIKEY") -> str:
    """
    Retrieve the API key from the provided argument, a file, or an environment variable.

    Parameters:
    - api_key (Optional[str]): Directly provided API key.
    - api_key_file (Optional[str]): Path to a file containing the API key.
    - env_var (str): Environment variable name to retrieve the API key from (default: "VTAPIKEY").

    Returns:
    - str: The API key.

    Raises:
    - FileNotFoundError: If the specified API key file does not exist.
    - ValueError: If no API key is found.
    """

    if api_key:
        return api_key

    if api_key_file:
        key_path = Path(api_key_file)
        if key_path.is_file():
            return key_path.read_text(encoding="utf-8").strip()
        else:
            logger.error("API key file '%s' not found.", api_key_file)
            raise FileNotFoundError(f"API key file '{api_key_file}' not found.")

    env_api_key = os.getenv(env_var)
    if env_api_key:
        return env_api_key

    raise ValueError("No API key provided. Please specify an API key, a key file, or set the environment variable.")


def get_proxy(proxy: Optional[str] = None, env_var: str = "PROXY") -> str:
    """
    Retrieve the proxy from the provided argument or an environment variable.

    Parameters:
    - proxy (Optional[str]): Directly provided proxy.
    - env_var (str): Environment variable name to retrieve the proxy from (default: "PROXY").

    Returns:
    - str: The proxy.

    Raises:
    - ValueError: If no proxy is found.
    """

    if proxy:
        return proxy

    env_proxy = os.getenv(env_var)
    if env_proxy:
        return env_proxy

    logger.error("No proxy provided. Please specify a proxy or set the environment variable.")


def display_menu() -> str:
    """
    Display the analysis type menu and get user selection.

    Returns:
    - str: The selected option key.
    """
    table = Table(title="Analysis Types", title_style="bold yellow")
    table.add_column("Key", justify="center", style="cyan", no_wrap=True)
    table.add_column("Type", justify="center", style="magenta")

    for key, value in ANALYSIS_OPTIONS.items():
        table.add_row(key, value)

    console.print(table)

    choice = Prompt.ask(
        "[bold green]Select an option[/bold green]",
        choices=ANALYSIS_OPTIONS.keys(),
        default="1"
    )

    return choice


def get_initial_choice() -> Literal["y", "n"]:
    """
    Get the initial choice from the user.

    Returns:
    - Literal["y", "n"]: The user's choice ('y' for yes, 'n' for no).
    """
    choice = Prompt.ask(
        "[bold green]Do you want to analyze a specific type? (y/n)[/bold green]",
        choices=["y", "n", "yes", "no"],
        default="n",
    ).strip().lower()

    return "y" if choice in {"y", "yes"} else "n"


def get_analysis_type() -> Literal["ips", "domains", "urls", "hashes"]:
    """
    Get the analysis type from the user.

    Returns:
    - Literal["ips", "domains", "urls", "hashes"]: The selected analysis type.
    """
    choice = display_menu()

    return ANALYSIS_OPTIONS[choice].lower()


def get_user_choice() -> List[Literal["ips", "domains", "urls", "hashes"]]:
    """
    Get the user's choice and return the selected analysis types.

    Returns:
    - List[Literal["ips", "domains", "urls", "hashes"]]: The selected analysis types.
    """
    try:
        return [get_analysis_type()] if get_initial_choice() == "y" else ALL_ANALYSIS_TYPES
    except InvalidResponse:
        console.print("[bold red]Invalid response. Defaulting to all types.[/bold red]")
        return ALL_ANALYSIS_TYPES
