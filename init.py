from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table

from app.VirusTotal.vt_reporter import VTReporter
from app.VirusTotal.vt_client import VirusTotalClient
from app.DataHandler.validator import DataValidator
from app.DBHandler.db_handler import DBHandler
from app.FileHandler.output_to_file import OutputHandler

console = Console()

class Initializator:
    """
    Initializes and manages components for VirusTotal data handling.

    Attributes:
        api_key (str): VirusTotal API key.
        proxy (str, optional): Proxy for API requests.
        case_num (str, optional): Case identifier for logging/output.
        client (VirusTotalClient): VirusTotal client instance.
        reporter (VTReporter): Handles VirusTotal reporting.
        validator (DataValidator): Validates input data.
        output (OutputHandler): Manages output file handling.
        db_handler (DBHandler): Manages database interactions.
    """

    def __init__(self, api_key: str, proxy: str = None, case_num: str = None):
        self.api_key = api_key
        self.proxy = proxy
        self.case_num = case_num

        self.client = self._init_client()
        self.reporter = VTReporter(self.client)
        self.validator = DataValidator()
        self.output = OutputHandler(self.case_num)
        self.db_handler = DBHandler()
        
        self._display_info(self.client, self.reporter, self.validator, self.output, self.db_handler)

    def _init_client(self):
        """Initializes the VirusTotal client."""
        return VirusTotalClient(self.api_key, self.proxy).init_client()

    def _display_info(self, client, reporter, validator, output, db_handler):
        """Displays information about the initialized components with a clear UI."""
        
        # Title panel
        console.print(Panel(Text("Initialized Components", style="bold magenta"), expand=False))

        # Define components and statuses
        components = {
            "VirusTotal Client": client,
            "VirusTotal Reporter": reporter,
            "Data Validator": validator,
            "Output Handler": output,
            "Database Handler": db_handler
        }

        # Create a table for structured display
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Component", style="bold white")
        table.add_column("Status", justify="center", style="bold")

        # Populate the table with component statuses
        for name, status in components.items():
            status_text = "[green]✅ Initialized[/green]" if status else "[red]❌ Not initialized[/red]"
            table.add_row(name, status_text)

        console.print(table)

        # Completion message
        console.print(Panel(Text("Initialization Complete ✅", style="bold green"), expand=False))
