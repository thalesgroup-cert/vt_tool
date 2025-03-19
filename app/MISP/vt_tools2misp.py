import csv
import logging
import os
import re
import warnings
from typing import List, Dict, Optional

from pymisp import ExpandedPyMISP, MISPEvent, MISPObject
from rich.console import Console
from rich.prompt import Prompt

console = Console()


# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def get_misp_event(misp: ExpandedPyMISP, case_str: str) -> MISPEvent:
    """
    Retrieve an existing MISP event by case string or create a new event if not found.

    Parameters:
        misp (ExpandedPyMISP): The MISP instance.
        case_str (str): The case string used to identify the event.

    Returns:
        MISPEvent: The MISP event associated with the case.
    """
    try:
        # Attempt to get the event by case_str
        event = misp.get_event(case_str)
        console.print(f"[bold green]Successfully fetched MISP event: {case_str}[/bold green]")

    except Exception as e:
        # Log the error and proceed to create a new event
        console.print(f"[bold red]Failed to get MISP event for {case_str}: {e}[/bold red]")
        logging.error(f"Failed to get MISP event for {case_str}: {e}")
        console.print("[bold yellow]Creating a new MISP event...[/bold yellow]")

        # Create a new MISP event
        event = misp.new_event(info="VirusTotal Report")

    # Load and return the event into MISPEvent object
    try:
        misp_event_obj = MISPEvent()
        misp_event_obj.load(event)
        return misp_event_obj
    except Exception as e:
        console.print(f"[bold red]Failed to load MISP event: {e}[/bold red]")
        logging.error(f"Failed to load MISP event: {e}")
        raise RuntimeError(f"Unable to load MISP event for {case_str}") from e


def process_csv_file(csv_file: str) -> list:
    """
    Process data from a CSV file and return the data as a list of dictionaries.

    Parameters:
        csv_file (str): The path to the CSV file.

    Returns:
        list: A list of dictionaries representing the rows in the CSV file.

    Raises:
        FileNotFoundError: If the CSV file is not found.
        csv.Error: If there is an issue with the CSV format.
    """
    data = []

    try:
        with open(csv_file, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f, delimiter=",")
            for row in reader:
                data.append(row)
            console.print(f"[bold green]Successfully processed {len(data)} rows from {csv_file}[/bold green]")
    except FileNotFoundError:
        console.print(f"[bold red]Error: The file '{csv_file}' was not found.[/bold red]")
        logging.error(f"File not found: {csv_file}")
    except csv.Error as e:
        console.print(f"[bold red]CSV Error: {e}[/bold red]")
        logging.error(f"CSV Error: {e}")
    except Exception as e:
        console.print(f"[bold red]Unexpected error: {e}[/bold red]")
        logging.error(f"Unexpected error processing {csv_file}: {e}")

    return data


def get_attribute_mapping(headers: List[str], attribute_type_mapping: Dict[str, str]) -> Dict[str, str]:
    """
    Get the attribute mapping based on CSV headers and a provided attribute-to-type mapping.

    Parameters:
        headers (List[str]): A list of headers from the CSV.
        attribute_type_mapping (Dict[str, str]): A dictionary mapping attribute names to types.

    Returns:
        Dict[str, str]: A dictionary where the keys are headers found in the CSV and
                        the values are their corresponding attribute types.

    Raises:
        ValueError: If no valid attribute mappings are found in the headers.
    """
    attribute_mapping = {}

    # Loop through headers and find matching attribute types
    for header in headers:
        if header in attribute_type_mapping:
            attribute_mapping[header] = attribute_type_mapping[header]
        else:
            logging.warning(f"Header '{header}' not found in attribute_type_mapping.")

    # Raise an error if no valid mappings were found
    if not attribute_mapping:
        raise ValueError("No valid attribute mappings were found based on the provided headers.")

    logging.info(f"Successfully mapped {len(attribute_mapping)} attributes.")

    return attribute_mapping


def load_template(template_file: str) -> Dict[str, Dict[str, List[str]]]:
    """
    Load and process the template file.

    Parameters:
        template_file (str): Path to the CSV template file.

    Returns:
        Dict[str, Dict[str, List[str]]]: Processed template data indexed by 'value'.
    """
    template_object = {}

    try:
        with open(template_file, newline='', encoding='utf-8') as file:
            reader = csv.reader(file)
            headers = next(reader, None)  # Read header row

            if not headers:
                console.print(f"[bold red]Error: Template file '{template_file}' is empty.[/bold red]")
                return {}

            if "value" not in headers:
                console.print(f"[bold red]Error: 'value' column missing in template file '{template_file}'.[/bold red]")
                return {}

            value_index = headers.index("value")

            for row_idx, row in enumerate(reader, start=1):
                if len(row) != len(headers):
                    console.print(f"[bold red]Error: Row {row_idx} in '{template_file}' has incorrect column count: {row}[/bold red]")
                    continue

                key = row[value_index]  # Extract the primary key

                for idx, header in enumerate(headers):
                    if header == "value":
                        continue
                    template_object.setdefault(key, {}).setdefault(header, []).append(row[idx])

    except FileNotFoundError:
        console.print(f"[bold red]Error: Template file '{template_file}' not found.[/bold red]")
    except Exception as e:
        console.print(f"[bold red]Error loading template file '{template_file}': {e}[/bold red]")

    return template_object


def apply_template_data(data: List[Dict[str, str]], template_object: Dict[str, Dict[str, List[str]]], template_key: str) -> None:
    """
    Apply template data to the main dataset.

    Parameters:
        data (List[Dict[str, str]]): List of dictionaries representing rows of CSV data.
        template_object (Dict[str, Dict[str, List[str]]]): Loaded template data.
        template_key (str): The key used to match data with the template.
    """
    for row in data:
        key_value = row.get(template_key)
        if key_value and key_value in template_object:
            for key, values in template_object[key_value].items():
                row[key] = values[0] if len(values) == 1 else values  # Store as single value or list


def create_misp_object(row: Dict[str, str], object_name: str, attribute_mapping: Dict[str, List[str]]) -> Optional[MISPObject]:
    """
    Create a MISP object from a data row.

    Parameters:
        row (Dict[str, str]): A dictionary representing a single row of CSV data.
        object_name (str): The name of the MISP object to be created.
        attribute_mapping (Dict[str, List[str]]): A dictionary mapping CSV headers to MISP attribute details.

    Returns:
        Optional[MISPObject]: The created MISP object, or None if failed.
    """
    try:
        misp_object = MISPObject(name=object_name)
        misp_object.comment = row.get("comment", "")

        for key, value in row.items():
            if key in attribute_mapping:
                attr_details = attribute_mapping[key]

                if len(attr_details) != 4:
                    raise ValueError(f"Attribute mapping for '{key}' is incomplete (should contain 4 details).")

                attribute_type, attr_type, category, to_ids = attr_details
                misp_object.add_attribute(
                    attribute_type,
                    value=value,
                    type=attr_type,
                    category=category,
                    to_ids=attribute_type in ["ip", "url", "sha256", "md5", "sha1", "ssdeep", "tlsh"],
                    disable_correlation=not (attribute_type in ["ip", "url", "sha256", "md5", "sha1", "ssdeep", "tlsh"])
                )

        return misp_object

    except Exception as e:
        console.print(f"[bold red]Failed to create MISP object from row: {row}. Error: {e}[/bold red]")
        return None


def create_misp_objects_from_csv(
    data: List[Dict[str, str]],
    object_name: str,
    attribute_mapping: Dict[str, List[str]],
    template_file: Optional[str] = None,
    template: Optional[str] = None
) -> List[MISPObject]:
    """
    Create MISP objects from CSV data and attribute mapping.

    Parameters:
        data (List[Dict[str, str]]): List of dictionaries representing rows of CSV data.
        object_name (str): The name of the MISP object to be created.
        attribute_mapping (Dict[str, List[str]]): A dictionary mapping CSV headers to MISP attribute details.
        template_file (Optional[str]): Path to the template CSV file.

    Returns:
        List[MISPObject]: A list of MISP objects created from the data.
    """
    misp_objects = []

    # Define expected mapping keys
    patterns = {
        "file": "hash",
        "url": "url",
        "ip-port": "ip",
        "domain": "domain"
    }

    template_key = patterns.get(object_name)
    if not template_key:
        console.print(f"[bold red]Error: Unsupported object name '{object_name}'.[/bold red]")
        return []

    # Load and apply template data if a template file is provided
    template_object = load_template(template_file) if template_file else {}
    if template_object:
        apply_template_data(data, template_object, template_key)

    # Process each row to create MISP objects
    for row_idx, row in enumerate(data):
        misp_object = create_misp_object(row, object_name, attribute_mapping)
        if misp_object:
            misp_objects.append(misp_object)

    if not misp_objects:
        console.print("[bold yellow]Warning: No valid MISP objects were created.[/bold yellow]")

    return misp_objects


def identify_object_type(csv_file: str) -> str:
    """
    Get the MISP object name based on the CSV file name.

    Parameters:
        csv_file (str): The name of the CSV file.

    Returns:
        str: The MISP object name based on the CSV file name.

    Raises:
        ValueError: If the CSV file name does not match any known patterns.
    """
    # Define a list of patterns and corresponding object names
    patterns = [
        (r"Hash", "file"),
        (r"URL", "url"),
        (r"IP", "ip-port"),
        (r"Domain", "domain")
    ]

    # Search the CSV file name for each pattern
    for pattern, misp_object_name in patterns:
        if re.search(pattern, csv_file, re.IGNORECASE):
            return misp_object_name

    # If no matches found, raise an exception
    raise ValueError(f"Unknown CSV file format: '{csv_file}'. Could not determine MISP object name.")


def process_and_submit_to_misp(misp, case_str, csv_files_created, template_file, template) -> None:
    """
    Process CSV files and submit data to MISP.

    Parameters:
        misp: An instance of the MISP object.
        case_str (str): The case identifier string.
        csv_files_created (List[str]): List of CSV files that were created for submission.
    """
    # Get or create MISP event
    misp_event = get_misp_event(misp, case_str)
    console.print(f"[bold]Using MISP event {misp_event.id} for submission[/bold]")

    if not csv_files_created:
        console.print("[bold red]No CSV files found for processing![/bold red]")
        return

    console.print("[bold]Processing CSV files and submitting data to MISP...[/bold]")

    # Attribute type mappings for different CSV structures
    attribute_type_mapping = {
        "file": {
            "sha256": ("sha256", "sha256", "Payload delivery", False),
            "sha1": ("sha1", "sha1", "Payload delivery", False),
            "md5": ("md5", "md5", "Payload delivery", False),
            "ssdeep": ("ssdeep", "ssdeep", "Payload delivery", False),
            "tlsh": ("tlsh", "tlsh", "Payload delivery", False),
            "size": ("size", "size-in-bytes", "Payload delivery", False),
            "meaningful_name": ("filename", "text", "Payload delivery", False),
        },
        "domain": {
            "creation_date": ("creation_date", "datetime", "Network activity", False),
            "reputation": ("reputation", "text", "External analysis", False),
            "whois": ("whois", "text", "External analysis", False),
            "info": ("info", "text", "Other", False),
        },
        "url": {
            "url": ("url", "url", "Network activity", False),
            "title": ("title", "text", "Other", False),
            "final_url": ("final_url", "url", "Network activity", False),
            "first_scan": ("first_scan", "datetime", "Other", False),
            "info": ("info", "text", "Other", False),
        },
        "ip-port": {
            "ip": ("ip", "ip-dst", "Network activity", False),
            "owner": ("owner", "text", "Other", False),
            "location": ("location", "text", "Other", False),
            "network": ("network", "text", "Other", False),
            "https_certificate": ("https_certificate", "text", "External analysis", False),
            "info-ip": ("info-ip", "text", "Other", False),
        },
        "general": {
            "malicious_score": ("malicious_score", "text", "Antivirus detection", False),
            "link": ("link", "link", "External analysis", False),
        }
    }

    # Iterate over each created CSV file and process it
    for csv_file in csv_files_created:
        console.print(f"[bold]Processing CSV file: {csv_file}[/bold]")

        try:
            data = process_csv_file(csv_file)  # Process the CSV file and extract data
            if not data:
                console.print(f"[bold yellow]No data found in {csv_file}[/bold yellow]")
                continue

            object_type = identify_object_type(csv_file)
            if not object_type:
                console.print(f"[bold red]Unknown data format in {csv_file}, skipping...[/bold red]")
                continue

            console.print(f"[bold green]Detected format: {object_type}[/bold green]")

            # Map attributes based on object type
            attribute_mapping = attribute_type_mapping[object_type].copy()
            attribute_mapping.update(attribute_type_mapping["general"])

            # Create MISP objects from the CSV data
            misp_objects = create_misp_objects_from_csv(data, object_type, attribute_mapping, template_file, template)

            # Submit objects to MISP event
            submit_misp_objects(misp, misp_event, misp_objects)

        except Exception as e:
            console.print(f"[bold red]Failed to process CSV file '{csv_file}': {e}[/bold red]")
            continue

    console.print("[bold green]All CSV files processed and submitted successfully![/bold green]")


def submit_misp_objects(misp, misp_event, misp_objects) -> None:
    """
    Submit a list of MISP objects to a MISP event.

    Parameters:
        misp: An instance of the MISP object.
        misp_event: The MISP event to which objects will be added.
        misp_objects: List of MISP objects to be submitted.
    """
    if not misp_objects:
        console.print("[bold yellow]No MISP objects to submit.[/bold yellow]")
        return

    console.print(f"[bold]Submitting {len(misp_objects)} MISP objects to event {misp_event.id}...[/bold]")

    # Loop through and submit each MISP object
    for misp_object in misp_objects:
        try:
            # Attempt to add the object to the MISP event
            misp.add_object(misp_event.id, misp_object)
            console.print(f"[bold green]Successfully added MISP object {misp_object.name}[/bold green]")
        except Exception as e:
            console.print(f"[bold red]Failed to add MISP object {misp_object.name}: {e}[/bold red]")
            logging.error(f"Failed to add MISP object {misp_object.name}: {e}")

    try:
        # Update the event after adding all objects
        misp.update_event(misp_event)
        console.print(f"[bold green]MISP event {misp_event.id} updated successfully.[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Failed to update MISP event: {e}[/bold red]")
        logging.error(f"Failed to update MISP event: {e}")


def misp_event(case_str, csvfilescreated, template_file, template) -> None:
    """
    Initialize MISP connection and start the process of sending data to MISP.

    Parameters:
        case_str: Case identifier or name for which MISP event will be created.
        csvfilescreated: List of created CSV files to be processed and submitted to MISP.
    """
    # Disable warnings from the VirusTotal API and related PyMISP warnings
    warnings.filterwarnings("ignore")
    warnings.filterwarnings(
        "ignore",
        category=UserWarning,
        message="The template .* doesn't have the object_relation .*",
    )

    # Set logging levels to suppress unnecessary output
    logging.getLogger("Python").setLevel(logging.CRITICAL)
    logging.getLogger().setLevel(logging.CRITICAL)

    try:
        # Prompt for MISP key and URL if they are not set as environment variables
        console.print("[bold]Initializing MISP connection...[/bold]")
        misp_key = os.getenv("MISPKEY")
        misp_url = os.getenv("MISPURL")

        if not misp_key:
            misp_key = Prompt.ask("[bold]Enter your MISP key[/bold]")
        if not misp_url:
            misp_url = Prompt.ask("[bold]Enter your MISP URL[/bold]")

        # Establish MISP connection
        misp = ExpandedPyMISP(misp_url, misp_key, False)
        console.print("[bold green]MISP connection established successfully.[/bold green]")

        # Process and submit data to MISP
        process_and_submit_to_misp(misp, case_str, csvfilescreated,template_file, template)

    except KeyboardInterrupt:
        console.print("[bold red]Exiting...[/bold red]")  # Graceful exit on Ctrl+C
    except Exception as e:
        console.print(f"[bold red]An error occurred while initializing MISP: {e}[/bold red]")
        console.print("[bold red]Exiting...[/bold red]")


def misp_choice_template(case_str, csvfilescreated, template_file, template):
    """
    Ask the user if they want to send the results to MISP and proceed accordingly.

    Parameters:
        case_str: Case identifier for the MISP event.
        csvfilescreated: List of CSV files to be processed and submitted.
    """
    try:
        # Prompt the user for a decision
        console.print("[bold]Do you want to send the results to MISP?[/bold]")
        console.print("- Yes (1, Y, yes)")
        console.print("- No (2, N, no)")

        # Get the user's input
        choice = Prompt.ask("[bold]Enter your choice[/bold]").strip().lower()

        # Handle user choice for Yes
        if choice in ["1", "y", "yes"]:
            if case_str == "000000":
                # If the case ID is '000000', ask for a valid MISP event ID
                case_str = Prompt.ask("[bold]Please enter the MISP event ID[/bold]")

            # Proceed with MISP processing and submission
            misp_event(case_str, csvfilescreated, template_file,template)

        # Handle user choice for No
        elif choice in ["2", "n", "no"]:
            console.print("[bold yellow]MISP event not created.[/bold yellow]")

        # Invalid input handling
        else:
            console.print("[bold red]Invalid choice. Please enter a valid option.[/bold red]")
            misp_choice_template(case_str, csvfilescreated, template_file, template)  # Recursively prompt until valid input

    except KeyboardInterrupt:
        console.print("[bold red]Exiting...[/bold red]")  # Graceful exit on keyboard interrupt
    except Exception as e:
        console.print(f"[bold red]An error occurred: {e}[/bold red]")  # Catch unexpected errors
        console.print("[bold red]Exiting...[/bold red]")


def misp_choice(case_str: str, csvfilescreated: list) -> None:
    """
    Ask the user if they want to send the results to MISP and proceed accordingly.

    Parameters:
        case_str: Case identifier for the MISP event.
        csvfilescreated: List of CSV files to be processed and submitted.
    """
    try:
        # Prompt the user for a decision
        console.print("[bold]Do you want to send the results to MISP?[/bold]")
        console.print("- Yes (1, Y, yes)")
        console.print("- No (2, N, no)")

        # Get the user's input
        choice = Prompt.ask("[bold]Enter your choice[/bold]").strip().lower()

        # Handle user choice for Yes
        if choice in ["1", "y", "yes"]:
            if case_str == "000000":
                # If the case ID is '000000', ask for a valid MISP event ID
                case_str = Prompt.ask("[bold]Please enter the MISP event ID[/bold]")

            # Proceed with MISP processing and submission
            misp_event(case_str, csvfilescreated, None, None)

        # Handle user choice for No
        elif choice in ["2", "n", "no"]:
            console.print("[bold yellow]MISP event not created.[/bold yellow]")

        # Invalid input handling
        else:
            console.print("[bold red]Invalid choice. Please enter a valid option.[/bold red]")
            misp_choice(case_str, csvfilescreated)  # Recursively prompt until valid input

    except KeyboardInterrupt:
        console.print("[bold red]Exiting...[/bold red]")  # Graceful exit on keyboard interrupt
    except Exception as e:
        console.print(f"[bold red]An error occurred: {e}[/bold red]")  # Catch unexpected errors
        console.print("[bold red]Exiting...[/bold red]")
