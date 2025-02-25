import csv
import logging
import os
import re
import warnings
from typing import List, Dict

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


def create_misp_objects_from_csv(data: List[Dict[str, str]], object_name: str, attribute_mapping: Dict[str, List[str]]) -> List[MISPObject]:
    """
    Create MISP objects from CSV data and attribute mapping.

    Parameters:
        data (List[Dict[str, str]]): List of dictionaries representing rows of CSV data.
        object_name (str): The name of the MISP object to be created.
        attribute_mapping (Dict[str, List[str]]): A dictionary mapping CSV headers to MISP attribute details.

    Returns:
        List[MISPObject]: A list of MISP objects created from the data.

    Raises:
        ValueError: If the attribute mapping is incorrect or missing required details.
    """
    misp_objects = []

    # Loop through each row in the data
    for row_idx, row in enumerate(data):
        try:
            misp_object = MISPObject(name=object_name)

            # Loop through each field in the row
            for key, value in row.items():
                try:
                    # Check if the key exists in the attribute mapping
                    if key in attribute_mapping:
                        attr_details = attribute_mapping[key]

                        if len(attr_details) != 4:
                            raise ValueError(f"Attribute mapping for '{key}' is incomplete (should contain 4 details).")

                        # Ensure fields correlate with correct attributes
                        attribute_type = attr_details[0]
                        attribute_value = value
                        attribute_category = attr_details[2]
                        to_ids = attr_details[3]
                        disable_correlation = True if len(attr_details) > 3 else False

                        # Adding MISP attribute based on type
                        if attribute_type in ["ip", "url", "sha256", "md5", "sha1", "ssdeep", "tlsh"]:
                            misp_object.add_attribute(
                                attribute_type,
                                value=attribute_value,
                                type=attr_details[1],
                                category=attribute_category,
                                to_ids=True,
                                disable_correlation=False,
                            )
                        else:
                            misp_object.add_attribute(
                                attribute_type,
                                value=attribute_value,
                                type=attr_details[1],
                                category=attribute_category,
                                to_ids=to_ids,
                                disable_correlation=disable_correlation,
                            )

                except Exception as e:
                    console.print(f"[bold red]Failed to add attribute '{key}' to MISP object (Row {row_idx+1}): {e}[/bold red]")

            misp_objects.append(misp_object)

        except Exception as e:
            console.print(f"[bold red]Failed to create MISP object for Row {row_idx+1}: {e}[/bold red]")

    if not misp_objects:
        console.print("[bold yellow]No valid MISP objects were created.[/bold yellow]")

    return misp_objects


def get_misp_object_name(csv_file: str) -> str:
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


def process_and_submit_to_misp(misp, case_str: str, csv_files_created: List[str]) -> None:
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

    # Define the attribute type mapping for the CSV data
    attribute_type_mapping = {
        "ip": ("ip", "ip-dst", "Network activity", False, ["tlp:green"]),
        "malicious_score": ("malicious_score", "text", "Antivirus detection", False, ["tlp:white"]),
        "owner": ("owner", "text", "Other", False, ["tlp:white"]),
        "location": ("location", "text", "Other", False, ["tlp:white"]),
        "network": ("network", "text", "Other", False, ["tlp:white"]),
        "https_certificate": ("https_certificate", "text", "Other", False, ["tlp:white"]),
        "info-ip": ("info-ip", "text", "Other", False, ["tlp:white"]),
        "link": ("link", "link", "External analysis", False, ["tlp:white"]),
        "url": ("url", "url", "Network activity", False, ["tlp:green"]),
        "title": ("title", "text", "Other", False, ["tlp:white"]),
        "final_Url": ("final_Url", "text", "Other", False, ["tlp:white"]),
        "meaningful_name": ("filename", "text", "Other", False, ["tlp:white"]),
        "first_scan": ("first_scan", "datetime", "Other", False, ["tlp:white"]),
        "info": ("info", "text", "Other", False, ["tlp:white"]),
        "sha256": ("sha256", "sha256", "Payload delivery", False, ["tlp:green"]),
        "md5": ("md5", "md5", "Payload delivery", False, ["tlp:white"]),
        "sha1": ("sha1", "sha1", "Payload delivery", False, ["tlp:white"]),
        "ssdeep": ("ssdeep", "ssdeep", "Payload delivery", False, ["tlp:white"]),
        "tlsh": ("tlsh", "tlsh", "Payload delivery", False, ["tlp:white"]),
        "size": ("size", "size-in-bytes", "Payload delivery", False, ["tlp:white"]),
    }

    # Iterate over each created CSV file and process it
    for csv_file in csv_files_created:
        console.print(f"[bold]Processing CSV file: {csv_file}[/bold]")

        try:
            # Process the CSV file and extract data
            data = process_csv_file(csv_file)
            if not data:
                console.print(f"[bold yellow]No data found in {csv_file}[/bold yellow]")
                continue

            # Get headers and determine the attribute mapping
            headers = data[0].keys()
            attribute_mapping = get_attribute_mapping(headers, attribute_type_mapping)

            # Determine the object name based on the CSV file name
            object_name = get_misp_object_name(csv_file)

            # Create MISP objects from the CSV data
            misp_objects = create_misp_objects_from_csv(data, object_name, attribute_mapping)

            # Submit the created MISP objects to the event
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


def misp_event(case_str: str, csvfilescreated: list) -> None:
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
        process_and_submit_to_misp(misp, case_str, csvfilescreated)

    except KeyboardInterrupt:
        console.print("[bold red]Exiting...[/bold red]")  # Graceful exit on Ctrl+C
    except Exception as e:
        console.print(f"[bold red]An error occurred while initializing MISP: {e}[/bold red]")
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
            misp_event(case_str, csvfilescreated)

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
