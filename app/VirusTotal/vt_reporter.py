import logging
from vt import url_id  # for interacting with URLs in VirusTotal
from app.DataHandler.utils import utc2local  # for converting UTC time to local time
from app.DBHandler.db_handler import DBHandler

# Constants for handling various types and error messages
IPV4_PUBLIC_TYPE = "PUBLIC IPV4"
NOT_FOUND_ERROR = "Not found"
NO_LINK = "No link"
NO_HTTP_CERT = "No https certificate found"

# Set up logging for better debugging and tracking of issues
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VTReporter:
    """
    A class to generate reports from VirusTotal for different value types.

    Attributes:
        vt (object): The VirusTotal client instance.

    Methods:
        create_report(value_type: str, value: str) -> dict:
            Creates and fetches a report for a given value type (e.g., IP, URL, SHA256).
    """

    def __init__(self, vt):
        """
        Initializes the VTReporter with the provided VirusTotal client.

        Parameters:
            vt (object): The initialized VirusTotal client.
        """
        self.vt = vt

    def create_report(self, value_type: str, value: str) -> dict:
        """
        Create a report for a given value (e.g., IP, URL, hash).

        Parameters:
            value_type (str): The type of value (e.g., IPV4, DOMAIN, URL, SHA-256).
            value (str): The value for which the report will be created (e.g., IP, URL, hash).

        Returns:
            dict: The report data from VirusTotal.
        """
        # Define API endpoints for different value types
        api_endpoints = {
            IPV4_PUBLIC_TYPE: f"/ip_addresses/{value}",
            "DOMAIN": f"/domains/{value}",
            "URL": f"/urls/{url_id(value)}",
            "SHA-256": f"/files/{value}",
            "SHA-1": f"/files/{value}",
            "MD5": f"/files/{value}",
        }

        # Initialize report
        report = None

        # Ensure valid value_type and value are provided
        if value_type not in api_endpoints:
            logger.error(f"Invalid value_type provided: {value_type}")
            return {"error": "Invalid value type."}

        try:
            # Fetch the report from VirusTotal
            report = self.vt.get_object(api_endpoints[value_type])
            logger.info(f"Report fetched for {value_type}: {value}")
        except Exception as e:
            # Handle errors such as not found
            if "NotFoundError" in str(e):
                logger.warning(f"{NOT_FOUND_ERROR} on VirusTotal Database: {value}")
            else:
                logger.error(f"Error fetching report for {value_type}: {value} - {e}")
                raise e

        return report if report else {"error": f"No report found for {value}"}

    def create_object(self, value_type, value, report):
        """
        Creates and populates an object for a given value from VirusTotal data.

        Parameters:
            value_type (str): The type of value (e.g., "SHA-256", "IPV4", etc.)
            value (str): The value for which to create the object (e.g., IP address, hash, URL).
            report (dict): The VirusTotal report for the value.

        Returns:
            dict: A dictionary with the populated data.
        """
        value_object = self.initialize_value_object(value_type)

        if report != NOT_FOUND_ERROR and report:
            self.populate_value_object(value_object, value_type, value, report)

            # Determine where to insert based on value type
            self.insert_into_db(value_type, value_object)

        return value_object

    def initialize_value_object(self, value_type):
        """
        Initializes a value object based on the value type.

        Parameters:
            value_type (str): The type of value (e.g., "SHA-256", "IPV4", etc.)

        Returns:
            dict: An initialized value object with default values.
        """
        value_object = {
            "malicious_score": NOT_FOUND_ERROR,
            "total_scans": NOT_FOUND_ERROR,
            "tags": NOT_FOUND_ERROR,
            "link": NO_LINK,
        }

        # Add specific fields for hash types
        if value_type in ["SHA-256", "SHA-1", "MD5"]:
            value_object["threat_category"] = NOT_FOUND_ERROR
            value_object["threat_labels"] = NOT_FOUND_ERROR

        return value_object

    def populate_value_object(self, value_object, value_type, value, report):
        """
        Populates the value object with data from the VirusTotal report.

        Parameters:
            value_object (dict): The object to populate.
            value_type (str): The type of value (e.g., "SHA-256", "IPV4", etc.)
            value (str): The value (e.g., IP address, hash, URL).
            report (dict): The VirusTotal report for the value.
        """
        total_scans = sum(report.last_analysis_stats.values())
        malicious = report.last_analysis_stats.get("malicious", 0)

        self.populate_scores(value_object, total_scans, malicious)
        self.populate_link(value_object, value, value_type)
        self.populate_tags(value_object, report)

        # Populate additional fields based on value type
        if value_type == IPV4_PUBLIC_TYPE:
            self.populate_ip_data(value_object, value, report)
        elif value_type == "DOMAIN":
            self.populate_domain_data(value_object, value, report)
        elif value_type == "URL":
            self.populate_url_data(value_object, value, report)
        elif value_type in ["SHA-256", "SHA-1", "MD5"]:
            self.populate_hash_data(value_object, value, report)
            if report.popular_threat_classification:
                self.populate_threat_classification(value_object, report)

    def insert_into_db(self, value_type, value_object):
        """
        Inserts the value object into the appropriate database table.

        Parameters:
            value_type (str): The type of value (e.g., "SHA-256", "IPV4", etc.)
            value_object (dict): The value object to insert.
        """
        database = "vttools.sqlite"
        conn = DBHandler().create_connection(database)

        if value_type == IPV4_PUBLIC_TYPE:
            DBHandler().insert_ip_data(conn, value_object)
        elif value_type == "DOMAIN":
            DBHandler().insert_domain_data(conn, value_object)
        elif value_type == "URL":
            DBHandler().insert_url_data(conn, value_object)
        elif value_type in ["SHA-256", "SHA-1", "MD5"]:
            DBHandler().insert_hash_data(conn, value_object)

    def populate_tags(self, value_object, report):
        """Populates the 'tags' field from the VirusTotal report."""
        tags = getattr(report, "tags", [])
        value_object["tags"] = ", ".join(tags) if tags else NOT_FOUND_ERROR

    def populate_scores(self, value_object, total_scans, malicious):
        """Populates the 'malicious_score' and 'total_scans' fields."""
        value_object["malicious_score"] = malicious
        value_object["total_scans"] = total_scans

    def populate_link(self, value_object, value, value_type):
        """Populates the 'link' field based on the value type."""
        if value_type == "URL":
            value_object["link"] = f"https://www.virustotal.com/gui/url/{url_id(value)}"
        else:
            value_object["link"] = f"https://www.virustotal.com/gui/search/{value}"

    def populate_ip_data(self, value_object, value, report):
        """Populates the IP-specific fields."""
        value_object.update({
            "ip": value,
            "owner": getattr(report, "as_owner", "No owner found"),
            "location": f"{report.continent} / {report.country}" if hasattr(report, "continent") and hasattr(report, "country") else NOT_FOUND_ERROR,
            "network": getattr(report, "network", "No network found"),
            "https_certificate": getattr(report, "last_https_certificate", NO_HTTP_CERT),
            "info-ip": {
                "regional_internet_registry": getattr(report, "regional_internet_registry", "No regional internet registry found"),
                "asn": getattr(report, "asn", "No asn found"),
            },
        })

    def populate_domain_data(self, value_object, value, report):
        """Populates the domain-specific fields."""
        value_object.update({
            "domain": value,
            "creation_date": getattr(report, "creation_date", "No creation date found"),
            "reputation": getattr(report, "reputation", "No reputation found"),
            "whois": getattr(report, "whois", "No whois found"),
            "info": {
                "last_analysis_results": getattr(report, "last_analysis_results", "No analysis results found"),
                "last_analysis_stats": getattr(report, "last_analysis_stats", "No analysis stats found"),
                "last_dns_records": getattr(report, "last_dns_records", "No dns records found"),
                "last_https_certificate": NO_HTTP_CERT,
                "registrar": getattr(report, "registrar", "No registrar found"),
            },
        })

    def populate_url_data(self, value_object, value, report):
        """Populates the URL-specific fields."""
        value_object.update({
            "url": value,
            "title": getattr(report, "title", "No Title Found"),
            "final_Url": getattr(report, "last_final_url", "No endpoints"),
            "first_scan": str(utc2local(getattr(report, "first_submission_date", "No date Found"))),
            "info": {
                "metadatas": getattr(report, "html_meta", "No metadata Found"),
                "targeted": getattr(report, "targeted_brand", "No target brand Found"),
                "links": getattr(report, "outgoing_links", "No links in url"),
                "redirection_chain": getattr(report, "redirection_chain", "No redirection chain Found"),
                "trackers": getattr(report, "trackers", "No tracker Found"),
            },
        })

    def populate_hash_data(self, value_object, value, report):
        """Populates the hash-specific fields."""
        value_object.update({
            "hash": value,
            "extension": getattr(report, "type_extension", "No extension found"),
            "size": getattr(report, "size", "No size found"),
            "md5": getattr(report, "md5", "No md5 found"),
            "sha1": getattr(report, "sha1", "No sha1 found"),
            "sha256": getattr(report, "sha256", "No sha256 found"),
            "ssdeep": getattr(report, "ssdeep", "No ssdeep found"),
            "tlsh": getattr(report, "tlsh", "No tlsh found"),
            "meaningful_name": getattr(report, "meaningful_name", "No meaningful name found"),
            "names": ", ".join(getattr(report, "names", "No names found")),
            "type": report.trid[0]["file_type"] if hasattr(report, "trid") else "No filetype Found",
            "type_probability": report.trid[0]["probability"] if hasattr(report, "trid") else "No type probability",
        })

    def populate_threat_classification(self, value_object, report):
        """Populates threat category and labels for hashes."""
        try:
            if report.popular_threat_classification:
                classification = report.popular_threat_classification
                value_object["threat_category"] = ", ".join(category['value'] for category in classification.get('popular_threat_category', []))
                value_object["threat_labels"] = classification.get("suggested_threat_label", NOT_FOUND_ERROR)
        except Exception as e:
            logger.error(f"Error populating threat classification: {e}")

    def get_rows(self, value_type, value, report):
        """
        Get the rows for a value and its report.

        Parameters:
        value_type (str): The type of value.
        value (str): The value to get the rows for.
        report (dict): The report for the value.

        Returns:
        List[List[str]]: The rows for the value and its report.
        """
        # Create the object for the value
        row_object = self.create_object(value_type, value, report)

        if report != NOT_FOUND_ERROR:
            # Clean up the 'info' key if it exists
            row_object.pop("info", None)

            # Construct rows from the row object
            rows = [[key, value] for key, value in row_object.items()]

            # Append standard rows for votes and other metadata
            standard_rows = [
                ["VirusTotal Total Votes", getattr(report, "total_votes", "No total votes found")]
            ]
            rows.extend(standard_rows)

            return rows
        return []

    def csv_report(self, value_type, value, report):
        """
        Create a CSV report for a value.

        Parameters:
        value_type (str): The type of value.
        value (str): The value to create a report for.
        report (dict): The report for the value.

        Returns:
        List[Dict[str, str]]: The CSV report for the value.
        """
        # Create the object to use for the CSV
        csv_object = self.create_object(value_type, value, report)

        # Return the CSV in a list format
        return [csv_object]

    def get_report(self, value_type, value):
        """
        Get the report for a value, generating the CSV and rows.

        Parameters:
        value_type (str): The type of value.
        value (str): The value to get the report for.

        Returns:
        dict: The report for the value along with its CSV and row data.
        """
        # Generate the report using an external method
        report = self.create_report(value_type, value)

        if report:
            # Generate CSV and rows
            csv_report = self.csv_report(value_type, value, report)
            rows = self.get_rows(value_type, value, report)

            # Return all results in a dictionary
            return {
                "report": report,
                "csv_report": csv_report,
                "rows": rows
            }

        return None
