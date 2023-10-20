from vt import url_id               # for interacting with urls in VirusTotal
from ..DataHandler.utils import utc2local       # for converting UTC time to local time


class VTReporter:
    def __init__(self, vt):
        self.vt = vt
    
    def create_report(self, value_type, value):
        """
        Create a report for a value.

        Parameters:
        value_type (str): The type of value.
        value (str): The value to create a report for.

        Returns:
        dict: The report for the value.
        """
        # Create a report for the value
        if value_type == "IP":
            report = self.vt.get_object(f"/ip_addresses/{value}")
        elif value_type == "DOMAIN":
            report = self.vt.get_object(f"/domains/{value}")
        elif value_type == "URL":
            report = self.vt.get_object(f"/urls/{url_id(value)}")
        elif value_type == "HASH":
            report = self.vt.get_object(f"/files/{value}")

        return report

    def create_object(self, value_type, value, report):
        """
        Create an object for a value.

        Parameters:
        value_type (str): The type of value.
        value (str): The value to create an object for.
        report (dict): The report for the value.

        Returns:
        dict: The object for the value.
        """
        # Create an object for the value
        malicious = report.last_analysis_stats["malicious"]
        suspicious = report.last_analysis_stats["suspicious"]
        undetected = report.last_analysis_stats["undetected"]
        harmless = report.last_analysis_stats["harmless"]
        malicious_score = f"{malicious} \\ {malicious + undetected + suspicious + harmless}"
        suspi_score = f"{suspicious} \\ {malicious + undetected + suspicious + harmless}"
        safe_score = f"{harmless} \\ {malicious + undetected + suspicious + harmless}"
        if value_type == "IP":
            object = {
                "IP Address" : value,
                "malicious_score": malicious_score,
                "suspicious_score": suspi_score,
                "safe_score": safe_score,
                "owner": getattr(report, 'as_owner', 'No owner found'),
                "location": f"{report.continent} / {report.country}" if hasattr(report, 'continent') and hasattr(report, 'country') else "Not found",
                "network": getattr(report, 'network', 'No network found'),
                "https_certificate": getattr(report, 'last_https_certificate', 'No https certificate found'),
                "info-ip": {
                    "regional_internet_registry": getattr(report, 'regional_internet_registry', 'No regional internet registry found'),
                    "asn": getattr(report, 'asn', 'No asn found'),
                },
                "link": "https://www.virustotal.com/gui/ip-address/" + value
            }
        elif value_type == "DOMAIN":
            object = {
                "Domain" : value,
                "malicious_score": malicious_score,
                "suspicious_score": suspi_score,
                "safe_score": safe_score,
                'creation_date': getattr(report, 'creation_date', 'No creation date found'),
                "reputation": getattr(report, 'reputation', 'No reputation found'),
                "whois": getattr(report, 'whois', 'No whois found'),
                "info": {
                    'last_analysis_results': getattr(report, 'last_analysis_results', 'No analysis results found'),
                    'last_analysis_stats': getattr(report, 'last_analysis_stats', 'No analysis stats found'),
                    'last_dns_records': getattr(report, 'last_dns_records', 'No dns records found'),
                    'last_https_certificate': getattr(report, 'last_https_certificate', 'No https certificate found'),
                    'registrar': getattr(report, 'registrar', 'No registrar found'),
                },
                "link": "https://www.virustotal.com/gui/domain/" + value
            }
        elif value_type == "URL":
            object = {
                "URL": value,
                "malicious_score": malicious_score,
                "suspicious_score": suspi_score,
                "safe_score": safe_score,
                "title": getattr(report, 'title', 'No Title Found'),
                "final_Url": getattr(report, 'last_final_url', 'No endpoints'),
                "first_scan": str(utc2local(getattr(report, 'first_submission_date', 'No date Found'))),
                "info": {
                    'metadatas': getattr(report, 'html_meta', 'No metadata Found'),
                    'targeted': getattr(report, 'targeted_brand', 'No target brand Found'),
                    'links': getattr(report, 'outgoing_links', 'No links in url'),
                    'redirection_chain': getattr(report, 'redirection_chain', 'No redirection chain Found'),
                    'trackers': getattr(report, 'trackers', 'No tracker Found'),
                },
                "link": f"https://www.virustotal.com/gui/url/{report.id}"
            }
        elif value_type == "HASH":
            object = {
                "Hash (Sha256)": value,
                "malicious_score": malicious_score,
                "suspicious_score": suspi_score,
                "safe_score": safe_score,
                "extension": getattr(report, 'type_extension', 'No extension found'),
                "Size (Bytes)": getattr(report, 'size', 'No size found'),
                "md5": getattr(report, 'md5', 'No md5 found'),
                "sha1": getattr(report, 'sha1', 'No sha1 found'),
                "ssdeep": getattr(report, 'ssdeep', 'No ssdeep found'),
                "tlsh": getattr(report, 'tlsh', 'No tlsh found'),
                "names": ", ".join(getattr(report, 'names', 'No names found')),
                "Type": report.trid[0]["file_type"] if hasattr(report, 'trid') else "No filetype Found",
                "Type Probability": report.trid[0]["probability"] if hasattr(report, 'trid') else "No type probabilty",
                "link": "https://www.virustotal.com/gui/report/"+ value
            }

        return object

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
        # Get the rows for the value and its report
        object = self.create_object(value_type, value, report)
        try:
            object.pop("info")
        except:
            pass
        rows = [[key, value] for key, value in object.items()]

        standard_rows = [
            ["VirusTotal Total Votes", report.get("total_votes", 0)]
        ]
        rows.extend(standard_rows)

        return rows

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
        # Create a CSV report for the value
        object = self.create_object(value_type, value, report)
        csv_report = [object]

        return csv_report

    def get_report(self, value_type, value):
        """
        Get the report for a value.

        Parameters:
        value_type (str): The type of value.
        value (str): The value to get the report for.

        Returns:
        dict: The report for the value.
        """
        # Get the report for the value
        report = self.create_report(value_type, value)
        csv_report = self.csv_report(value_type, value, report)
        rows = self.get_rows(value_type, value, report)

        results = {
            "report": report,
            "csv_report": csv_report,
            "rows": rows
        }

        return results
