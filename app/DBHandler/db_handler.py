import sqlite3
from sqlite3 import Error
from vt import url_id  # For interacting with URLs in VirusTotal

# Constants
IPV4_PUBLIC_TYPE = "PUBLIC IPV4"
NOT_FOUND_ERROR = "Not found"
NO_LINK = "No link"
NO_HTTP_CERT = "No https certificate found"

# Database schema for creating tables
SCHEMA = """
CREATE TABLE IF NOT EXISTS urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT,
    malicious_score TEXT,
    total_scans TEXT,
    tags TEXT,
    link TEXT,
    title TEXT,
    final_url TEXT,
    first_scan TEXT,
    metadatas TEXT,
    targeted TEXT,
    links TEXT,
    redirection_chain TEXT,
    trackers TEXT
);

CREATE TABLE IF NOT EXISTS hashes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hash TEXT,
    malicious_score TEXT,
    total_scans TEXT,
    tags TEXT,
    threat_category TEXT,
    threat_labels TEXT,
    link TEXT,
    extension TEXT,
    size TEXT,
    md5 TEXT,
    sha1 TEXT,
    sha256 TEXT,
    ssdeep TEXT,
    tlsh TEXT,
    meaningful_name TEXT,
    names TEXT,
    type TEXT,
    type_probability TEXT
);

CREATE TABLE IF NOT EXISTS ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT,
    port TEXT,
    protocol TEXT,
    malicious_score TEXT,
    total_scans TEXT,
    tags TEXT,
    link TEXT,
    owner TEXT,
    location TEXT,
    network TEXT,
    https_certificate TEXT,
    regional_internet_registry TEXT,
    asn TEXT
);

CREATE TABLE IF NOT EXISTS domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT,
    malicious_score TEXT,
    total_scans TEXT,
    tags TEXT,
    link TEXT,
    creation_date TEXT,
    reputation TEXT,
    whois TEXT,
    last_analysis_results TEXT,
    last_analysis_stats TEXT,
    last_dns_records TEXT,
    last_https_certificate TEXT,
    registrar TEXT
);
"""

class DBHandler:
    def create_connection(self, db_file):
        """Create a database connection to a SQLite database"""
        try:
            conn = sqlite3.connect(db_file)
            return conn
        except Error as e:
            print(f"Error connecting to SQLite database: {e}")
            return None

    def create_schema(self, conn):
        """Create tables in the SQLite database"""
        if conn:
            try:
                c = conn.cursor()
                c.executescript(SCHEMA)
            except Error as e:
                print(f"Error creating schema: {e}")

    def close_connection(self, conn):
        """Close the database connection"""
        if conn:
            conn.close()
            print("SQLite database connection closed.")

    def _insert_data(self, conn, table_name, data, columns):
        """Insert data into the specified table if it doesn't already exist, and handle nested info fields"""
        columns_str = ", ".join(columns)
        placeholders = ", ".join("?" * len(columns))

        select_query = f"SELECT * FROM {table_name} WHERE {columns[0]} = ?"
        insert_query = f"INSERT INTO {table_name}({columns_str}) VALUES({placeholders})"
        update_query = f"UPDATE {table_name} SET {', '.join(f'{col} = ?' for col in columns)} WHERE {columns[0]} = ?"

        unnested_data = data.copy()

        # Update nested 'info' or 'info-ip' fields if present
        for key in ["info", "info-ip"]:
            if key in unnested_data:
                for sub_key, value in unnested_data[key].items():
                    unnested_data[sub_key] = str(value)
                del unnested_data[key]

        try:
            cur = conn.cursor()
            cur.execute(select_query, (data[columns[0]],))  # Check if the record already exists

            values = tuple(str(unnested_data[col]) for col in columns)
            if not cur.fetchone():  # If the record doesn't exist, insert it
                cur.execute(insert_query, values)
            else:
                cur.execute(update_query, values + (data[columns[0]],))  # Append WHERE column value

            conn.commit()
            cur.close()
        except Exception as e:
            conn.rollback()
            print(f"Error inserting/updating data into {table_name}: {e}")
            cur.close()


    def insert_ip_data(self, conn, ip_data):
        """Insert IP data into the ips table"""
        columns = ["ip", "port", "protocol", "malicious_score", "total_scans", "tags", "link", "owner",
                   "location", "network", "https_certificate", "regional_internet_registry", "asn"]
        self._insert_data(conn, "ips", ip_data, columns)

    def insert_domain_data(self, conn, domain_data):
        """Insert domain data into the domains table"""
        columns = ["domain", "malicious_score", "total_scans", "tags", "link", "creation_date",
                   "reputation", "whois", "last_analysis_results", "last_analysis_stats",
                   "last_dns_records", "last_https_certificate", "registrar"]
        self._insert_data(conn, "domains", domain_data, columns)

    def insert_url_data(self, conn, url_data):
        """Insert URL data into the urls table"""
        columns = ["url", "malicious_score", "total_scans", "tags", "link", "title", 
                   "final_url", "first_scan", "metadatas", "targeted", "links", 
                   "redirection_chain", "trackers"]
        self._insert_data(conn, "urls", url_data, columns)

    def insert_hash_data(self, conn, hash_data):
        """Insert hash data into the hashes table"""
        columns = ["hash", "malicious_score", "total_scans", "tags", "threat_category", 
                   "threat_labels", "link", "extension", "size", "md5", "sha1", "sha256", 
                   "ssdeep", "tlsh", "meaningful_name", "names", "type", "type_probability"]
        self._insert_data(conn, "hashes", hash_data, columns)

    def exists(self, conn, table, value, column="ip", threshold=0.8):
        """Check if a value exists in the database, but return None if most other columns contain 'Not Found'."""
        try:
            cur = conn.cursor()
            query = f"SELECT * FROM {table} WHERE {column} = ?"
            cur.execute(query, (value,))
            result = cur.fetchone()

            if result:
                # Get column names from cursor description
                col_names = [desc[0] for desc in cur.description]

                # Create a dictionary of column values
                result_dict = dict(zip(col_names, result))

                # Exclude 'id' and searched column from the check
                excluded_keys = {"id", column}
                filtered_values = [result_dict[key] for key in result_dict if key not in excluded_keys]

                # Count occurrences of "Not Found"
                not_found_count = sum(1 for value in filtered_values if value == "Not Found")
                not_found_ratio = not_found_count / len(filtered_values) if filtered_values else 0

                # Return None if the ratio of "Not Found" exceeds the threshold
                if not_found_ratio >= threshold:
                    return False

                return True

            return False
        except Exception as e:
            print(f"Error checking existence in {table}: {e}")
            return False
        finally:
            cur.close()



    def get_report(self, value, value_type, conn):
        """Retrieve the report for a given value"""
        report = self.create_report(value_type, value, conn)
        if report:
            csv_report = self.csv_report(value_type, value, report)
            rows = self.get_rows(value_type, value, report)
            return {"report": report, "csv_report": csv_report, "rows": rows}
        return None

    def create_report(self, value_type, value, conn):
        """Fetch a report from the database based on value_type and value"""
        if conn is None:
            return None

        cursor = conn.cursor()
        if isinstance(value, tuple):
            value = value[0]
        report = None
        try:
            if value_type == IPV4_PUBLIC_TYPE:
                cursor.execute("SELECT * FROM ips WHERE ip = ?", (value,))
            elif value_type == "DOMAIN":
                cursor.execute("SELECT * FROM domains WHERE domain = ?", (value,))
            elif value_type == "URL":
                cursor.execute("SELECT * FROM urls WHERE url = ?", (value,))
            elif value_type in ["SHA-256", "SHA-1", "MD5"]:
                cursor.execute("SELECT * FROM hashes WHERE hash = ? OR md5 = ? OR sha1 = ?", (value, value, value))

            report = cursor.fetchone()
        except Exception as e:
            print(f"An error occurred while fetching the report: {e}")
        finally:
            cursor.close()

        return report

    def csv_report(self, value_type, value, report):
        """Generate a CSV report from the fetched report"""
        csv_object = self.create_object(value_type, value, report)
        return [csv_object]

    def create_object(self, value_type, value, report):
        """Create an object to represent the report"""
        value_object = {"malicious_score": NOT_FOUND_ERROR, "total_scans": NOT_FOUND_ERROR, 
                        "tags": NOT_FOUND_ERROR, "link": NO_LINK}

        if report != NOT_FOUND_ERROR and report:
            self.populate_scores(value_object, report)
            self.populate_link(value_object, value, value_type)
            self.populate_tags(value_object, report[4])
            if value_type == IPV4_PUBLIC_TYPE:
                self.populate_ip_data(value, value_object, report)
            elif value_type == "DOMAIN":
                self.populate_domain_data(value, value_object, report)
            elif value_type == "URL":
                self.populate_url_data(value, value_object, report)
            elif value_type in ["SHA-256", "SHA-1", "MD5"]:
                self.populate_hash_data(value, value_object, report)

        return value_object

    def populate_scores(self, value_object, report):
        """Populate malicious score and total scans"""
        value_object["malicious_score"] = report[2]
        value_object["total_scans"] = report[3]

    def populate_link(self, value_object, value, value_type):
        """Populate the link for the report"""
        if value_type == "URL":
            value_object["link"] = f"https://www.virustotal.com/gui/url/{url_id(value)}"
        else:
            if isinstance(value, tuple):
                value = value[0]
            value_object["link"] = f"https://www.virustotal.com/gui/search/{value}"

    def populate_tags(self, value_object, tags):
        """Populate tags for the report"""
        value_object["tags"] = tags

    def populate_ip_data(self, value, value_object, report):
        """Populate IP-related data"""
        if isinstance(value, tuple):
            value = value[0]
        value_object.update({
            "ip": value,
            "port": report[5],
            "protocol": report[6],
            "owner": report[7],
            "location": report[8],
            "network": report[9],
            "info-ip": {
                "https_certificate": report[10] if report[10] != NO_HTTP_CERT else None,
                "regional_internet_registry": report[11],
                "asn": report[12]
            }
        })

    def populate_domain_data(self, value,  value_object, report):
        """Populate domain-related data"""
        value_object.update({
            "domain": value,
            "creation_date": report[6],
            "reputation": report[7],
            "whois": [report[8]],
            "info": {
                "last_analysis_results": report[9],
                "last_analysis_stats": report[10],
                "last_dns_records": report[11],
                "last_https_certificate": report[12],
                "registrar": report[13]
            },
        })

    def populate_url_data(self, value, value_object, report):
        """Populate URL-related data"""
        value_object.update({
            "url": value,
            "title": report[6],
            "final_url": report[7],
            "first_scan": report[8],
            "info": {
                "metadatas": report[9],
                "targeted": report[10],
                "links": report[11],
                "redirection_chain": report[12],
                "trackers": report[13]
            },
        })

    def populate_hash_data(self, value, value_object, report):
        """Populate hash-related data"""
        value_object.update({
            "hash": value,
            "extension": report[8],
            "size": report[9],
            "md5": report[10],
            "sha1": report[11],
            "sha256": report[12],
            "ssdeep": report[13],
            "tlsh": report[14],
            "meaningful_name": report[15],
            "names": report[16],
            "type": report[17],
            "type_probability": report[18]
        })

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
        row_object = self.create_object(value_type, value, report)
        if report != NOT_FOUND_ERROR:
            try:
                row_object.pop("info")
            except Exception as e:
                pass
            # Construct rows from the value object
            rows = [[key, value] for key, value in row_object.items()]
            # Append standard rows
            standard_rows = [["VirusTotal Total Votes", getattr(report, "total_votes", "No total votes found")]]
            rows.extend(standard_rows)
            
            return rows