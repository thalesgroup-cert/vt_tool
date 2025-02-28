from typing import List
from prettytable import PrettyTable
import logging

logging.basicConfig(level=logging.ERROR)

class CustomPrettyTable:
    """
    A class for creating a formatted table with sorting and alignment options.
    """

    def __init__(self, headers: List[str], data: List[List[str]]):
        """
        Initializes the table with headers and data.

        Parameters:
        headers (List[str]): The headers of the table.
        data (List[List[str]]): The data for the table rows.
        """
        self.unwanted_headers = {"info", "whois", "https_certificate"}
        self.headers, self.data = self.clean_data(headers, data)

    def clean_data(self, headers: List[str], data: List[List[str]]) -> tuple:
        """
        Removes specific headers and their corresponding data.

        Parameters:
        - headers (List[str]): Original headers.
        - data (List[List[str]]): Original data.

        Returns:
        - tuple: (Cleaned headers, Cleaned data)
        """
        # Get indexes of headers to remove
        indexes_to_remove = [i for i, header in enumerate(headers) if header in self.unwanted_headers]

        # Remove headers
        cleaned_headers = [header for i, header in enumerate(headers) if i not in indexes_to_remove]

        # Remove corresponding data columns
        cleaned_data = []
        for row in data:
            if len(row) == len(headers):  # Ensure row length matches headers
                cleaned_row = [value for i, value in enumerate(row) if i not in indexes_to_remove]
                cleaned_data.append(cleaned_row)
            else:
                logging.error(f"Skipping malformed row (incorrect column count): {row}")

        return cleaned_headers, cleaned_data

    def sort_data(self, sort_by: str = None, reverse_sort: bool = False) -> None:
        """
        Sorts the data based on a column header.

        Parameters:
        - sort_by (str): The column header to sort by.
        - reverse_sort (bool): Whether to sort in reverse order (descending).
        """
        if sort_by and sort_by in self.headers:
            index = self.headers.index(sort_by)
            self.data.sort(key=lambda x: x[index], reverse=reverse_sort)
        elif sort_by:
            raise ValueError(f"Invalid sort column: {sort_by}. Column not found in headers.")

    def create_table(self, sort_by: str = None, reverse_sort: bool = False, align: str = "c") -> str:
        """
        Creates a formatted table with sorting and alignment.

        Parameters:
        - sort_by (str): Column name to sort the table by.
        - reverse_sort (bool): Whether to sort the table in reverse order.
        - align (str): Alignment of columns ('l' for left, 'r' for right, 'c' for center).

        Returns:
        - str: The formatted table as a string.
        """
        # Sort data if required
        self.sort_data(sort_by, reverse_sort)

        # Create PrettyTable object
        table = PrettyTable()
        # Set headers and alignment for all columns
        table.field_names = self.headers
        table.reversesort = True

        # Add rows to the table
        for row in self.data:
            table.add_row(row)

        return str(table)
