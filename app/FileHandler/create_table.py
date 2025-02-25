from typing import List
from prettytable import PrettyTable


class CustomPrettyTable:
    """
    A class for creating a table of data with various customizations.
    """

    def __init__(self, headers: List[str], data: List[List[str]]):
        """
        Initializes the table with headers and data.

        Parameters:
        headers (List[str]): The headers of the table.
        data (List[List[str]]): The data for the table rows.
        """
        self.headers = headers
        self.data = data


    def divide_list(self, lst, n):
        return [lst[i : i + n] for i in range(0, len(lst), n)]


    def validate_data(self, filtered_data) -> None:
        """
        Validate that each row has the correct number of columns matching the headers.
        """
        if len(self.headers) != len(filtered_data[0]):
            raise ValueError("Each row of data must have the same number of columns as headers.")


    def sort_data(self, sort_by: str = None, reverse_sort: bool = False) -> None:
        """
        Sort the data based on a column header.

        Parameters:
        sort_by (str): The column header to sort by.
        reverse_sort (bool): Whether to sort in reverse order (descending).
        """
        if sort_by and sort_by in self.headers:
            index = self.headers.index(sort_by)
            self.data.sort(key=lambda x: x[index], reverse=reverse_sort)
        elif sort_by:
            raise ValueError(f"Invalid sort column: {sort_by}. Column not found in headers.")


    def create_table(self, sort_by: str = None, reverse_sort: bool = False, align: str = "l") -> str:
        """
        Create a table of data, with optional sorting and alignment.

        Parameters:
        - sort_by (str): Column name to sort the table by.
        - reverse_sort (bool): Whether to sort the table in reverse order.
        - align (str): Alignment of columns ('l' for left, 'r' for right, 'c' for center).

        Returns:
        str: The table as a string.
        """
        # Create PrettyTable object
        table = PrettyTable()
        filtered_data = self.divide_list(self.data, len(self.headers))
        # Validate data format
        self.validate_data(filtered_data)
        # Sort data if required
        self.sort_data(sort_by, reverse_sort)

        # Set headers and alignment for all columns
        table.field_names = self.headers
        table.reversesort = True

        # Add rows to the table
        for row in filtered_data:
            table.add_row(row)

        return str(table)
